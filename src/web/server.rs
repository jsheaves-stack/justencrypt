//! Serves the application over HTTP until the server shuts down.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use axum::ServiceExt;
use tokio::{net::TcpListener, signal};

use crate::{
    app::App,
    session::reaper::SessionReaper,
    web::router::{build_service, web_state},
};

/// How long requests still running at shutdown may take to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Serves `app` until the process is told to stop (Ctrl-C or `SIGTERM`),
/// then cleans up after it. HTTPS is left to a reverse proxy in front of the
/// server.
pub async fn run(app: Arc<App>) -> io::Result<()> {
    let http = &app.config.http;
    let address = SocketAddr::new(http.address, http.port);
    let listener = TcpListener::bind(address).await?;

    info!(
        "Listening on http://{}. Terminate TLS in a reverse proxy in front of the server.",
        listener.local_addr()?
    );

    match SessionReaper::every(app.config.session.reaper_interval_seconds) {
        Some(reaper) => reaper.spawn(app.sessions.clone(), app.config.upload_ttl()),
        None => info!(
            "Session reaper disabled (JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS is unset or 0)."
        ),
    }

    let service = build_service(web_state(app.clone()));
    let (stopping_tx, stopping_rx) = tokio::sync::oneshot::channel::<()>();

    let server =
        axum::serve(listener, service.into_make_service()).with_graceful_shutdown(async move {
            shutdown_signal().await;

            info!("Shutdown signal received; finishing the requests in progress.");

            let _ = stopping_tx.send(());
        });

    // Once the signal comes, requests still running get a grace period to
    // finish; after that the server stops without them.
    let deadline = async {
        if stopping_rx.await.is_ok() {
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    let result = tokio::select! {
        result = server => result,
        () = deadline => {
            warn!("Requests still running after {}s; stopping anyway.", SHUTDOWN_GRACE.as_secs());

            Ok(())
        },
    };

    app.shutdown().await;

    result
}

/// Resolves when the process is asked to stop: Ctrl-C, or `SIGTERM` on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to listen for Ctrl-C: {}", e);

            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            },
            Err(e) => {
                error!("Failed to listen for SIGTERM: {}", e);

                std::future::pending::<()>().await;
            },
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
