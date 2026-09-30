use std::{io::Write, process, sync::Arc};

use config::AppConfig;
use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    launch,
    shield::{Hsts, Shield},
    time::Duration,
    tokio::sync::Semaphore,
};
use routes::{
    admin::{
        admin_options, create_user, create_user_options, delete_session, delete_session_options,
        get_session,
    },
    file::{
        delete_file, file_options, finalize_upload, get_file, init_upload, patch_file, put_file,
        upload_chunk,
    },
    folder::{create_folder, delete_folder, folder_options, get_folder, patch_folder},
    info::get_server_info,
    session::{create_session, destroy_session, session_options},
    thumbnail::{get_thumbnail, thumbnail_options},
};
use session::{
    orphans::OrphanScanner, policy::SessionPolicy, reaper::SessionReaper, store::SessionStore,
};
use web::fairings::Cors;

pub mod config;
pub mod db;
pub mod encryption;
pub mod enums;
pub mod routes;
pub mod session;
pub mod util;
pub mod web;

#[macro_use]
extern crate rocket;
extern crate serde;

pub struct AppState {
    pub config: Arc<AppConfig>,
    pub sessions: Arc<SessionStore>,
    pub orphan_scanner: OrphanScanner,
    pub thumbnail_semaphore: Arc<Semaphore>,
}

pub struct CleanupOnShutdown;

#[async_trait]
impl Fairing for CleanupOnShutdown {
    fn info(&self) -> Info {
        Info {
            name: "Cleanup on Shutdown",
            kind: Kind::Shutdown,
        }
    }

    async fn on_shutdown(&self, rocket: &rocket::Rocket<rocket::Orbit>) {
        info!("Shutdown signal received. Cleaning up active uploads for all sessions.");

        if let Some(state) = rocket.state::<AppState>() {
            for session in state.sessions.snapshot().await {
                if let Err(e) = session.cleanup_own_uploads().await {
                    error!(
                        "Error during shutdown cleanup for user {}: {}",
                        session.username, e
                    );
                }
            }
        }
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv::dotenv().ok();

    // The logger isn't set up yet, and its level comes from this config.
    let config = match AppConfig::from_env() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("Invalid configuration: {}", e);

            process::exit(1);
        },
    };

    env_logger::Builder::new()
        .format(|buf, record| {
            let mut file = record.file().unwrap_or("unknown");
            if let Some(idx) = file.find("registry/src/") {
                let rest = &file[idx + 13..];
                if let Some(slash_idx) = rest.find('/') {
                    file = &rest[slash_idx + 1..];
                }
            } else if let Some(idx) = file.find("/rustc/") {
                let rest = &file[idx + 7..];
                if let Some(slash_idx) = rest.find('/') {
                    file = &rest[slash_idx + 1..];
                }
            }

            writeln!(
                buf,
                "[{time} {level} {file}:{line}] {msg}",
                time = buf.timestamp(),
                level = record.level(),
                file = file,
                line = record.line().unwrap_or(0),
                msg = record.args()
            )
        })
        .filter_level(config.server.log_level.filter())
        .filter_module("rocket", config.server.rocket_log_level.filter())
        .init();

    trace!("Loaded .env file and initialized logger.");

    trace!("Entering main::rocket launch function.");

    let workers = config.server.workers.get();
    let semaphore_tickets = ((workers * 7) / 10).max(1);

    trace!(
        "Calculated thumbnail semaphore tickets: {} (from {} workers)",
        semaphore_tickets,
        workers
    );

    let session_policy = SessionPolicy::from(&config.session);

    info!(
        "Session policy: idle timeout {}s, max lifetime {}s, max {} session(s) per user.",
        session_policy.idle_timeout.as_secs(),
        session_policy.max_lifetime.as_secs(),
        session_policy.max_per_user
    );

    let orphan_scanner = OrphanScanner::new(config.orphan_scan_enabled);

    info!(
        "Orphan file scan at login is {} (JUSTENCRYPT_ORPHAN_SCAN_ENABLED).",
        if orphan_scanner.is_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );

    let state = AppState {
        config: config.clone(),
        sessions: Arc::new(SessionStore::new(session_policy)),
        orphan_scanner,
        thumbnail_semaphore: Arc::new(Semaphore::new(semaphore_tickets)),
    };

    trace!("AppState initialized.");

    let hsts = Hsts::Enable(Duration::days(365));

    trace!("HSTS enabled.");

    trace!("Building Rocket instance...");

    let mut rocket = rocket::custom(config.rocket_figment())
        .attach(Cors::new(config.allow_origin.clone()))
        .attach(Shield::default().enable(hsts))
        .attach(CleanupOnShutdown)
        .manage(state)
        .mount("/", routes![get_server_info])
        .mount(
            "/file",
            routes![
                get_file,
                put_file,
                delete_file,
                file_options,
                patch_file,
                init_upload,
                upload_chunk,
                finalize_upload
            ],
        )
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount(
            "/folder",
            routes![
                get_folder,
                create_folder,
                folder_options,
                delete_folder,
                patch_folder
            ],
        )
        .mount(
            "/session",
            routes![create_session, destroy_session, session_options,],
        );

    if config.admin_api_key.is_some() {
        trace!("JUSTENCRYPT_ADMIN_API_KEY is set, mounting admin routes.");

        rocket = rocket.mount(
            "/admin",
            routes![
                get_session,
                admin_options,
                delete_session,
                delete_session_options,
                create_user,
                create_user_options
            ],
        );
    } else {
        warn!("JUSTENCRYPT_ADMIN_API_KEY is not set, admin routes will NOT be available.");
    }

    match SessionReaper::every(config.session.reaper_interval_seconds) {
        Some(reaper) => {
            rocket = rocket.attach(reaper);
        },
        None => {
            info!(
                "Session reaper disabled (JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS is unset or 0)."
            );
        },
    }

    rocket
}

#[cfg(test)]
pub mod tests;
