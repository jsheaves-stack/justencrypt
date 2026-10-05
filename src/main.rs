use std::{io::Write, process, sync::Arc};

use config::AppConfig;
use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    shield::{Hsts, Shield},
    time::Duration,
    tokio::sync::Semaphore,
    Build, Rocket,
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
    folder::{
        create_folder, delete_folder, download_folder, folder_options, get_folder, patch_folder,
    },
    info::get_server_info,
    session::{create_session, destroy_session, session_options},
    thumbnail::{get_thumbnail, thumbnail_options},
};
use session::{
    orphans::OrphanScanner, policy::SessionPolicy, reaper::SessionReaper, store::SessionStore,
};
use web::fairings::{Cors, SecurityHeaders};

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

/// State every request shares.
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub sessions: Arc<SessionStore>,
    pub orphan_scanner: OrphanScanner,
    pub thumbnail_semaphore: Arc<Semaphore>,
    /// One permit for each folder download in progress; none when folder
    /// downloads are unlimited.
    pub download_semaphore: Option<Arc<Semaphore>>,
}

/// Cleans up the uploads every live session has in progress when the server
/// shuts down.
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

/// Reads the configuration from the environment (and `.env`), sets up
/// logging, then runs the server until it shuts down.
fn main() {
    dotenv::dotenv().ok();

    // The logger isn't set up yet, and its level comes from this config.

    let config = match AppConfig::from_env() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("Invalid configuration: {}", e);

            process::exit(1);
        },
    };

    init_logger(&config);

    trace!("Loaded .env file and initialized logger.");

    // Rocket's `#[launch]` builds the async runtime from Rocket's own config
    // sources, before any of ours is read, so the worker and blocking thread
    // counts configured here would be ignored. The runtime is built here
    // instead, the same way Rocket builds it.
    let result = rocket::async_run(
        build_rocket(config.clone()).launch(),
        config.server.workers.get(),
        config.server.max_blocking_threads.get(),
        true,
        "rocket-worker-thread",
    );

    if let Err(e) = result {
        error!("The server stopped: {}", e.pretty_print());

        process::exit(1);
    }
}

/// Sets up logging at the configured levels, with each line naming the
/// source file and line it came from.
fn init_logger(config: &AppConfig) {
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
}

/// Builds the server: its state, fairings and routes, as configured.
fn build_rocket(config: Arc<AppConfig>) -> Rocket<Build> {
    let semaphore_tickets = config.thumbnail_concurrency();

    info!(
        "Thumbnails: at most {} generated at once, each decode limited to {}.",
        semaphore_tickets, config.thumbnail.max_decode_memory
    );

    info!(
        "Blocking threads: at most {} in all, {}.",
        config.server.max_blocking_threads,
        match config.max_blocking_threads_per_user {
            Some(limit) => format!("at most {} per user", limit),
            None => "no limit per user (JUSTENCRYPT_MAX_BLOCKING_THREADS_PER_USER)".to_string(),
        }
    );

    match config.max_active_downloads {
        Some(limit) => info!("Folder downloads: at most {} at once.", limit),
        None => info!("Folder downloads: no limit (JUSTENCRYPT_MAX_ACTIVE_DOWNLOADS)."),
    }

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
        download_semaphore: config
            .max_active_downloads
            .map(|limit| Arc::new(Semaphore::new(limit.get()))),
    };

    trace!("AppState initialized.");

    let hsts = Hsts::Enable(Duration::days(365));

    trace!("HSTS enabled.");

    trace!("Building Rocket instance...");

    let mut rocket = rocket::custom(config.rocket_figment())
        .attach(Cors::new(config.allow_origin.clone()))
        .attach(SecurityHeaders)
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
                download_folder,
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
