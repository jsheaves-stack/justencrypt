use std::{env, io::Write, str::FromStr, sync::Arc};

use log::LevelFilter;
use rocket::{
    async_trait,
    config::{Config, TlsConfig},
    data::{ByteUnit, Limits},
    fairing::{Fairing, Info, Kind},
    figment::Figment,
    launch,
    shield::{Hsts, Shield},
    time::Duration,
    tokio::sync::Semaphore,
};
use routes::{
    admin::{admin_options, delete_session, delete_session_options, get_session},
    file::{
        delete_file, file_options, finalize_upload, get_file, init_upload, patch_file, put_file,
        upload_chunk,
    },
    folder::{create_folder, delete_folder, folder_options, get_folder, patch_folder},
    info::get_server_info,
    session::{create_session, destroy_session, session_options},
    thumbnail::{get_thumbnail, thumbnail_options},
};
use session::store::SessionStore;
use web::fairings::Cors;

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
    pub sessions: SessionStore,
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

fn get_required_env_var(var_name: &str, default: &str, error_msg: &str) -> String {
    if cfg!(debug_assertions) {
        match env::var(var_name) {
            Ok(v) => v,

            Err(_) => default.to_owned(),
        }
    } else {
        match env::var(var_name) {
            Ok(v) => v,

            Err(e) => panic!("{} Error: {}", error_msg, e),
        }
    }
}

pub fn get_app_config() -> Figment {
    trace!("Entering config::get_app_config");

    let secret_key = get_required_env_var(
        "JUSTENCRYPT_ROCKET_SECRET_KEY",
        "ept8SXw6KDzOX2Yko87xvH9lwRvOzdUc/BoheaN0Uhk=",
        "JUSTENCRYPT_ROCKET_SECRET_KEY must be set in release mode.",
    );

    trace!("Secret key loaded.");

    let app_config = Config::figment()
        .merge((
            "address",
            env::var("JUSTENCRYPT_ADDRESS").unwrap_or_else(|_| "0.0.0.0".into()),
        ))
        .merge((
            "port",
            env::var("JUSTENCRYPT_PORT")
                .unwrap_or_else(|_| "8000".into())
                .parse::<u16>()
                .unwrap_or(8000),
        ))
        .merge((
            "workers",
            env::var("JUSTENCRYPT_WORKERS")
                .unwrap_or_else(|_| "16".into())
                .parse::<usize>()
                .unwrap_or(16),
        ))
        .merge((
            "keep_alive",
            env::var("JUSTENCRYPT_KEEP_ALIVE")
                .unwrap_or_else(|_| "5".into())
                .parse::<u64>()
                .unwrap_or(5),
        ))
        .merge(("secret_key", secret_key))
        .merge((
            "limits",
            Limits::default()
                .limit(
                    "form",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_FORM").unwrap_or_else(|_| "10MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "data-form",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_DATA_FORM")
                            .unwrap_or_else(|_| "10MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "file",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_FILE").unwrap_or_else(|_| "64GiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "file-chunk",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_FILE_CHUNK")
                            .unwrap_or_else(|_| "32MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "json",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_JSON").unwrap_or_else(|_| "10MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "msgpack",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_MSGPACK").unwrap_or_else(|_| "1MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "file/jpg",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_FILE_JPG").unwrap_or_else(|_| "10GiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "bytes",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_BYTES").unwrap_or_else(|_| "10MiB".into()),
                    )
                    .unwrap(),
                )
                .limit(
                    "string",
                    ByteUnit::from_str(
                        &env::var("JUSTENCRYPT_LIMITS_STRING").unwrap_or_else(|_| "10MiB".into()),
                    )
                    .unwrap(),
                ),
        ));
    trace!("Merged standard and limits configuration from environment variables.");

    let tls_key_path = env::var("JUSTENCRYPT_TLS_KEY_PATH").unwrap_or_default();
    let tls_cert_path = env::var("JUSTENCRYPT_TLS_CERT_PATH").unwrap_or_default();

    // Only add TLS config if both paths are non-empty

    if !tls_cert_path.is_empty() && !tls_key_path.is_empty() {
        trace!(
            "TLS paths provided, merging TLS configuration. Cert: {}, Key: {}",
            tls_cert_path,
            tls_key_path
        );

        app_config.merge(("tls", TlsConfig::from_paths(tls_cert_path, tls_key_path)))
    } else {
        trace!("No TLS paths provided, skipping TLS configuration.");

        app_config
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv::dotenv().ok();

    let app_log_level = env::var("JUSTENCRYPT_LOG_LEVEL").unwrap_or_else(|_| "Warn".into());
    let rocket_log_level_str =
        env::var("JUSTENCRYPT_ROCKET_LOG_LEVEL").unwrap_or_else(|_| "Critical".into());

    let rocket_log_level = match rocket_log_level_str.as_str() {
        "Off" => LevelFilter::Off,
        "Debug" => LevelFilter::Debug,
        "Critical" => LevelFilter::Error,
        _ => LevelFilter::Info,
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
        .filter_level(LevelFilter::from_str(&app_log_level).unwrap_or(LevelFilter::Error))
        .filter_module("rocket", rocket_log_level)
        .init();

    trace!("Loaded .env file and initialized logger.");

    trace!("Entering main::rocket launch function.");

    let app_config = get_app_config();

    trace!("Application configuration loaded.");

    let workers: u16 = app_config.extract_inner("workers").unwrap();
    let semaphore_tickets = ((workers as usize * 7) / 10).max(1);

    trace!(
        "Calculated thumbnail semaphore tickets: {} (from {} workers)",
        semaphore_tickets,
        workers
    );

    let state = AppState {
        sessions: SessionStore::default(),
        thumbnail_semaphore: Arc::new(Semaphore::new(semaphore_tickets)),
    };

    trace!("AppState initialized.");

    let hsts = Hsts::Enable(Duration::days(365));

    trace!("HSTS enabled.");

    trace!("Building Rocket instance...");

    let mut rocket = rocket::custom(app_config)
        .attach(Cors)
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

    if env::var("JUSTENCRYPT_ADMIN_API_KEY").is_ok() {
        trace!("JUSTENCRYPT_ADMIN_API_KEY is set, mounting admin routes.");

        rocket = rocket.mount(
            "/admin",
            routes![
                get_session,
                admin_options,
                delete_session,
                delete_session_options
            ],
        );
    } else {
        warn!("JUSTENCRYPT_ADMIN_API_KEY is not set, admin routes will NOT be available.");
    }

    rocket
}

#[cfg(test)]
pub mod tests;
