use log::LevelFilter;
use rocket::{
    config::{Config, TlsConfig},
    data::{ByteUnit, Limits},
    figment::Figment,
    launch,
    shield::{Hsts, Shield},
    time::Duration,
    tokio::sync::{RwLock, Semaphore},
};
use routes::{
    file::{delete_file, file_options, get_file, patch_file, put_file},
    folder::{create_folder, delete_folder, folder_options, get_folder},
    session::{create_session, create_session_options, destroy_session, destroy_session_options},
    thumbnail::{get_thumbnail, thumbnail_options},
};
use session::user_session::UserSession;
use std::{collections::HashMap, env, io::Write, str::FromStr, sync::Arc};
use web::fairings::Cors;

mod db;
mod encryption;
mod enums;
mod routes;
mod session;
mod util;
mod web;

#[macro_use]
extern crate rocket;
extern crate serde;

pub struct AppState {
    active_sessions: RwLock<HashMap<String, Arc<RwLock<UserSession>>>>,
    thumbnail_semaphore: Arc<Semaphore>,
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

fn get_app_config() -> Figment {
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
            writeln!(
                buf,
                "[{time} {level} {file}:{line}] {msg}",
                time = buf.timestamp(),
                level = record.level(),
                file = record.file().unwrap_or("unknown"),
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
        active_sessions: RwLock::default(),
        thumbnail_semaphore: Arc::new(Semaphore::new(semaphore_tickets)),
    };

    trace!("AppState initialized.");

    let hsts = Hsts::Enable(Duration::days(365));

    trace!("HSTS enabled.");
    trace!("Building Rocket instance...");

    rocket::custom(app_config)
        .attach(Cors)
        .attach(Shield::default().enable(hsts))
        .manage(state)
        .mount(
            "/file",
            routes![get_file, put_file, delete_file, file_options, patch_file],
        )
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount(
            "/folder",
            routes![get_folder, create_folder, folder_options, delete_folder],
        )
        .mount(
            "/session",
            routes![
                create_session,
                destroy_session,
                create_session_options,
                destroy_session_options,
            ],
        )
}
