use rocket::{
    config::{Config, TlsConfig},
    data::{ByteUnit, Limits},
    figment::Figment,
    http::uri::Segments,
    launch,
    request::FromSegments,
    shield::{Hsts, Shield},
    time::Duration,
    tokio::{
        fs,
        sync::{RwLock, Semaphore},
    },
};
use routes::{
    file::{delete_file, file_options, get_file, move_file, put_file},
    folder::{create_folder, folder_options, get_folder},
    session::{create_session, create_session_options, destroy_session, destroy_session_options},
    thumbnail::{get_thumbnail, thumbnail_options},
};
use session::user_session::UserSession;
use std::{
    collections::HashMap,
    env,
    error::Error,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use web::fairings::Cors;

mod db;
mod enums;
mod routes;
mod session;
mod streaming;
mod web;

#[macro_use]
extern crate rocket;
extern crate serde;

pub struct AppState {
    active_sessions: RwLock<HashMap<String, Arc<RwLock<UserSession>>>>,
    thumbnail_semaphore: Arc<Semaphore>,
}

#[derive(Debug)]
struct UnrestrictedPath(Vec<String>);

impl UnrestrictedPath {
    /// Convert to a PathBuf while sanitizing the path
    pub fn to_path_buf(&self) -> PathBuf {
        self.0.iter().fold(PathBuf::new(), |mut pb, segment| {
            pb.push(segment);
            pb
        })
    }
}

impl<'r> FromSegments<'r> for UnrestrictedPath {
    type Error = rocket::http::uri::Error<'r>;

    fn from_segments(
        segments: Segments<'r, rocket::http::uri::fmt::Path>,
    ) -> Result<Self, Self::Error> {
        Ok(UnrestrictedPath(
            segments.into_iter().map(|s| s.to_string()).collect(),
        ))
    }
}

async fn remove_sharded_path(base_path: &Path, file_path: &Path) -> Result<(), Box<dyn Error>> {
    fs::remove_file(file_path).await?;

    let mut current_dir = file_path.parent();

    while let Some(dir) = current_dir {
        if dir == base_path {
            break;
        }

        if fs::read_dir(dir).await?.next_entry().await?.is_none() {
            fs::remove_dir(dir).await?;
        } else {
            break;
        }
        current_dir = dir.parent();
    }
    Ok(())
}

fn get_sharded_path(mut user_path: PathBuf, file_name: &String) -> PathBuf {
    if file_name.len() >= 4 {
        user_path.push(&file_name[0..2]);
        user_path.push(&file_name[2..4]);
    }
    user_path.push(file_name);

    user_path
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
    let secret_key = get_required_env_var(
        "JUSTENCRYPT_ROCKET_SECRET_KEY",
        "ept8SXw6KDzOX2Yko87xvH9lwRvOzdUc/BoheaN0Uhk=",
        "JUSTENCRYPT_ROCKET_SECRET_KEY must be set in release mode.",
    );

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
        .merge((
            "log_level",
            env::var("JUSTENCRYPT_LOG_LEVEL").unwrap_or_else(|_| "critical".into()),
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

    let tls_key_path = env::var("JUSTENCRYPT_TLS_KEY_PATH").unwrap_or_default();
    let tls_cert_path = env::var("JUSTENCRYPT_TLS_CERT_PATH").unwrap_or_default();

    // Only add TLS config if both paths are non-empty
    if !tls_cert_path.is_empty() && !tls_key_path.is_empty() {
        app_config.merge(("tls", TlsConfig::from_paths(tls_cert_path, tls_key_path)))
    } else {
        app_config
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv::dotenv().ok();

    let app_config = get_app_config();

    let workers: u16 = app_config.extract_inner("workers").unwrap();
    let semaphore_tickets = ((workers as usize * 7) / 10).max(1);

    let state = AppState {
        active_sessions: RwLock::default(),
        thumbnail_semaphore: Arc::new(Semaphore::new(semaphore_tickets)),
    };

    let hsts = Hsts::Enable(Duration::days(365));

    rocket::custom(app_config)
        .attach(Cors)
        .attach(Shield::default().enable(hsts))
        .manage(state)
        .mount(
            "/file",
            routes![get_file, put_file, delete_file, file_options, move_file],
        )
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount(
            "/folder",
            routes![get_folder, create_folder, folder_options],
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
