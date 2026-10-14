use std::{io::Write, process, sync::Arc, time::Duration};

use app::App;
use config::AppConfig;
use web::middleware::ACCESS_LOG_TARGET;

pub mod app;
pub mod config;
pub mod db;
pub mod encryption;
pub mod enums;
pub mod service;
pub mod session;
pub mod storage;
pub mod util;
pub mod web;

#[macro_use]
extern crate log;

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

    info!("justencrypt {}", util::version::VERSION);

    // The runtime is built here, rather than by a framework macro, so the
    // configured worker and blocking thread counts apply to it.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.runtime.workers.get())
        .max_blocking_threads(config.runtime.max_blocking_threads.get())
        .thread_name("justencrypt-worker")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("Failed to start the async runtime: {}", e);

            process::exit(1);
        },
    };

    let app = Arc::new(App::new(config));

    trace!("Application state initialized.");

    let result = runtime.block_on(web::server::run(app));

    // Work still running, such as a download whose client went away, is not
    // waited for.
    runtime.shutdown_timeout(Duration::from_millis(500));

    if let Err(e) = result {
        error!("The server stopped: {}", e);

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
        .filter_level(config.runtime.log_level.filter())
        .filter_module("hyper", config.http.log_level.filter())
        .filter_module("hyper_util", config.http.log_level.filter())
        .filter_module("h2", config.http.log_level.filter())
        .filter_module("axum", config.http.log_level.filter())
        .filter_module("axum_extra", config.http.log_level.filter())
        .filter_module(ACCESS_LOG_TARGET, config.http.log_level.filter())
        .init();
}

#[cfg(test)]
pub mod tests;
