use std::{
    fs::{self, OpenOptions},
    io::ErrorKind,
};

use rocket::tokio::task;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    config::AppConfig,
    db::sqlite,
    enums::request_error::RequestError,
    session::credentials::{check_password_strength, validate_credentials},
};

/// Creates an account after checking the username and the password's
/// strength. Accounts are only ever created here; logging in never creates
/// one.
pub async fn create_account(
    username: &str,
    password: &SecretString,
    config: &AppConfig,
) -> Result<(), RequestError> {
    validate_credentials(username, password.expose_secret())?;
    check_password_strength(
        password.expose_secret(),
        config.minimum_password_security_score,
    )?;

    create_account_storage(username, password, config).await
}

/// Creates the user's directory and encrypted database, without checking the
/// password's strength. Fails with `AccountAlreadyExists` if the user already
/// has a database; a directory without one is set up normally.
pub async fn create_account_storage(
    username: &str,
    password: &SecretString,
    config: &AppConfig,
) -> Result<(), RequestError> {
    let username = username.to_owned();
    let password = password.clone();
    let user_path = config.user_data_path.join(&username);
    let db_config = config.db.clone();

    task::spawn_blocking(move || {
        let db_path = user_path.join(format!("{username}.db"));

        fs::create_dir_all(&user_path).map_err(|e| {
            error!("Failed to create user directory for {}: {}", username, e);

            RequestError::InternalServerError
        })?;

        // Claims the database file atomically, so two concurrent requests for
        // the same username can't both set its password.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&db_path)
        {
            Ok(_) => {},
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(RequestError::AccountAlreadyExists);
            },
            Err(e) => {
                error!("Failed to create database for {}: {}", username, e);

                return Err(RequestError::InternalServerError);
            },
        }

        // Keys the new database with the password and runs the migrations.
        if let Err(e) = sqlite::create_user_db_connection(db_path.clone(), password, &db_config) {
            error!("Failed to initialize database for {}: {}", username, e);

            let _ = fs::remove_file(&db_path);

            return Err(RequestError::InternalServerError);
        }

        info!("Created account {}", username);

        Ok(())
    })
    .await
    .map_err(|e| {
        error!("Blocking task failed: {}", e);

        RequestError::InternalServerError
    })?
}
