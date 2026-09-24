use std::{
    env,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::PathBuf,
};

use rocket::tokio::task;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    db::sqlite,
    enums::request_error::RequestError,
    session::credentials::{check_password_strength, validate_credentials},
};

/// Directory that holds one sub-directory per user
/// (`JUSTENCRYPT_USER_DATA_PATH`, default `./user_data`).
pub fn user_data_path() -> PathBuf {
    PathBuf::from(env::var("JUSTENCRYPT_USER_DATA_PATH").unwrap_or_else(|_| "./user_data".into()))
}

/// Creates an account after checking the username and the password's
/// strength. Accounts are only ever created here; logging in never creates
/// one.
pub async fn create_account(username: &str, password: &SecretString) -> Result<(), RequestError> {
    validate_credentials(username, password.expose_secret())?;
    check_password_strength(password.expose_secret())?;

    create_account_storage(username, password).await
}

/// Creates the user's directory and encrypted database, without checking the
/// password's strength. Fails with `AccountAlreadyExists` if the user already
/// has a database; a directory without one is set up normally.
pub async fn create_account_storage(
    username: &str,
    password: &SecretString,
) -> Result<(), RequestError> {
    let username = username.to_owned();
    let password = password.clone();

    task::spawn_blocking(move || {
        let user_path = user_data_path().join(&username);
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
        if let Err(e) = sqlite::create_user_db_connection(db_path.clone(), password) {
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
