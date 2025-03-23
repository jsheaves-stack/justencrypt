use std::{env, error::Error, path::PathBuf};

use encryption::FileEncryptionMetadata;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use secrecy::SecretString;

use crate::{
    db::{db, sql},
    enums::request_error::RequestError,
};

pub struct AppSession {
    user_path: PathBuf,
    user_db: Pool<SqliteConnectionManager>,
}

impl AppSession {
    pub async fn open<'a>(
        user_name: &String,
        passphrase: &SecretString,
    ) -> Result<Box<Self>, RequestError> {
        let user_data_path = match env::var("JUSTENCRYPT_USER_DATA_PATH") {
            Ok(val) => val,
            Err(_) => String::from("./user_data"),
        };

        let user_path = PathBuf::from(user_data_path).join(user_name);
        let user_db_path = user_path.join(format!("{user_name}.db"));

        let db_pool = db::create_user_db_connection(user_db_path, passphrase.clone());

        Ok(Box::new(Self {
            user_path,
            user_db: db_pool,
        }))
    }

    pub fn get_user_path(&self) -> PathBuf {
        self.user_path.clone()
    }

    pub fn add_file(
        &mut self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), Box<dyn Error>> {
        let _ = sql::add_file(
            &self.user_db,
            file_path.to_str().unwrap(),
            &encoded_file_name.as_str(),
            metadata.key.unprotected_as_bytes(),
            metadata.buffer_size,
            metadata.salt_size,
            metadata.nonce_size,
            metadata.tag_size,
        );

        Ok(())
    }

    pub fn get_file_encryption_metadata(
        &self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, Box<dyn Error>> {
        Ok(sql::get_file(&self.user_db, file_path.to_str().unwrap())?)
    }
}
