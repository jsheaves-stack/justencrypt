pub mod chunk_decryptor;
pub mod chunk_encryptor;

use std::error::Error;

pub use orion::{auth, kex::SecretKey};

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const INDEX_LEN: usize = 8;
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + INDEX_LEN + NONCE_LEN + TAG_LEN;
pub const ENCRYPTION_VERSION: i32 = 1;

pub const KEY_LENGTH: usize = 32;
pub const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000));
pub const MPSC_CHANNEL_CAPACITY: usize = 2;

pub struct FileEncryptionMetadata {
    pub key: SecretKey,
    pub encryption_version: i32,
    pub total_size: u64,
}

impl Clone for FileEncryptionMetadata {
    fn clone(&self) -> Self {
        Self {
            key: SecretKey::from_slice(self.key.unprotected_as_bytes()).unwrap(),
            encryption_version: self.encryption_version,
            total_size: self.total_size,
        }
    }
}

impl FileEncryptionMetadata {
    pub fn new() -> FileEncryptionMetadata {
        FileEncryptionMetadata {
            key: SecretKey::generate(KEY_LENGTH).unwrap(),
            encryption_version: ENCRYPTION_VERSION,
            total_size: 0,
        }
    }

    pub fn derive_thumbnail_metadata(
        &self,
        salt: &[u8],
    ) -> Result<FileEncryptionMetadata, Box<dyn Error>> {
        let secret_key = auth::SecretKey::from_slice(self.key.unprotected_as_bytes())?;
        let tag = auth::authenticate(&secret_key, salt)?;
        let derived_key = SecretKey::from_slice(tag.unprotected_as_bytes())?;
        Ok(FileEncryptionMetadata {
            key: derived_key,
            encryption_version: self.encryption_version,
            total_size: 0,
        })
    }
}

impl Default for FileEncryptionMetadata {
    fn default() -> Self {
        Self::new()
    }
}
