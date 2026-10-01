pub mod chunk_decryptor;
pub mod chunk_encryptor;
pub mod sync_chunk_decryptor;

use std::{error::Error, sync::Arc};

pub use orion::{aead::SecretKey, auth};

use crate::enums::encryption_error::EncryptionError;

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const INDEX_LEN: usize = 8;
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + INDEX_LEN + NONCE_LEN + TAG_LEN;
pub const ENCRYPTION_VERSION: i32 = 1;

pub const KEY_LENGTH: usize = 32;
pub const MPSC_CHANNEL_CAPACITY: usize = 2;

/// Size on disk of an encrypted file holding `plaintext_len` bytes: every
/// chunk carries its index, nonce and tag on top of its plaintext.
pub fn encrypted_len(plaintext_len: u64) -> u64 {
    let chunk_size = CHUNK_SIZE as u64;
    let overhead = (ENCRYPTED_CHUNK_SIZE - CHUNK_SIZE) as u64;

    plaintext_len + plaintext_len.div_ceil(chunk_size) * overhead
}

/// A file's key and format. Clones share the key rather than copying the key
/// material.
#[derive(Clone)]
pub struct FileEncryptionMetadata {
    pub key: Arc<SecretKey>,
    pub encryption_version: i32,
    pub total_size: u64,
}

impl FileEncryptionMetadata {
    pub fn new() -> FileEncryptionMetadata {
        FileEncryptionMetadata {
            key: Arc::new(
                SecretKey::generate(KEY_LENGTH).expect("the OS random number generator failed"),
            ),
            encryption_version: ENCRYPTION_VERSION,
            total_size: 0,
        }
    }

    /// Fails unless the file is in the one format this code reads and writes.
    /// A future format must get a new version and keep a reader for version 1.
    pub fn check_version(&self) -> Result<(), EncryptionError> {
        if self.encryption_version != ENCRYPTION_VERSION {
            return Err(EncryptionError::UnsupportedVersion(self.encryption_version));
        }

        Ok(())
    }

    pub fn derive_thumbnail_metadata(
        &self,
        salt: &[u8],
    ) -> Result<FileEncryptionMetadata, Box<dyn Error>> {
        let secret_key = auth::SecretKey::from_slice(self.key.unprotected_as_bytes())?;
        let tag = auth::authenticate(&secret_key, salt)?;
        let derived_key = SecretKey::from_slice(tag.unprotected_as_bytes())?;
        Ok(FileEncryptionMetadata {
            key: Arc::new(derived_key),
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
