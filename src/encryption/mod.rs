pub mod stream_decryptor;
pub mod stream_encryptor;

pub use orion::{aead::streaming::ABYTES, kex::SecretKey};

pub const NONCE_SIZE: usize = 24; // Nonce size for the XChaCha20 algorithm
pub const SALT_SIZE: usize = 32; // 32 byte salt
pub const TAG_SIZE: usize = ABYTES; //  POLY1305 outsize (16) + tag size (1)

pub const BUFFER_SIZE: usize = 1024 * 16; // Adjust this buffer size as needed (Minimum 8192)

pub const KEY_LENGTH: usize = 32; // 32 byte key

pub const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000)); // 50 Gigabyte

pub const MPSC_CHANNEL_CAPACITY: usize = 2;

pub struct DerivedKey {
    pub key: SecretKey,
}

pub struct FileEncryptionMetadata {
    pub key: SecretKey,
    pub buffer_size: usize,
    pub nonce_size: usize,
    pub salt_size: usize,
    pub tag_size: usize,
}

impl Default for FileEncryptionMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FileEncryptionMetadata {
    fn clone(&self) -> Self {
        Self {
            key: SecretKey::from_slice(self.key.unprotected_as_bytes()).unwrap(),
            buffer_size: self.buffer_size,
            nonce_size: self.nonce_size,
            salt_size: self.salt_size,
            tag_size: self.tag_size,
        }
    }
}

impl FileEncryptionMetadata {
    pub fn new() -> FileEncryptionMetadata {
        FileEncryptionMetadata {
            key: SecretKey::generate(32).unwrap(),
            buffer_size: BUFFER_SIZE,
            nonce_size: NONCE_SIZE,
            salt_size: SALT_SIZE,
            tag_size: TAG_SIZE,
        }
    }
}
