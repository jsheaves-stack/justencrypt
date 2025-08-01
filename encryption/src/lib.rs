pub use orion::{
    aead::{
        self,
        streaming::{Nonce, StreamOpener, StreamSealer, StreamTag, ABYTES},
    },
    hash::{digest, Digest},
    kdf::{self, Salt},
    kex::SecretKey,
};
use secrecy::{ExposeSecret, SecretString};

use std::{error::Error, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE, Engine};

pub mod file_decryptor;
pub mod file_encryptor;
pub mod stream_decryptor;
pub mod stream_encryptor;

pub const NONCE_SIZE: usize = 24; // Nonce size for the XChaCha20 algorithm
pub const SALT_SIZE: usize = 32; // 32 byte salt
pub const TAG_SIZE: usize = ABYTES; //  POLY1305 outsize (16) + tag size (1)

pub const BUFFER_SIZE: usize = 1024 * 16; // Adjust this buffer size as needed (Minimum 8192)

const KEY_ITERATIONS: usize = 40;
const KEY_MEMORY: usize = 1 << 18; // 256000 bytes
const KEY_LENGTH: usize = 32; // 32 byte key

pub struct DerivedKey {
    pub key: SecretKey,
    pub salt: Salt,
}

pub fn derive_key_from_string(passphrase: &SecretString) -> Result<DerivedKey, Box<dyn Error>> {
    let salt = Salt::generate(SALT_SIZE)?;

    derive_key_from_string_and_salt(passphrase, &salt)
}

pub fn derive_key_from_string_and_salt(
    passphrase: &SecretString,
    salt: &Salt,
) -> Result<DerivedKey, Box<dyn Error>> {
    let password = kdf::Password::from_slice(passphrase.expose_secret().as_bytes())?;

    let key_iterations = KEY_ITERATIONS.try_into()?;
    let key_memory = KEY_MEMORY.try_into()?;
    let key_length = KEY_LENGTH.try_into()?;

    let key = kdf::derive_key(&password, salt, key_iterations, key_memory, key_length)?;

    Ok(DerivedKey {
        key: SecretKey::from_slice(key.unprotected_as_bytes())?,
        salt: Salt::from_slice(salt.as_ref().to_vec().as_slice())?,
    })
}

pub enum Auth {
    Passphrase(SecretString),
    DerivedKey(SecretKey, Salt),
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let key_len = self.key.len();
        bytes.extend_from_slice(&(key_len as u64).to_le_bytes());
        bytes.extend_from_slice(self.key.unprotected_as_bytes());

        // Serialize the usize fields
        bytes.extend_from_slice(&self.buffer_size.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_size.to_le_bytes());
        bytes.extend_from_slice(&self.salt_size.to_le_bytes());
        bytes.extend_from_slice(&self.tag_size.to_le_bytes());

        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() < 8 {
            return Err("Invalid byte array length".into());
        }

        let key_len = u64::from_le_bytes(bytes[0..8].try_into()?) as usize;

        let usize_len = std::mem::size_of::<usize>();

        if bytes.len() < 8 + key_len + 4 * usize_len {
            return Err("Invalid byte array length".into());
        }

        let key = SecretKey::from_slice(&bytes[8..8 + key_len]).unwrap();

        let buffer_size =
            usize::from_le_bytes(bytes[8 + key_len..8 + key_len + usize_len].try_into()?);

        let nonce_size = usize::from_le_bytes(
            bytes[8 + key_len + usize_len..8 + key_len + 2 * usize_len].try_into()?,
        );

        let salt_size = usize::from_le_bytes(
            bytes[8 + key_len + 2 * usize_len..8 + key_len + 3 * usize_len].try_into()?,
        );

        let tag_size = usize::from_le_bytes(
            bytes[8 + key_len + 3 * usize_len..8 + key_len + 4 * usize_len].try_into()?,
        );

        Ok(FileEncryptionMetadata {
            key,
            buffer_size,
            nonce_size,
            salt_size,
            tag_size,
        })
    }
}

pub fn get_encoded_file_name(file_path: PathBuf) -> Result<String, Box<dyn Error>> {
    let hashed_file_path: Digest = digest(file_path.to_string_lossy().as_bytes())?;

    Ok(URL_SAFE.encode(hashed_file_path.as_ref()))
}

#[cfg(test)]
mod tests {
    use crate::{
        file_decryptor::FileDecryptor, file_encryptor::FileEncryptor,
        stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor,
    };

    use super::*;

    #[tokio::test]
    async fn test_derive_key_from_string() {
        let passphrase = SecretString::new("securepassword123".to_string());
        let result = derive_key_from_string(&passphrase);

        assert!(result.is_ok());

        let derived_key = result.unwrap();
        assert_eq!(derived_key.key.unprotected_as_bytes().len(), KEY_LENGTH);
        assert_eq!(derived_key.salt.as_ref().len(), SALT_SIZE);
    }

    #[tokio::test]
    async fn test_file_encryption_decryption() {
        use tokio::fs;

        let temp_file_path = PathBuf::from("./test_file.enc");
        let passphrase = SecretString::new("securepassword123".to_string());

        let mut encryptor =
            FileEncryptor::new(&temp_file_path, Auth::Passphrase(passphrase.clone()))
                .await
                .unwrap();

        let data = b"This is test data";

        encryptor.encrypt_file(data).await.unwrap();

        let mut decryptor = FileDecryptor::new(&temp_file_path, Auth::Passphrase(passphrase))
            .await
            .unwrap();

        let decrypted_data = decryptor.decrypt_file().await.unwrap();

        assert_eq!(decrypted_data, data);

        // Clean up
        fs::remove_file(temp_file_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_metadata_serialization_deserialization() {
        let metadata = FileEncryptionMetadata {
            key: SecretKey::generate(32).unwrap(),
            buffer_size: 16384,
            nonce_size: 24,
            salt_size: 32,
            tag_size: 16,
        };

        let serialized = metadata.serialize();
        let deserialized = FileEncryptionMetadata::deserialize(&serialized).unwrap();

        assert_eq!(metadata.key, deserialized.key);
        assert_eq!(metadata.buffer_size, deserialized.buffer_size);
        assert_eq!(metadata.nonce_size, deserialized.nonce_size);
        assert_eq!(metadata.salt_size, deserialized.salt_size);
        assert_eq!(metadata.tag_size, deserialized.tag_size);
    }

    #[tokio::test]
    async fn test_stream_encryption_decryption() {
        use tokio::fs;

        let temp_file_path = PathBuf::from("./test_stream.enc");

        let mut stream_encryptor = StreamEncryptor::new(temp_file_path.clone()).await.unwrap();

        let metadata = stream_encryptor.get_file_encryption_metadata();

        let data = b"This is a test stream chunk.";

        stream_encryptor.write_salt_and_nonce().await.unwrap();

        let encrypted_chunk = stream_encryptor.encrypt_chunk(data).await.unwrap();

        stream_encryptor
            .write_chunk(encrypted_chunk.clone())
            .await
            .unwrap();

        let mut stream_decryptor = StreamDecryptor::new(temp_file_path.clone(), metadata)
            .await
            .unwrap();

        let decrypted_chunk = stream_decryptor
            .decrypt_chunk(&encrypted_chunk)
            .await
            .unwrap();

        assert_eq!(decrypted_chunk, data);

        // Clean up
        fs::remove_file(temp_file_path.clone()).await.unwrap();
    }
}
