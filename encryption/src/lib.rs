use orion::{
    aead::streaming::{Nonce, StreamOpener, StreamSealer, StreamTag, ABYTES},
    hash::{digest, Digest},
    kdf::{self, Salt},
};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    path::PathBuf,
};

use base64::{engine::general_purpose::URL_SAFE, prelude::*};

pub const NONCE_SIZE: usize = 24; // Nonce size for the XChaCha20 algorithm
pub const SALT_SIZE: usize = 32;
pub const TAG_SIZE: usize = ABYTES;

pub const BUFFER_SIZE: usize = 1024 * 16; // Adjust this buffer size as needed (Minimum 8192)

const KEY_ITERATIONS: usize = 10;
const KEY_MEMORY: usize = 1 << 16;
const KEY_LENGTH: usize = 32;

pub struct Encryptor {
    file: File,
    sealer: StreamSealer,
    nonce: Nonce,
    salt: Salt,
}

impl Encryptor {
    pub fn new(
        user_path: &PathBuf,
        file_path: &PathBuf,
        passphrase: &String,
    ) -> Result<Self, Box<dyn Error>> {
        let password = kdf::Password::from_slice(passphrase.as_bytes())?;
        let salt = Salt::generate(SALT_SIZE)?;

        let key_iterations = KEY_ITERATIONS.try_into()?;
        let key_memory = KEY_MEMORY.try_into()?;
        let key_length = KEY_LENGTH.try_into()?;
        let key = kdf::derive_key(&password, &salt, key_iterations, key_memory, key_length)?;

        let hashed_file_path: Digest = digest(&file_path.to_string_lossy().as_bytes())?;
        let base64_encoded_hash = URL_SAFE.encode(hashed_file_path.as_ref().to_vec());
        let encoded_file_path = user_path.join(base64_encoded_hash);

        let (sealer, nonce) = StreamSealer::new(&key)?;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&encoded_file_path)?;

        Ok(Encryptor {
            sealer,
            nonce,
            salt,
            file,
        })
    }

    // Function to write salt and nonce to the output file
    pub fn write_salt_and_nonce(&mut self) -> Result<(), Box<dyn Error>> {
        self.file.write_all(&self.salt.as_ref())?;
        self.file.write_all(&self.nonce.as_ref())?;

        Ok(())
    }

    // Encrypt a single chunk of data
    pub fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let stream_tag = if data.len() < BUFFER_SIZE {
            StreamTag::Finish
        } else {
            StreamTag::Message
        };

        let chunk = self.sealer.seal_chunk(data, &stream_tag)?;

        Ok(chunk)
    }

    pub fn write_chunk(&mut self, data: &Vec<u8>) -> Result<(), Box<dyn Error>> {
        self.file.write_all(&data)?;

        Ok(())
    }
}

pub struct Decryptor {
    opener: StreamOpener,
    pub file_path: PathBuf,
}

impl Decryptor {
    pub fn new(
        user_path: &PathBuf,
        file_path: &PathBuf,
        passphrase: &String,
    ) -> Result<Self, Box<dyn Error>> {
        let hashed_file_path: Digest = digest(&file_path.to_string_lossy().as_bytes())?;
        let base64_encoded_hash = URL_SAFE.encode(hashed_file_path.as_ref().to_vec());
        let encoded_file_path = user_path.join(base64_encoded_hash);

        let file = File::open(&encoded_file_path)?;
        let mut reader = BufReader::new(&file);

        let password = kdf::Password::from_slice(passphrase.as_bytes())?;

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf)?;
        reader.read_exact(&mut nonce_buf)?;

        let salt = Salt::from_slice(&salt_buf)?;
        let nonce = Nonce::from_slice(&nonce_buf)?;

        let key_iterations = KEY_ITERATIONS.try_into()?;
        let key_memory = KEY_MEMORY.try_into()?;
        let key_length = KEY_LENGTH.try_into()?;
        let key = kdf::derive_key(&password, &salt, key_iterations, key_memory, key_length)?;

        let opener = StreamOpener::new(&key, &nonce)?;

        Ok(Decryptor {
            opener,
            file_path: PathBuf::from(encoded_file_path),
        })
    }

    pub fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }
}
