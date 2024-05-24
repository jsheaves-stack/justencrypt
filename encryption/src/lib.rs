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
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
};

use std::{error::Error, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE, Engine};

pub const NONCE_SIZE: usize = 24; // Nonce size for the XChaCha20 algorithm
pub const SALT_SIZE: usize = 32; // 32 byte salt
pub const TAG_SIZE: usize = ABYTES; //  POLY1305 outsize (16) + tag size (1)

pub const BUFFER_SIZE: usize = 1024 * 16; // Adjust this buffer size as needed (Minimum 8192)

const KEY_ITERATIONS: usize = 10;
const KEY_MEMORY: usize = 1 << 16; // 65536 bytes
const KEY_LENGTH: usize = 32; // 32 byte key

pub struct DerivedKey {
    pub key: SecretKey,
    pub salt: Salt,
}

trait Encryptor {
    fn derive_key_from_string(passphrase: &SecretString) -> Result<DerivedKey, Box<dyn Error>> {
        let salt = Salt::generate(SALT_SIZE)?;

        Self::derive_key_from_string_and_salt(passphrase, salt)
    }

    fn derive_key_from_string_and_salt(
        passphrase: &SecretString,
        salt: Salt,
    ) -> Result<DerivedKey, Box<dyn Error>> {
        let password = kdf::Password::from_slice(passphrase.expose_secret().as_bytes())?;

        let key_iterations = KEY_ITERATIONS.try_into()?;
        let key_memory = KEY_MEMORY.try_into()?;
        let key_length = KEY_LENGTH.try_into()?;

        let key = kdf::derive_key(&password, &salt, key_iterations, key_memory, key_length)?;

        Ok(DerivedKey {
            key: SecretKey::from_slice(key.unprotected_as_bytes())?,
            salt: Salt::from(salt),
        })
    }
}

impl Encryptor for FileEncryptor {}
impl Encryptor for StreamEncryptor {}

impl Encryptor for FileDecryptor {}
impl Encryptor for StreamDecryptor {}

pub enum Auth {
    Passphrase(SecretString),
    DerivedKey(SecretKey, Salt),
}

pub struct FileEncryptor {
    file: File,
    derived_key: DerivedKey,
}

impl FileEncryptor {
    pub async fn new(file_path: &PathBuf, auth: Auth) -> Result<Self, Box<dyn Error>> {
        let input_file = File::create(file_path).await?;

        let (key, salt) = match auth {
            Auth::Passphrase(passphrase) => {
                let key_salt = Self::derive_key_from_string(&passphrase)?;

                (key_salt.key, key_salt.salt)
            }
            Auth::DerivedKey(key, salt) => (key, salt),
        };

        Ok(FileEncryptor {
            file: input_file,
            derived_key: DerivedKey { key, salt },
        })
    }

    pub async fn encrypt_file(&mut self, file_data: &[u8]) -> Result<(), Box<dyn Error>> {
        let encrypted_data = aead::seal(&self.derived_key.key, file_data)?;

        self.file.write_all(&self.derived_key.salt.as_ref()).await?;
        self.file.write_all(encrypted_data.as_slice()).await?;

        Ok(())
    }
}

pub struct StreamEncryptor {
    file: File,
    sealer: StreamSealer,
    nonce: Nonce,
    salt: Salt,
}

pub fn get_encoded_file_name(file_path: &PathBuf) -> Result<String, Box<dyn Error>> {
    let hashed_file_path: Digest = digest(&file_path.to_string_lossy().as_bytes())?;

    Ok(URL_SAFE.encode(hashed_file_path.as_ref().to_vec()))
}

impl StreamEncryptor {
    pub async fn new(
        user_path: &PathBuf,
        file_path: &PathBuf,
        passphrase: &SecretString,
    ) -> Result<Self, Box<dyn Error>> {
        let encoded_file_name = get_encoded_file_name(&file_path)?;
        let encoded_file_path = user_path.join(encoded_file_name);

        let derived_key = Self::derive_key_from_string(&passphrase)?;
        let salt = Salt::from(derived_key.salt);

        let (sealer, nonce) = StreamSealer::new(&derived_key.key)?;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&encoded_file_path)
            .await?;

        Ok(StreamEncryptor {
            sealer,
            nonce,
            salt,
            file,
        })
    }

    // Function to write salt and nonce to the output file
    pub async fn write_salt_and_nonce(&mut self) -> Result<(), Box<dyn Error>> {
        self.file.write_all(&self.salt.as_ref()).await?;
        self.file.write_all(&self.nonce.as_ref()).await?;

        Ok(())
    }

    // Encrypt a single chunk of data
    pub async fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let stream_tag = if data.len() < BUFFER_SIZE {
            StreamTag::Finish
        } else {
            StreamTag::Message
        };

        let chunk = self.sealer.seal_chunk(data, &stream_tag)?;

        Ok(chunk)
    }

    pub async fn write_chunk(&mut self, data: &Vec<u8>) -> Result<(), Box<dyn Error>> {
        self.file.write_all(&data).await?;

        Ok(())
    }
}

pub struct FileDecryptor {
    file: File,
    pub key_salt: DerivedKey,
}

impl FileDecryptor {
    pub async fn new(
        file_path: &PathBuf,
        passphrase: &SecretString,
    ) -> Result<Self, Box<dyn Error>> {
        let mut input_file = File::open(file_path).await?;
        let mut salt_buf = [0u8; SALT_SIZE];

        input_file.read_exact(&mut salt_buf).await?;

        let salt = Salt::from_slice(&salt_buf)?;

        let key_salt = Self::derive_key_from_string_and_salt(&passphrase, salt)?;

        Ok(FileDecryptor {
            file: input_file,
            key_salt,
        })
    }

    pub async fn decrypt_file(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut file_buffer = vec![];

        self.file.read_to_end(&mut file_buffer).await?;

        let decrypted_data = aead::open(&self.key_salt.key, &file_buffer)?;

        Ok(decrypted_data)
    }
}

pub struct StreamDecryptor {
    opener: StreamOpener,
    pub file_path: PathBuf,
}

impl StreamDecryptor {
    pub async fn new(
        user_path: &PathBuf,
        file_path: &PathBuf,
        passphrase: &SecretString,
    ) -> Result<Self, Box<dyn Error>> {
        let encoded_file_name = get_encoded_file_name(&file_path)?;
        let encoded_file_path = user_path.join(&encoded_file_name);

        let file = File::open(&encoded_file_path).await?;
        let mut reader = BufReader::new(file);

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf).await?;
        reader.read_exact(&mut nonce_buf).await?;

        let salt = Salt::from_slice(&salt_buf)?;
        let nonce = Nonce::from_slice(&nonce_buf)?;

        let derived_key = Self::derive_key_from_string_and_salt(&passphrase, salt)?;

        let opener = StreamOpener::new(&derived_key.key, &nonce)?;

        Ok(StreamDecryptor {
            opener,
            file_path: PathBuf::from(encoded_file_path),
        })
    }

    pub async fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }
}
