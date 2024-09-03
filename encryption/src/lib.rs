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

const KEY_ITERATIONS: usize = 40;
const KEY_MEMORY: usize = 1 << 18; // 256000 bytes
const KEY_LENGTH: usize = 32; // 32 byte key

pub struct DerivedKey {
    pub key: SecretKey,
    pub salt: Salt,
}

trait Encryptor {
    fn derive_key_from_string(passphrase: &SecretString) -> Result<DerivedKey, Box<dyn Error>> {
        let salt = Salt::generate(SALT_SIZE)?;

        Self::derive_key_from_string_and_salt(passphrase, &salt)
    }

    fn derive_key_from_string_and_salt(
        passphrase: &SecretString,
        salt: &Salt,
    ) -> Result<DerivedKey, Box<dyn Error>> {
        let password = kdf::Password::from_slice(passphrase.expose_secret().as_bytes())?;

        let key_iterations = KEY_ITERATIONS.try_into()?;
        let key_memory = KEY_MEMORY.try_into()?;
        let key_length = KEY_LENGTH.try_into()?;

        let key = kdf::derive_key(&password, &salt, key_iterations, key_memory, key_length)?;

        Ok(DerivedKey {
            key: SecretKey::from_slice(key.unprotected_as_bytes())?,
            salt: Salt::from_slice(salt.as_ref().to_vec().as_slice())?,
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

pub struct FileEncryptionMetadata {
    key: Vec<u8>,
    buffer_size: usize,
    nonce_size: usize,
    salt_size: usize,
    tag_size: usize,
}

impl FileEncryptionMetadata {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let key_len = self.key.len();
        bytes.extend_from_slice(&(key_len as u64).to_le_bytes());
        bytes.extend_from_slice(&self.key);

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

        let key = bytes[8..8 + key_len].to_vec();

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
        derived_key: DerivedKey,
    ) -> Result<Self, Box<dyn Error>> {
        let encoded_file_name = get_encoded_file_name(&file_path)?;
        let encoded_file_path = user_path.join(encoded_file_name);

        let secret_key = SecretKey::generate(KEY_LENGTH)?;
        let salt = Salt::generate(SALT_SIZE)?;
        let (sealer, nonce) = StreamSealer::new(&secret_key)?;

        let mut key_encryptor = FileEncryptor::new(
            &encoded_file_path.with_extension("meta"),
            Auth::DerivedKey(
                SecretKey::from_slice(derived_key.key.unprotected_as_bytes().to_vec().as_slice())
                    .unwrap(),
                Salt::from_slice(derived_key.salt.as_ref().to_vec().as_slice()).unwrap(),
            ),
        )
        .await?;

        let file_encryption_metadata = FileEncryptionMetadata {
            key: secret_key.unprotected_as_bytes().to_vec(),
            buffer_size: BUFFER_SIZE,
            nonce_size: NONCE_SIZE,
            salt_size: SALT_SIZE,
            tag_size: TAG_SIZE,
        };

        key_encryptor
            .encrypt_file(&file_encryption_metadata.serialize())
            .await?;

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
    pub async fn new(file_path: &PathBuf, auth: &Auth) -> Result<Self, Box<dyn Error>> {
        let mut input_file = File::open(file_path).await?;
        let mut salt_buf = [0u8; SALT_SIZE];

        input_file.read_exact(&mut salt_buf).await?;

        let salt = Salt::from_slice(&salt_buf)?;

        let key = match auth {
            Auth::Passphrase(passphrase) => {
                let derived = Self::derive_key_from_string_and_salt(passphrase, &salt)?;
                derived.key
            }
            Auth::DerivedKey(key, _) => SecretKey::from_slice(key.unprotected_as_bytes())?,
        };

        let key_salt = DerivedKey {
            key: SecretKey::from_slice(key.unprotected_as_bytes().to_vec().as_slice()).unwrap(),
            salt: Salt::from_slice(salt.as_ref().to_vec().as_slice()).unwrap(),
        };

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
        derived_key: &DerivedKey,
    ) -> Result<Self, Box<dyn Error>> {
        let encoded_file_name = get_encoded_file_name(&file_path)?;
        let encoded_file_path = user_path.join(&encoded_file_name);
        let key_file_path = encoded_file_path.with_extension("meta");

        let auth = Auth::DerivedKey(
            SecretKey::from_slice(derived_key.key.unprotected_as_bytes().to_vec().as_slice())
                .unwrap(),
            Salt::from_slice(derived_key.salt.as_ref().to_vec().as_slice()).unwrap(),
        );

        let mut file_encryption_metadata_decryptor =
            FileDecryptor::new(&key_file_path, &auth).await?;

        let file_encryption_metadata_vec =
            file_encryption_metadata_decryptor.decrypt_file().await?;

        let file_encryption_metadata =
            FileEncryptionMetadata::deserialize(&file_encryption_metadata_vec)?;

        let file = File::open(&encoded_file_path).await?;
        let mut reader = BufReader::new(file);

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf).await?;
        reader.read_exact(&mut nonce_buf).await?;

        let nonce = Nonce::from_slice(&nonce_buf)?;

        let opener = StreamOpener::new(
            &SecretKey::from_slice(&file_encryption_metadata.key.as_slice()).unwrap(),
            &nonce,
        )?;

        Ok(StreamDecryptor {
            opener,
            file_path: PathBuf::from(encoded_file_path),
        })
    }

    pub async fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }
}
