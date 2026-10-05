use std::{collections::BTreeMap, io};

use orion::aead;
use rocket::tokio::{io::AsyncReadExt, sync::Mutex};

use crate::{
    encryption::{
        encrypted_len, FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, INDEX_LEN,
    },
    enums::encryption_error::EncryptionError,
    session::user_storage::BlobFile,
};

/// Encrypts plaintext into a file of fixed-size encrypted chunks.
///
/// Every chunk is written at its own position in the file, so writing needs
/// no exclusive access: several chunk uploads of one file can be encrypted and
/// written at the same time.
pub struct ChunkEncryptor {
    file: BlobFile,
    metadata: FileEncryptionMetadata,
}

impl ChunkEncryptor {
    /// Encrypts into `file`, which should be empty, with a new key.
    pub fn new(file: BlobFile) -> Self {
        ChunkEncryptor {
            file,
            metadata: FileEncryptionMetadata::new(),
        }
    }

    /// Encrypts into `file`, which should be empty, with the key in `metadata`.
    pub fn new_with_metadata(
        file: BlobFile,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, EncryptionError> {
        metadata.check_version()?;

        Ok(ChunkEncryptor { file, metadata })
    }

    /// The key and format of the file, with its size once known.
    pub fn get_metadata(&self) -> FileEncryptionMetadata {
        self.metadata.clone()
    }

    /// Completes a chunked upload of `total_size` plaintext bytes. The file is
    /// cut to exactly the encrypted length of that size, which drops anything
    /// left past the end by an earlier, longer write of the last chunk.
    pub async fn seal(&mut self, total_size: u64) -> Result<(), EncryptionError> {
        self.file.set_len(encrypted_len(total_size)).await?;
        self.sync().await?;
        self.metadata.total_size = total_size;

        Ok(())
    }

    /// Waits until everything written is on disk, so the file survives a
    /// crash or power loss from here on.
    pub async fn sync(&self) -> Result<(), EncryptionError> {
        self.file.sync().await?;

        Ok(())
    }

    /// Encrypts `source` into the file starting at plaintext `offset`, and
    /// records the plaintext length of every chunk written in
    /// `written_chunks`. Fails with `TooLarge`, before writing the offending
    /// chunk, once more than `max_bytes` have been read.
    ///
    /// Each chunk is written and recorded under the `written_chunks` lock, so
    /// even when two calls write the same chunk, the file and the record end up
    /// describing the same write. Reading and encrypting happen outside it.
    pub async fn encrypt_stream_at_offset<R: AsyncReadExt + Unpin>(
        &self,
        source: &mut R,
        offset: u64,
        max_bytes: u64,
        written_chunks: &Mutex<BTreeMap<u64, u32>>,
    ) -> Result<u64, EncryptionError> {
        if !offset.is_multiple_of(CHUNK_SIZE as u64) {
            return Err(EncryptionError::InvalidOffset(
                "Offset must be a multiple of CHUNK_SIZE".to_string(),
            ));
        }

        self.encrypt_chunks(
            source,
            offset / CHUNK_SIZE as u64,
            max_bytes,
            Some(written_chunks),
        )
        .await
    }

    /// Encrypts all of `source` into the file. Fails with `TooLarge`, before
    /// writing the offending chunk, once more than `max_bytes` have been read.
    pub async fn encrypt_stream<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
        max_bytes: u64,
    ) -> Result<u64, EncryptionError> {
        let total_size = self.encrypt_chunks(source, 0, max_bytes, None).await?;

        self.metadata.total_size = total_size;

        Ok(total_size)
    }

    /// Encrypts `source` chunk by chunk, starting at chunk `first_chunk_index`,
    /// writes each chunk at its place in the file, and returns the plaintext
    /// bytes read. Records each chunk's length in `written_chunks` when
    /// given. Fails with `TooLarge` before writing a chunk that would go
    /// past `max_bytes`.
    async fn encrypt_chunks<R: AsyncReadExt + Unpin>(
        &self,
        source: &mut R,
        first_chunk_index: u64,
        max_bytes: u64,
        written_chunks: Option<&Mutex<BTreeMap<u64, u32>>>,
    ) -> Result<u64, EncryptionError> {
        let mut chunk_index = first_chunk_index;
        let mut total_bytes_read = 0;
        // The chunk index followed by the plaintext, read straight into place.
        let mut indexed_plaintext = vec![0u8; INDEX_LEN + CHUNK_SIZE];

        loop {
            let bytes_read = read_full(source, &mut indexed_plaintext[INDEX_LEN..]).await?;

            if bytes_read == 0 {
                break;
            }

            if total_bytes_read + bytes_read as u64 > max_bytes {
                return Err(EncryptionError::TooLarge);
            }

            indexed_plaintext[..INDEX_LEN].copy_from_slice(&chunk_index.to_le_bytes());

            let encrypted_chunk = aead::seal(
                &self.metadata.key,
                &indexed_plaintext[..INDEX_LEN + bytes_read],
            )
            .map_err(|e| {
                error!("Encryption error at chunk {}: {:?}", chunk_index, e);

                EncryptionError::Crypto(e)
            })?;
            let position = chunk_index * ENCRYPTED_CHUNK_SIZE as u64;

            match written_chunks {
                Some(written_chunks) => {
                    let mut written_chunks = written_chunks.lock().await;

                    self.write_at(encrypted_chunk, position).await?;
                    written_chunks.insert(chunk_index, bytes_read as u32);
                },
                None => self.write_at(encrypted_chunk, position).await?,
            }

            total_bytes_read += bytes_read as u64;
            chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        Ok(total_bytes_read)
    }

    /// Writes an encrypted chunk at `position` in the file.
    async fn write_at(&self, bytes: Vec<u8>, position: u64) -> io::Result<()> {
        self.file.write_at(bytes, position).await
    }
}

// Fills `buf` from `source`, stopping early only at the end of the source.
async fn read_full<R: AsyncReadExt + Unpin>(source: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;

    while filled < buf.len() {
        let n = source.read(&mut buf[filled..]).await?;

        if n == 0 {
            break;
        }

        filled += n;
    }

    Ok(filled)
}
