use std::{error::Error, io::SeekFrom, path::PathBuf};

use orion::aead::streaming::{Nonce, StreamOpener};
use rocket::{
    futures::AsyncWriteExt,
    tokio::{
        fs::File,
        io::{AsyncReadExt, AsyncSeekExt, BufReader},
        sync::mpsc::Sender,
    },
};

use crate::encryption::{
    DerivedKey, FileEncryptionMetadata, BUFFER_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

pub struct StreamDecryptor {
    opener: StreamOpener,
    file_path: PathBuf,
}

impl StreamDecryptor {
    pub async fn new(
        file_path: PathBuf,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, Box<dyn Error>> {
        let file = File::open(file_path.clone()).await?;
        let mut reader = BufReader::new(file);

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf).await?;
        reader.read_exact(&mut nonce_buf).await?;

        let nonce = Nonce::from_slice(&nonce_buf)?;

        let derived_key = DerivedKey { key: metadata.key };

        let opener = StreamOpener::new(&derived_key.key, &nonce)?;

        Ok(StreamDecryptor { opener, file_path })
    }

    pub async fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }

    pub fn get_file_path(&self) -> PathBuf {
        self.file_path.clone()
    }

    pub async fn decrypt_stream_to_writer<
        R: AsyncReadExt + AsyncSeekExt + Unpin,
        W: AsyncWriteExt + Unpin,
    >(
        &mut self,
        source: &mut R,
        writer: &mut W,
        offset: u64,
    ) -> Result<(), Box<dyn Error>> {
        trace!("Entering decrypt_stream_to_writer");

        // Skip the encryption metadata (salt and nonce).
        source.seek(SeekFrom::Start(offset)).await?;

        trace!("Seeked past metadata (offset: {}).", offset);

        let mut encrypted_read_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        loop {
            // Read a chunk of data from the encrypted file.
            let bytes_read = match source.read(&mut encrypted_read_buffer).await {
                Ok(0) => {
                    trace!("End of encrypted file.");
                    break; // End of file
                }
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to read encrypted file chunk: {}", e);
                    return Err(Box::new(e));
                }
            };

            trace!("Read {} encrypted bytes from file.", bytes_read);

            // Decrypt the chunk.
            let decrypted_chunk = self
                .decrypt_chunk(&encrypted_read_buffer[..bytes_read])
                .await?;

            if decrypted_chunk.is_empty() {
                trace!("Decrypted chunk is empty, assuming end of stream.");
                break;
            }

            trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

            // Write the decrypted chunk to the destination writer.
            writer.write_all(&decrypted_chunk).await?;
        }

        trace!("Exiting decrypt_stream_to_writer");

        Ok(())
    }

    pub async fn decrypt_stream_to_channel<R: AsyncReadExt + AsyncSeekExt + Unpin>(
        &mut self,
        source: &mut R,
        tx: Sender<Vec<u8>>,
        offset: u64,
    ) {
        trace!("Entering spawned task: decrypt_stream_to_channel");

        // Skip the encryption metadata (salt and nonce).
        if let Err(e) = source.seek(SeekFrom::Start(offset)).await {
            error!("Failed to seek in file: {}", e);
            return;
        }

        trace!("Seeked past metadata (offset: {}).", offset);

        let mut encrypted_read_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        loop {
            // Read a chunk of data from the encrypted file.
            let bytes_read = match source.read(&mut encrypted_read_buffer).await {
                Ok(0) => {
                    trace!("End of encrypted file.");
                    break; // End of file
                }
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to read encrypted file chunk: {}", e);
                    return;
                }
            };

            trace!("Read {} encrypted bytes from file.", bytes_read);

            // Decrypt the chunk.
            let decrypted_chunk = self
                .decrypt_chunk(&encrypted_read_buffer[..bytes_read])
                .await
                .unwrap();

            if decrypted_chunk.is_empty() {
                trace!("Decrypted chunk is empty, assuming end of stream.");
                break;
            }

            trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

            // Send the decrypted chunk for streaming.
            if tx.send(decrypted_chunk).await.is_err() {
                info!(
                    "Failed to send decrypted chunk: channel closed (client likely disconnected)."
                );
                return;
            }

            trace!("Sent decrypted chunk to stream.");
        }

        trace!("Finished processing all chunks in decryption task.");
    }
}
