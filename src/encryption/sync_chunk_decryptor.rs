use orion::aead;
use std::{
    cmp,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
};

use crate::encryption::{FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE};

pub struct SyncChunkDecryptReader {
    file: File,
    metadata: FileEncryptionMetadata,
    current_chunk_index: u64,
    current_chunk_buffer: Vec<u8>,
    total_size: u64,
    current_pos: u64,
}

impl SyncChunkDecryptReader {
    pub fn new(file_path: PathBuf, metadata: FileEncryptionMetadata) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let total_size = metadata.total_size;

        Ok(SyncChunkDecryptReader {
            file,
            metadata,
            current_chunk_index: u64::MAX,
            current_chunk_buffer: Vec::new(),
            total_size,
            current_pos: 0,
        })
    }

    fn load_chunk(&mut self, chunk_index: u64) -> io::Result<()> {
        let disk_offset = chunk_index * (ENCRYPTED_CHUNK_SIZE as u64);
        self.file.seek(SeekFrom::Start(disk_offset))?;

        let mut encrypted_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let mut bytes_read = 0;

        while bytes_read < ENCRYPTED_CHUNK_SIZE {
            match self.file.read(&mut encrypted_buffer[bytes_read..]) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if bytes_read == 0 {
            self.current_chunk_buffer = Vec::new();
            self.current_chunk_index = chunk_index;
            return Ok(());
        }

        let decrypted_payload = aead::open(&self.metadata.key, &encrypted_buffer[..bytes_read])
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Decryption error: {:?}", e),
                )
            })?;

        if decrypted_payload.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Chunk too short",
            ));
        }

        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&decrypted_payload[..8]);
        let stored_index = u64::from_le_bytes(index_bytes);

        if stored_index != chunk_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Tampering detected: index mismatch",
            ));
        }

        self.current_chunk_buffer = decrypted_payload[8..].to_vec();
        self.current_chunk_index = chunk_index;

        Ok(())
    }
}

impl Read for SyncChunkDecryptReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current_pos >= self.total_size {
            return Ok(0);
        }

        let chunk_index = self.current_pos / (CHUNK_SIZE as u64);
        let chunk_offset = (self.current_pos % (CHUNK_SIZE as u64)) as usize;

        if self.current_chunk_index != chunk_index {
            self.load_chunk(chunk_index)?;
            if self.current_chunk_buffer.is_empty() {
                return Ok(0);
            }
        }

        let available = self.current_chunk_buffer.len().saturating_sub(chunk_offset);
        if available == 0 {
            return Ok(0);
        }

        let bytes_to_copy = cmp::min(buf.len(), available);
        let end_bound = cmp::min(self.current_pos + bytes_to_copy as u64, self.total_size);
        let actual_bytes = (end_bound - self.current_pos) as usize;

        buf[..actual_bytes]
            .copy_from_slice(&self.current_chunk_buffer[chunk_offset..chunk_offset + actual_bytes]);

        self.current_pos += actual_bytes as u64;
        Ok(actual_bytes)
    }
}

impl Seek for SyncChunkDecryptReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.total_size as i64 + offset,
            SeekFrom::Current(offset) => self.current_pos as i64 + offset,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid seek to a negative position",
            ));
        }

        self.current_pos = new_pos as u64;
        Ok(self.current_pos)
    }
}
