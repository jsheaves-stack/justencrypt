use std::{collections::BTreeMap, io::Cursor};

use rocket::{
    async_test,
    tokio::{fs, sync::Mutex},
};
use tempfile::tempdir;

use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor, encrypted_len,
        FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE,
    },
    enums::encryption_error::EncryptionError,
    util::thumbnails::write_encrypted_atomically,
};

#[async_test]
async fn test_encrypt_stream_at_offset() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_encrypt_offset.enc");
    let encryptor = ChunkEncryptor::new(file_path.clone()).await.unwrap();

    let written_chunks = Mutex::new(BTreeMap::new());
    let mut data = Cursor::new(vec![b'A'; CHUNK_SIZE]);

    // Encrypt at offset 0
    encryptor
        .encrypt_stream_at_offset(&mut data, 0, u64::MAX, &written_chunks)
        .await
        .unwrap();
    assert_eq!(
        written_chunks.lock().await.get(&0),
        Some(&(CHUNK_SIZE as u32))
    );

    // Encrypt at offset CHUNK_SIZE
    let mut data2 = Cursor::new(vec![b'B'; CHUNK_SIZE]);
    encryptor
        .encrypt_stream_at_offset(&mut data2, CHUNK_SIZE as u64, u64::MAX, &written_chunks)
        .await
        .unwrap();
    assert_eq!(
        written_chunks.lock().await.get(&1),
        Some(&(CHUNK_SIZE as u32))
    );

    drop(encryptor);

    // Verify file size
    let metadata = fs::metadata(file_path).await.unwrap();
    assert_eq!(metadata.len(), (ENCRYPTED_CHUNK_SIZE * 2) as u64);
}

#[async_test]
async fn test_encrypt_stream_at_invalid_offset() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_invalid_offset.enc");
    let encryptor = ChunkEncryptor::new(file_path).await.unwrap();

    let written_chunks = Mutex::new(BTreeMap::new());
    let mut data = Cursor::new(vec![b'A'; 100]);

    // Offset not a multiple of CHUNK_SIZE
    let result = encryptor
        .encrypt_stream_at_offset(&mut data, 100, u64::MAX, &written_chunks)
        .await;
    assert!(result.is_err());
}

#[test]
fn test_encrypted_len() {
    let overhead = (ENCRYPTED_CHUNK_SIZE - CHUNK_SIZE) as u64;

    assert_eq!(encrypted_len(0), 0);
    assert_eq!(encrypted_len(1), 1 + overhead);
    assert_eq!(
        encrypted_len(CHUNK_SIZE as u64),
        ENCRYPTED_CHUNK_SIZE as u64
    );
    assert_eq!(
        encrypted_len(CHUNK_SIZE as u64 + 10),
        ENCRYPTED_CHUNK_SIZE as u64 + 10 + overhead
    );
}

#[async_test]
async fn test_encrypt_stream_at_offset_records_the_length_of_each_chunk() {
    let dir = tempdir().unwrap();
    let encryptor = ChunkEncryptor::new(dir.path().join("lengths.enc"))
        .await
        .unwrap();
    let written_chunks = Mutex::new(BTreeMap::new());
    let mut data = Cursor::new(vec![b'A'; CHUNK_SIZE + 10]);

    let read = encryptor
        .encrypt_stream_at_offset(&mut data, 0, u64::MAX, &written_chunks)
        .await
        .unwrap();

    assert_eq!(read, CHUNK_SIZE as u64 + 10);
    assert_eq!(
        *written_chunks.lock().await,
        BTreeMap::from([(0, CHUNK_SIZE as u32), (1, 10)])
    );

    // Re-writing a chunk replaces its recorded length.
    let mut shorter = Cursor::new(vec![b'B'; 3]);
    encryptor
        .encrypt_stream_at_offset(&mut shorter, CHUNK_SIZE as u64, u64::MAX, &written_chunks)
        .await
        .unwrap();

    assert_eq!(written_chunks.lock().await.get(&1), Some(&3));
}

#[async_test]
async fn test_encrypt_stream_at_offset_stops_before_exceeding_the_limit() {
    let dir = tempdir().unwrap();
    let encryptor = ChunkEncryptor::new(dir.path().join("limit.enc"))
        .await
        .unwrap();
    let written_chunks = Mutex::new(BTreeMap::new());
    let mut data = Cursor::new(vec![b'A'; CHUNK_SIZE + 1]);

    let result = encryptor
        .encrypt_stream_at_offset(&mut data, 0, CHUNK_SIZE as u64, &written_chunks)
        .await;

    assert!(matches!(result, Err(EncryptionError::TooLarge)));
    // The chunk that fit was written; the one that crossed the limit was not.
    assert_eq!(
        *written_chunks.lock().await,
        BTreeMap::from([(0, CHUNK_SIZE as u32)])
    );

    let mut exact = Cursor::new(vec![b'A'; CHUNK_SIZE]);
    let result = encryptor
        .encrypt_stream_at_offset(&mut exact, 0, CHUNK_SIZE as u64, &written_chunks)
        .await;

    assert_eq!(result.unwrap(), CHUNK_SIZE as u64);
}

#[async_test]
async fn test_encrypt_stream_enforces_the_limit() {
    let dir = tempdir().unwrap();

    let mut encryptor = ChunkEncryptor::new(dir.path().join("under.enc"))
        .await
        .unwrap();
    let result = encryptor
        .encrypt_stream(&mut Cursor::new(vec![b'A'; 1000]), 1000)
        .await;
    assert_eq!(result.unwrap(), 1000);

    let mut encryptor = ChunkEncryptor::new(dir.path().join("over.enc"))
        .await
        .unwrap();
    let result = encryptor
        .encrypt_stream(&mut Cursor::new(vec![b'A'; 1001]), 1000)
        .await;
    assert!(matches!(result, Err(EncryptionError::TooLarge)));
}

#[async_test]
async fn test_seal_truncates_the_file_to_the_exact_encrypted_length() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("seal.enc");
    let mut encryptor = ChunkEncryptor::new(file_path.clone()).await.unwrap();
    let written_chunks = Mutex::new(BTreeMap::new());

    encryptor
        .encrypt_stream_at_offset(
            &mut Cursor::new(vec![b'A'; 2 * CHUNK_SIZE]),
            0,
            u64::MAX,
            &written_chunks,
        )
        .await
        .unwrap();
    // A shorter retry of the last chunk leaves the old tail on disk...
    encryptor
        .encrypt_stream_at_offset(
            &mut Cursor::new(vec![b'B'; 10]),
            CHUNK_SIZE as u64,
            u64::MAX,
            &written_chunks,
        )
        .await
        .unwrap();

    // ...which sealing removes.
    encryptor.seal(CHUNK_SIZE as u64 + 10).await.unwrap();

    assert_eq!(encryptor.get_metadata().total_size, CHUNK_SIZE as u64 + 10);
    assert_eq!(
        fs::metadata(&file_path).await.unwrap().len(),
        encrypted_len(CHUNK_SIZE as u64 + 10)
    );
}

// A source that yields `good` bytes and then fails.
struct FailingReader {
    good: std::io::Cursor<Vec<u8>>,
}

impl rocket::tokio::io::AsyncRead for FailingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut rocket::tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.good.position() < self.good.get_ref().len() as u64 {
            return std::pin::Pin::new(&mut self.good).poll_read(cx, buf);
        }

        std::task::Poll::Ready(Err(std::io::Error::other("source failed midway")))
    }
}

fn files_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();

    names
}

#[async_test]
async fn test_failed_atomic_write_leaves_nothing_behind() {
    let dir = tempdir().unwrap();
    let final_path = dir.path().join("thumb");
    let mut source = FailingReader {
        good: std::io::Cursor::new(vec![b'A'; CHUNK_SIZE + 10]),
    };

    let result =
        write_encrypted_atomically(&final_path, FileEncryptionMetadata::new(), &mut source).await;

    assert!(result.is_err());
    assert_eq!(files_in(dir.path()), Vec::<String>::new());
}

#[async_test]
async fn test_failed_atomic_write_keeps_the_existing_file() {
    let dir = tempdir().unwrap();
    let final_path = dir.path().join("thumb");
    std::fs::write(&final_path, b"previous").unwrap();
    let mut source = FailingReader {
        good: std::io::Cursor::new(vec![b'A'; 10]),
    };

    let result =
        write_encrypted_atomically(&final_path, FileEncryptionMetadata::new(), &mut source).await;

    assert!(result.is_err());
    assert_eq!(files_in(dir.path()), ["thumb"]);
    assert_eq!(std::fs::read(&final_path).unwrap(), b"previous");
}

#[async_test]
async fn test_atomic_write_replaces_the_file_with_a_complete_one() {
    let dir = tempdir().unwrap();
    let final_path = dir.path().join("thumb");
    std::fs::write(&final_path, b"previous").unwrap();
    let metadata = FileEncryptionMetadata::new();
    let plaintext = vec![b'Z'; CHUNK_SIZE + 10];

    write_encrypted_atomically(
        &final_path,
        metadata.clone(),
        &mut Cursor::new(plaintext.clone()),
    )
    .await
    .unwrap();

    assert_eq!(files_in(dir.path()), ["thumb"]);

    let decrypted = ChunkDecryptor::new(final_path, metadata)
        .await
        .unwrap()
        .decrypt_all()
        .await
        .unwrap();

    assert_eq!(decrypted, plaintext);
}
