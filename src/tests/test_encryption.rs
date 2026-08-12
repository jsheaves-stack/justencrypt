use std::{collections::HashSet, io::Cursor};

use rocket::{async_test, tokio::fs};
use tempfile::tempdir;

use crate::encryption::{chunk_encryptor::ChunkEncryptor, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE};

#[async_test]
async fn test_encrypt_stream_at_offset() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_encrypt_offset.enc");
    let mut encryptor = ChunkEncryptor::new(file_path.clone()).await.unwrap();

    let mut written_chunks = HashSet::new();
    let mut data = Cursor::new(vec![b'A'; CHUNK_SIZE]);

    // Encrypt at offset 0
    encryptor
        .encrypt_stream_at_offset(&mut data, 0, &mut written_chunks)
        .await
        .unwrap();
    assert!(written_chunks.contains(&0));

    // Encrypt at offset CHUNK_SIZE
    let mut data2 = Cursor::new(vec![b'B'; CHUNK_SIZE]);
    encryptor
        .encrypt_stream_at_offset(&mut data2, CHUNK_SIZE as u64, &mut written_chunks)
        .await
        .unwrap();
    assert!(written_chunks.contains(&1));

    drop(encryptor);

    // Verify file size
    let metadata = fs::metadata(file_path).await.unwrap();
    assert_eq!(metadata.len(), (ENCRYPTED_CHUNK_SIZE * 2) as u64);
}

#[async_test]
async fn test_encrypt_stream_at_invalid_offset() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_invalid_offset.enc");
    let mut encryptor = ChunkEncryptor::new(file_path).await.unwrap();

    let mut written_chunks = HashSet::new();
    let mut data = Cursor::new(vec![b'A'; 100]);

    // Offset not a multiple of CHUNK_SIZE
    let result = encryptor
        .encrypt_stream_at_offset(&mut data, 100, &mut written_chunks)
        .await;
    assert!(result.is_err());
}
