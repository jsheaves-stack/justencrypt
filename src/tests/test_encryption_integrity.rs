// A5: integrity and efficiency of the encryption module.

use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    sync::Arc,
    time::Duration,
};

use rocket::{
    async_test,
    tokio::{
        self,
        io::{duplex, AsyncWriteExt},
        sync::{mpsc, Mutex},
        time::timeout,
    },
};
use secrecy::SecretString;
use tempfile::tempdir;

use super::migrated_db;
use crate::{
    config::DbConfig,
    db::sqlite,
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor,
        sync_chunk_decryptor::SyncChunkDecryptReader, FileEncryptionMetadata, CHUNK_SIZE,
        ENCRYPTED_CHUNK_SIZE,
    },
    enums::{db_error::DbError, encryption_error::EncryptionError},
    session::user_context::UserContext,
    tests::storage_context,
};

// Plaintext whose every byte depends on its position, so a byte from the
// wrong place can't go unnoticed.
fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// Encrypts `data` into the encrypted file "file" of a user whose files live
// in `dir`, and returns the user's context, the file's path and its metadata.
async fn encrypted_file(
    dir: &std::path::Path,
    data: &[u8],
) -> (UserContext, std::path::PathBuf, FileEncryptionMetadata) {
    let context = storage_context(dir);
    let mut encryptor = ChunkEncryptor::new(context.create_upload("file").await.unwrap());

    encryptor
        .encrypt_stream(&mut Cursor::new(data.to_vec()), u64::MAX)
        .await
        .unwrap();
    encryptor.sync().await.unwrap();
    context.commit_upload("file").await.unwrap();

    let path = context.blob_path("file");

    (context, path, encryptor.get_metadata())
}

async fn decryptor(
    context: &UserContext,
    name: &str,
    metadata: FileEncryptionMetadata,
) -> ChunkDecryptor {
    ChunkDecryptor::new(context.open_blob(name).await.unwrap(), metadata).unwrap()
}

// Runs `decrypt_range` on the encrypted file `name` and collects what it sends.
async fn decrypt_range(
    context: &UserContext,
    name: &str,
    metadata: FileEncryptionMetadata,
    start: u64,
    end: u64,
) -> (Result<(), EncryptionError>, Vec<u8>) {
    let mut decryptor = decryptor(context, name, metadata).await;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2);
    let receive = async {
        let mut received = Vec::new();

        while let Some(chunk) = rx.recv().await {
            received.extend_from_slice(&chunk);
        }

        received
    };

    tokio::join!(
        decryptor.decrypt_range(start, end, tx, Duration::from_secs(60)),
        receive
    )
}

#[async_test]
async fn test_decrypt_range_returns_exactly_the_requested_bytes() {
    let dir = tempdir().unwrap();
    let data = plaintext(3 * CHUNK_SIZE + 100);
    let (context, _, metadata) = encrypted_file(dir.path(), &data).await;
    let last = data.len() as u64 - 1;
    let chunk = CHUNK_SIZE as u64;

    for (start, end) in [
        (0, last),
        (0, 0),
        (5, 10),
        (chunk - 1, chunk),
        (chunk, 2 * chunk - 1),
        (10, 2 * chunk + 10),
        (3 * chunk, last),
        (last, last),
    ] {
        let (result, received) =
            decrypt_range(&context, "file", metadata.clone(), start, end).await;

        result.unwrap();
        assert_eq!(
            received,
            &data[start as usize..=end as usize],
            "{start}-{end}"
        );
    }
}

// A file that ends early at a chunk boundary used to be streamed short with
// `Ok(())` and nothing logged.
#[async_test]
async fn test_decrypt_range_reports_a_truncated_file() {
    let dir = tempdir().unwrap();
    let data = plaintext(3 * CHUNK_SIZE);
    let (context, path, metadata) = encrypted_file(dir.path(), &data).await;

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(2 * ENCRYPTED_CHUNK_SIZE as u64)
        .unwrap();

    let (result, received) =
        decrypt_range(&context, "file", metadata, 0, data.len() as u64 - 1).await;

    assert!(
        matches!(
            result,
            Err(EncryptionError::Truncated { expected, got })
                if expected == data.len() as u64 && got == 2 * CHUNK_SIZE as u64
        ),
        "{result:?}"
    );
    assert_eq!(received, &data[..2 * CHUNK_SIZE]);
}

// A client that goes away mid-download is not an error.
#[async_test]
async fn test_decrypt_range_stops_quietly_when_the_receiver_is_gone() {
    let dir = tempdir().unwrap();
    let data = plaintext(4 * CHUNK_SIZE);
    let (context, _, metadata) = encrypted_file(dir.path(), &data).await;
    let mut decryptor = decryptor(&context, "file", metadata).await;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(2);

    drop(rx);

    decryptor
        .decrypt_range(0, data.len() as u64 - 1, tx, Duration::from_secs(60))
        .await
        .unwrap();
}

// A client that stays connected but stops reading would otherwise keep the
// download, its open file and its key around forever.
#[async_test]
async fn test_decrypt_range_gives_up_when_the_receiver_stops_reading() {
    let dir = tempdir().unwrap();
    let data = plaintext(4 * CHUNK_SIZE);
    let (context, _, metadata) = encrypted_file(dir.path(), &data).await;
    let mut decryptor = decryptor(&context, "file", metadata).await;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2);
    let stall_timeout = Duration::from_millis(50);

    let result = decryptor
        .decrypt_range(0, data.len() as u64 - 1, tx, stall_timeout)
        .await;

    assert!(
        matches!(result, Err(EncryptionError::Stalled(d)) if d == stall_timeout),
        "{result:?}"
    );

    // The channel filled up, then nothing more was sent.
    let mut received = Vec::new();

    while let Some(chunk) = rx.recv().await {
        received.extend_from_slice(&chunk);
    }

    assert_eq!(received, &data[..2 * CHUNK_SIZE]);
}

#[test]
fn test_sync_reader_reads_the_whole_file() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempdir().unwrap();
    let data = plaintext(2 * CHUNK_SIZE + 7);
    let (_context, path, metadata) = rt.block_on(encrypted_file(dir.path(), &data));
    let mut reader =
        SyncChunkDecryptReader::new(std::fs::File::open(path).unwrap(), metadata).unwrap();
    let mut read = Vec::new();

    reader.read_to_end(&mut read).unwrap();

    assert_eq!(read, data);
}

// The stored format version used to be ignored.
#[async_test]
async fn test_unknown_encryption_versions_are_rejected() {
    let dir = tempdir().unwrap();
    let (context, path, metadata) = encrypted_file(dir.path(), &plaintext(10)).await;
    let future = FileEncryptionMetadata {
        encryption_version: 2,
        ..metadata
    };

    assert!(matches!(
        ChunkDecryptor::new(context.open_blob("file").await.unwrap(), future.clone()),
        Err(EncryptionError::UnsupportedVersion(2))
    ));
    assert!(matches!(
        ChunkEncryptor::new_with_metadata(
            context.create_upload("new").await.unwrap(),
            future.clone()
        ),
        Err(EncryptionError::UnsupportedVersion(2))
    ));

    let error = SyncChunkDecryptReader::new(std::fs::File::open(path).unwrap(), future)
        .err()
        .unwrap();
    assert!(error.to_string().contains("version 2"), "{error}");
}

// A key of the wrong length used to panic inside the query (an empty one) or
// to fail only later, at decryption (any other length).
#[test]
fn test_corrupt_key_blob_is_an_error_not_a_panic() {
    let db = migrated_db();

    db.execute(
        "INSERT INTO files (parent_folder_id, name, encoded_name, key) VALUES (1, 'empty.txt', 'blob-1', x''), (1, 'short.txt', 'blob-2', x'0001')",
        [],
    )
    .unwrap();

    for name in ["empty.txt", "short.txt"] {
        let result = sqlite::get_file_decryption_data(&db, name);

        assert!(
            matches!(result, Err(DbError::FailedToGetFileFromDb(_))),
            "{name}: {:?}",
            result.map(|(blob, _)| blob)
        );
    }
}

// Cloning metadata shares the key instead of copying the key material.
#[test]
fn test_metadata_clones_share_the_key() {
    let metadata = FileEncryptionMetadata::new();

    assert!(Arc::ptr_eq(&metadata.key, &metadata.clone().key));
}

#[test]
fn test_user_databases_use_secure_delete() {
    let dir = tempdir().unwrap();
    let pool = sqlite::create_user_db_connection(
        dir.path().join("user.db"),
        SecretString::from("pw".to_string()),
        &DbConfig::default(),
    )
    .unwrap();
    let secure_delete: i64 = pool
        .get()
        .unwrap()
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .unwrap();

    assert_eq!(secure_delete, 1);
}

// Chunk uploads used to hold the encryptor exclusively while reading their
// whole body, so a slow client stalled every other chunk of the upload.
#[async_test]
async fn test_chunks_of_one_upload_are_written_concurrently() {
    let dir = tempdir().unwrap();
    let context = storage_context(dir.path());
    let encryptor = ChunkEncryptor::new(context.create_upload("upload").await.unwrap());
    let written_chunks = Mutex::new(BTreeMap::new());
    let first = plaintext(CHUNK_SIZE);
    let second = vec![7u8; 10];

    // The first chunk's body arrives only after the second chunk is done.
    let (mut slow_client, mut slow_body) = duplex(1024);
    let slow_upload =
        encryptor.encrypt_stream_at_offset(&mut slow_body, 0, u64::MAX, &written_chunks);
    let fast_then_release = async {
        let fast = encryptor
            .encrypt_stream_at_offset(
                &mut Cursor::new(second.clone()),
                CHUNK_SIZE as u64,
                u64::MAX,
                &written_chunks,
            )
            .await;

        slow_client.write_all(&first).await.unwrap();
        drop(slow_client);

        fast
    };

    let (slow, fast) = timeout(Duration::from_secs(10), async {
        tokio::join!(slow_upload, fast_then_release)
    })
    .await
    .expect("the second chunk waited for the first chunk's body");

    assert_eq!(slow.unwrap(), CHUNK_SIZE as u64);
    assert_eq!(fast.unwrap(), 10);
    assert_eq!(
        *written_chunks.lock().await,
        BTreeMap::from([(0, CHUNK_SIZE as u32), (1, 10)])
    );

    let mut encryptor = encryptor;
    encryptor.seal(CHUNK_SIZE as u64 + 10).await.unwrap();
    context.commit_upload("upload").await.unwrap();

    let (result, received) = decrypt_range(
        &context,
        "upload",
        encryptor.get_metadata(),
        0,
        CHUNK_SIZE as u64 + 9,
    )
    .await;

    result.unwrap();
    assert_eq!(received, [first, second].concat());
}
