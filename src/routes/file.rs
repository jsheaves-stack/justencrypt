use std::{io::SeekFrom, path::PathBuf};

use encryption::{
    get_encoded_file_name, StreamDecryptor, StreamEncryptor, BUFFER_SIZE, NONCE_SIZE, SALT_SIZE,
    TAG_SIZE,
};
use rocket::{
    data::ByteUnit,
    get,
    http::CookieJar,
    put,
    response::stream::ByteStream,
    tokio::{
        self,
        fs::File,
        io::{AsyncReadExt, AsyncSeekExt, BufReader},
        sync::mpsc,
    },
    Data, State,
};

use crate::AppState;

const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000)); // 50 Gigabyte

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: PathBuf, // The path where the file should be stored, extracted from the URL.
    reqdata: Data<'_>,  // The raw data of the file being uploaded.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> std::io::Result<()> {
    // Lock the active sessions map for write access.
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = cookies
        .get_private("session_id")
        .expect("Couldn't find a session id");

    let session = active_sessions
        .get_mut(cookie.value())
        .expect("Could not find an active session for this session id");

    // Process the file path to separate it into components.
    let mut components = file_path
        .iter()
        .filter_map(|s| s.to_str())
        .map(String::from)
        .collect::<Vec<String>>();

    // Extract the file name from the path and prepare the user's directory path.
    let file_name = components.pop().unwrap();
    let user_path = session.user_path.clone();

    // Insert the file path into the user's manifest and update the manifest.
    session.manifest.files.insert_path(
        components.into_iter(),
        file_name.clone(),
        get_encoded_file_name(&user_path.join(&file_path)).unwrap(),
    );

    session.update_manifest().await.unwrap();

    // Create a channel for transferring file data chunks with a specified buffer size.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE);

    // Clone the passphrase for use in the spawned encryption task.
    let passphrase = session.passphrase.clone();

    // Spawn an async task to handle file encryption and writing.
    tokio::spawn(async move {
        // Initialize the stream encryptor for the file.
        let mut encryptor =
            StreamEncryptor::new(&user_path, &user_path.join(&file_path), &passphrase)
                .await
                .expect("Failed to create StreamEncryptor");

        // Write encryption metadata (salt and nonce) to the file.
        encryptor
            .write_salt_and_nonce()
            .await
            .expect("Failed to write salt and nonce");

        // Continuously read data chunks from the channel, encrypt, and write them.
        while let Some(data) = rx.recv().await {
            let encrypted_chunk = encryptor
                .encrypt_chunk(&data)
                .await
                .expect("Failed to encrypt chunk");

            encryptor
                .write_chunk(&encrypted_chunk)
                .await
                .expect("Failed to write encrypted chunk");
        }
    });

    // Buffer to store data chunks read from the request.
    let mut buffer = [0u8; BUFFER_SIZE];
    // Open the request data stream with a limit.
    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));
    let mut current_size = 0;

    loop {
        // Read a chunk of data from the stream.
        let chunk_size = data_stream.read(&mut buffer[current_size..]).await?;

        // Break the loop if no more data is available.
        if chunk_size == 0 {
            if current_size == 0 {
                break;
            }
            // Send the last chunk of data if not empty.
            tx.send(buffer[..current_size].to_vec()).await.unwrap();
            break;
        }

        current_size += chunk_size;

        // If the buffer is full, send it through the channel and reset the current size.
        if current_size >= BUFFER_SIZE {
            tx.send(buffer[..BUFFER_SIZE].to_vec()).await.unwrap();
            current_size = current_size - BUFFER_SIZE;
        }
    }

    Ok(())
}

#[get("/<file_name..>")]
pub async fn get_file(
    file_name: PathBuf, // The name/path of the file being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> ByteStream![Vec<u8>] {
    // Read access to the active sessions map.
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = cookies
        .get_private("session_id")
        .expect("Couldn't find a session id");

    let session = active_sessions
        .get(cookie.value())
        .expect("Could not find an active session for this session id");

    // Construct the full path to the requested file.
    let file_path = PathBuf::from(&session.user_path).join(&file_name);

    // Initialize the stream decryptor for the requested file.
    let mut decryptor = StreamDecryptor::new(&session.user_path, &file_path, &session.passphrase)
        .await
        .expect("Failed to create StreamDecryptor");

    // Open the encrypted file.
    let input_file = File::open(decryptor.file_path.clone())
        .await
        .expect("Failed to open file");

    let mut reader = BufReader::new(input_file);

    // Skip the encryption metadata (salt and nonce) at the beginning of the file.
    reader
        .seek(SeekFrom::Start(
            (SALT_SIZE + NONCE_SIZE).try_into().unwrap(),
        ))
        .await
        .expect("Failed to seek in file");

    // Create an unbounded channel for streaming decrypted file chunks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE + TAG_SIZE);

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        let mut buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        // Loop to read and decrypt the file in chunks.
        loop {
            let chunk_size = reader.read(&mut buffer).await.expect("Failed to read file");

            // Break the loop if end of file is reached.
            if chunk_size == 0 {
                break;
            }

            // Decrypt the current chunk.
            let decrypted_chunk = decryptor
                .decrypt_chunk(&buffer[..chunk_size])
                .await
                .expect("Failed to decrypt chunk");

            // Break the loop if the decrypted chunk is empty.
            if decrypted_chunk.len() == 0 {
                break;
            }

            // Send the decrypted chunk for streaming.
            tx.send(decrypted_chunk)
                .await
                .expect("Failed to send chunk");
        }
    });

    // Stream the decrypted file chunks as they become available.
    ByteStream! {
        while let Some(chunk) = rx.recv().await {
            yield chunk;
        }
    }
}
