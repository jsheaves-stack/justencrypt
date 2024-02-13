use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
};

use rocket::{
    data::ByteUnit,
    get,
    http::{CookieJar, Status},
    post,
    request::{self, FromRequest, Outcome},
    response::stream::ByteStream,
    tokio::{self, io::AsyncReadExt, sync::mpsc},
    Data, Request, State,
};

use encryption::{
    get_encoded_file_name, Decryptor, Encryptor, BUFFER_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

use crate::AppState;

const STREAM_LIMIT: usize = 10 * (1000 * (1000 * (1000))); // 10 Gigabytes

pub struct Passphrase(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Passphrase {
    type Error = std::io::Error;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match req.headers().get_one("X-Passphrase") {
            Some(passphrase) => Outcome::Success(Passphrase(passphrase.to_string())),
            None => Outcome::Error((
                Status::BadRequest,
                std::io::Error::new(std::io::ErrorKind::NotFound, "Passphrase header missing"),
            )),
        }
    }
}

#[post("/<file_name..>", data = "<data>")]
pub async fn upload(
    file_name: PathBuf,
    data: Data<'_>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> std::io::Result<()> {
    let mut active_sessions = state.active_sessions.write().await;

    let cookie = cookies.get_private("session_id").unwrap();
    let session = active_sessions.get_mut(cookie.value()).unwrap();

    session.manifest.files.insert(
        file_name.to_str().unwrap().to_string(),
        get_encoded_file_name(&file_name).unwrap(),
    );

    session.update_manifest().await.unwrap();

    // Create a channel
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE);

    let pass_phrase = session.pass_phrase.clone();
    let user_path = session.user_path.clone();

    // Spawn a separate thread for synchronous processing
    tokio::spawn(async move {
        let mut encryptor =
            match Encryptor::new(&user_path, &user_path.join(&file_name), &pass_phrase) {
                Ok(e) => e,
                Err(e) => panic!("{}", e),
            };

        match encryptor.write_salt_and_nonce() {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        };

        // Asynchronously receive and process data chunks
        while let Some(data) = rx.recv().await {
            let encrypted_chunk = match encryptor.encrypt_chunk(&data) {
                Ok(c) => c,
                Err(e) => panic!("{}", e),
            };

            match encryptor.write_chunk(&encrypted_chunk) {
                Ok(_) => (),
                Err(e) => panic!("{}", e),
            };
        }
    });

    let mut buffer = [0u8; BUFFER_SIZE];
    let mut data_stream = data.open(ByteUnit::from(STREAM_LIMIT));
    let mut current_size = 0;

    loop {
        let chunk_size = data_stream.read(&mut buffer[current_size..]).await?;

        if chunk_size == 0 {
            // End of the data stream, break if no data is left to process
            if current_size == 0 {
                break;
            }

            tx.send(buffer[..current_size].to_vec()).await.unwrap();
            break;
        }

        current_size += chunk_size;

        // If the buffer is full, send it and reset current_size
        if current_size >= BUFFER_SIZE {
            tx.send(buffer[..BUFFER_SIZE].to_vec()).await.unwrap();
            current_size = current_size - BUFFER_SIZE;
        }
    }

    Ok(())
}

#[get("/<file_name..>")]
pub async fn download(
    file_name: PathBuf,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> ByteStream![Vec<u8>] {
    let active_sessions = state.active_sessions.read().await;

    let session = match cookies.get_private("session_id") {
        Some(cookie) => match active_sessions.get(cookie.value()) {
            Some(t) => t,
            None => panic!(),
        },
        None => panic!(),
    };

    let file_path = PathBuf::from(&session.user_path).join(&file_name); // Adjust path as needed

    let mut decryptor = match Decryptor::new(&session.user_path, &file_path, &session.pass_phrase) {
        Ok(d) => d,
        Err(e) => panic!("{}", e),
    };

    let input_file = File::open(decryptor.file_path.clone()).unwrap();

    let mut reader = BufReader::new(input_file);

    reader
        .seek(SeekFrom::Start(
            (SALT_SIZE + NONCE_SIZE).try_into().unwrap(),
        ))
        .unwrap();

    // Prepare an unbounded channel for streaming chunks
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE + TAG_SIZE);

    // Spawn a separate thread to handle decryption and chunking
    tokio::spawn(async move {
        let mut buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        // Decrypt the file in chunks and send them
        loop {
            let chunk_size = reader.read(&mut buffer).unwrap();

            if chunk_size == 0 {
                break;
            }

            let decrypted_chunk = match decryptor.decrypt_chunk(&buffer[..chunk_size]) {
                Ok(c) => c,
                Err(e) => panic!("{}", e),
            };

            if decrypted_chunk.len() == 0 {
                break;
            }

            tx.send(decrypted_chunk).await.unwrap();
        }
    });

    ByteStream! {
        while let Some(chunk) = rx.recv().await {
            yield chunk;
        }
    }
}
