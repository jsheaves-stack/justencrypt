use crate::{enums::request_error::RequestError, AppState};
use encryption::{get_encoded_file_name, FileDecryptor, StreamDecryptor};
use image::ImageFormat;
use rocket::{
    get,
    http::{ContentType, CookieJar},
    response::stream::ByteStream,
    State,
};
use std::path::{Path, PathBuf};

#[get("/<file_path..>")]
pub async fn get_thumbnail(
    file_path: PathBuf, // The name/path of the file being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<(), RequestError> {
    // Read access to the active sessions map.
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => panic!(),
    };

    let session = match active_sessions.get(cookie.value()) {
        Some(s) => s,
        None => panic!(),
    };

    let user_path = session.user_path.clone();
    let passphrase = session.passphrase.clone();

    let encoded_thumbnail_file_name =
        get_encoded_file_name(&Path::new(".thumbnail").join(&file_path)).unwrap();

    let thumbnail_path: PathBuf = Path::new(&user_path)
        .join(".thumbnail")
        .join(&encoded_thumbnail_file_name);

    let thumbnail_extension = file_path.extension().unwrap();

    if !thumbnail_path.exists() {
        let encoded_file_name = get_encoded_file_name(&file_path).unwrap();

        let content_type =
            ContentType::from_extension(thumbnail_extension.to_str().unwrap()).unwrap();

        // Initialize the stream decryptor for the requested file.
        let mut decryptor =
            match StreamDecryptor::new(&session.user_path, &file_path, &session.passphrase).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to create StreamDecryptor: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

        let decrypted_file: Vec<u8> = Vec::new();

        let _img = match if content_type == ContentType::PNG {
            image::load_from_memory_with_format(&decrypted_file, ImageFormat::Png)
        } else if content_type == ContentType::JPEG {
            image::load_from_memory_with_format(&decrypted_file, ImageFormat::Jpeg)
        } else if content_type == ContentType::GIF {
            image::load_from_memory_with_format(&decrypted_file, ImageFormat::Gif)
        } else if content_type == ContentType::WEBP {
            image::load_from_memory_with_format(&decrypted_file, ImageFormat::WebP)
        } else {
            panic!();
        }
        .map_err(|e| {
            error!("Failed to process thumbnail file: {}", e);
        }) {
            Ok(i) => i,
            Err(_) => panic!(),
        };
    } else {
        let mut decryptor = FileDecryptor::new(&thumbnail_path, &passphrase)
            .await
            .unwrap();

        let decrypted_file = match decryptor.decrypt_file().await {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to decrypt thumbnail file: {}", e);
                panic!();
            }
        };
    }

    Ok(())
}
