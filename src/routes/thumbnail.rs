use rocket::{get, http::ContentType, options, State};

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::{
        thumbnails::{get_or_create_thumbnail, image_format_for},
        unrestricted_path::UnrestrictedPath,
    },
    web::forwarding_guards::AuthenticatedSession,
    AppState,
};

/// Answers the CORS preflight for `/thumbnail/<file_path..>`.
#[options("/<_file_path..>")]
pub fn thumbnail_options(_file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

/// A small preview of the image at `file_path`: from the user's encrypted
/// cache if it is there, otherwise generated and cached.
#[get("/<file_path..>")]
pub async fn get_thumbnail(
    file_path: UnrestrictedPath,
    state: &State<AppState>,
    auth: AuthenticatedSession,
) -> Result<(ContentType, Vec<u8>), RequestError> {
    let file_path_buf = file_path.to_path_buf();
    let format = image_format_for(&file_path_buf).ok_or(RequestError::UnsupportedFileType)?;

    get_or_create_thumbnail(
        &auth.session,
        file_path_buf,
        format,
        &state.config.thumbnail,
        &state.thumbnail_semaphore,
    )
    .await
}
