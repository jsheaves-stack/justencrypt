use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
};

use crate::{
    enums::service_error::ServiceError,
    service::thumbnails,
    web::{extractors::AuthenticatedSession, state::WebState, unrestricted_path::UnrestrictedPath},
};

/// Answers the CORS preflight for `/thumbnail/<file_path..>`.
pub async fn thumbnail_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// A small preview of the image at `file_path`: from the user's encrypted
/// cache if it is there, otherwise generated and cached.
pub async fn get_thumbnail(
    State(state): State<WebState>,
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<([(header::HeaderName, HeaderValue); 1], Vec<u8>), ServiceError> {
    let thumbnail = thumbnails::get(&state.app, &auth.session, file_path.to_path_buf()).await?;

    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(thumbnail.mime),
        )],
        thumbnail.bytes,
    ))
}
