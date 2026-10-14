use axum::{body::Body, extract::State, http::StatusCode, Json};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use tokio_util::io::StreamReader;

use crate::{
    enums::service_error::ServiceError,
    service::uploads,
    web::{
        extractors::{AuthenticatedSession, PathParam, QueryParams},
        state::WebState,
        unrestricted_path::UnrestrictedPath,
    },
};

/// The body of a successful `POST /upload/initiate`.
#[derive(Serialize, Deserialize)]
pub struct InitUploadResponse {
    pub upload_id: String,
}

/// The query of `PUT /upload/chunk`.
#[derive(Deserialize)]
pub struct ChunkQuery {
    pub offset: u64,
}

/// The query of `POST /upload/finalize`.
#[derive(Deserialize)]
pub struct FinalizeQuery {
    pub total_size: u64,
}

/// Answers the CORS preflight for the `/upload` routes.
pub async fn upload_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Starts a chunked upload to `file_path` and returns its id. The chunks
/// can then be sent in any order, and in parallel, before the upload is
/// finalized.
pub async fn init_upload(
    State(state): State<WebState>,
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<Json<InitUploadResponse>, ServiceError> {
    let upload_id = uploads::initiate(&state.app, &auth.session, file_path.to_path_buf()).await?;

    Ok(Json(InitUploadResponse { upload_id }))
}

/// Encrypts and stores one chunk of an upload. `offset` is where the chunk
/// starts in the file, and must be a multiple of the chunk size.
pub async fn upload_chunk(
    State(state): State<WebState>,
    PathParam(upload_id): PathParam<String>,
    auth: AuthenticatedSession,
    QueryParams(query): QueryParams<ChunkQuery>,
    body: Body,
) -> Result<StatusCode, ServiceError> {
    let body = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));

    uploads::write_chunk(&state.app, &auth.session, &upload_id, query.offset, body).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Completes a chunked upload once every chunk of its `total_size` bytes
/// has arrived, and stores the file, replacing any file already at its path.
/// A missing chunk is reported and the upload kept, so the client can send
/// it and try again.
pub async fn finalize_upload(
    State(state): State<WebState>,
    PathParam(upload_id): PathParam<String>,
    auth: AuthenticatedSession,
    QueryParams(query): QueryParams<FinalizeQuery>,
) -> Result<StatusCode, ServiceError> {
    uploads::finalize(&state.app, &auth.session, &upload_id, query.total_size).await?;

    Ok(StatusCode::CREATED)
}
