use crate::{
    encryption::{
        stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor,
        MPSC_CHANNEL_CAPACITY, STREAM_LIMIT,
    },
    enums::{db_error::DbError, request_error::RequestError, request_success::RequestSuccess},
    util::{
        sharded_path::{get_sharded_path, remove_sharded_path},
        unrestricted_path::UnrestrictedPath,
    },
    web::forwarding_guards::{AuthenticatedSession, RangeHeader},
};
use rocket::{
    data::ByteUnit,
    delete, get,
    http::{Header, Status},
    options, patch, put,
    response::{self, stream::ByteStream, Responder},
    serde::{json::Json, Deserialize},
    tokio::{self, sync::mpsc},
    Data, Request, Response,
};
use uuid::Uuid;

#[options("/<file_path..>")]
pub fn file_options(file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /file{}]", file_path);
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: UnrestrictedPath,
    reqdata: Data<'_>,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /file{}]", file_path);

    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;

    let mut encryptor = StreamEncryptor::new(encoded_file_path).await.map_err(|e| {
        error!("Failed to create StreamEncryptor: {}", e);
        RequestError::FailedToAddFile
    })?;

    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));

    let total_size = encryptor.encrypt_stream(&mut data_stream).await.map_err(|e| {
        error!("Encryption failed: {}", e);
        RequestError::FailedToAddFile
    })?;

    let mut metadata = encryptor.get_metadata();
    
    metadata.total_size = total_size;

    session
        .add_file(file_path.to_path_buf(), encoded_file_name, metadata)
        .await
        .map_err(|e| {
            error!("Failed to add file to db: {}", e);
            RequestError::FailedToAddFile
        })?;

    trace!("Exiting route [PUT /file{}] successfully.", file_path);
    Ok(RequestSuccess::Created)
}

#[derive(Deserialize)]
pub struct PatchFileRequest {
    parent_folder_path: Option<String>,
    file_name: Option<String>,
}

#[patch("/<file_path..>", data = "<patch_file_request>")]
pub async fn patch_file(
    file_path: UnrestrictedPath,
    patch_file_request: Json<PatchFileRequest>,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PATCH /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let updates = patch_file_request.into_inner();

    if let Some(parent_folder_path) = updates.parent_folder_path {
        session
            .move_file(file_path_buf.clone(), parent_folder_path)
            .await
            .map_err(|e| {
                error!("Failed to move file: {}", e);
                RequestError::FailedToMoveFile
            })?;
    };

    if let Some(new_file_name) = updates.file_name {
        session.rename_file(file_path_buf, new_file_name).await.map_err(|e| {
            error!("Failed to rename file: {}", e);
            RequestError::FailedToRenameFile
        })?;
    };

    trace!("Exiting route [PATCH /file{}] successfully.", file_path);
    Ok(RequestSuccess::NoContent)
}

pub struct RangeResponder {
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub status: Status,
    pub start: u64,
    pub end: u64,
    pub total_size: u64,
}

impl<'r> Responder<'r, 'r> for RangeResponder {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'r> {
        let mut rx = self.rx;
        let stream = ByteStream! {
            while let Some(chunk) = rx.recv().await {
                yield chunk;
            }
        };

        let mut response = Response::build_from(stream.respond_to(req)?);
        response.status(self.status);
        response.header(Header::new("Accept-Ranges", "bytes"));
        response.header(Header::new(
            "Content-Range",
            format!("bytes {}-{}/{}", self.start, self.end, self.total_size),
        ));
        response.header(Header::new(
            "Content-Length",
            (self.end - self.start + 1).to_string(),
        ));

        response.ok()
    }
}

fn parse_range(range_str: &str, total_size: u64) -> Result<(u64, u64, Status), RequestError> {
    if !range_str.starts_with("bytes=") {
        return Err(RequestError::BadRequest("Invalid Range header".into()));
    }
    let range_val = &range_str[6..];
    let parts: Vec<&str> = range_val.split('-').collect();
    if parts.len() != 2 {
        return Err(RequestError::BadRequest("Invalid Range format".into()));
    }

    let start = parts[0]
        .parse::<u64>()
        .map_err(|_| RequestError::BadRequest("Invalid range start".into()))?;
    let end = if parts[1].is_empty() {
        total_size.saturating_sub(1)
    } else {
        parts[1]
            .parse::<u64>()
            .map_err(|_| RequestError::BadRequest("Invalid range end".into()))?
    };

    if start > end || start >= total_size {
        return Err(RequestError::RangeNotSatisfiable);
    }
    Ok((start, end.min(total_size - 1), Status::PartialContent))
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    range: RangeHeader,
) -> Result<RangeResponder, RequestError> {
    trace!("Entering route [GET /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = session.get_encoded_file_name(file_path_buf.clone()).await.map_err(|e| {
        if let DbError::NotFound = e {
            RequestError::NotFound
        } else {
            error!("Failed to get encoded file name: {}", e);
            RequestError::FailedToProcessData
        }
    })?;

    let metadata = session.get_file_encryption_metadata(file_path_buf).await.map_err(|e| {
        if let DbError::NotFound = e {
            RequestError::NotFound
        } else {
            error!("Failed to get encryption metadata: {}", e);
            RequestError::FailedToProcessData
        }
    })?;
    drop(session);

    let total_size = metadata.total_size;
    let (start, end, status) = if let Some(range_str) = range.0 {
        parse_range(&range_str, total_size)?
    } else {
        (0, total_size.saturating_sub(1), Status::Ok)
    };

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;
    let mut decryptor = StreamDecryptor::new(encoded_file_path, metadata).await.map_err(|e| {
        error!("Failed to create StreamDecryptor: {}", e);
        RequestError::FailedToProcessData
    })?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        decryptor.decrypt_range(start, end, tx).await;
    });

    Ok(RangeResponder {
        rx,
        status,
        start,
        end,
        total_size,
    })
}

#[delete("/<file_path..>")]
pub async fn delete_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = session.get_encoded_file_name(file_path_buf.clone()).await.map_err(|e| {
        if let DbError::NotFound = e {
            RequestError::NotFound
        } else {
            error!("Failed to get encoded file name: {}", e);
            RequestError::FailedToProcessData
        }
    })?;

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

    session.delete_file(file_path_buf).await.map_err(|e| {
        error!("Failed to delete metadata: {}", e);
        RequestError::FailedToRemoveFile
    })?;

    remove_sharded_path(&user_path, &encoded_file_path).await.map_err(|e| {
        error!("Failed to delete physical file: {}", e);
        RequestError::FailedToRemoveFile
    })?;

    Ok(RequestSuccess::NoContent)
}
