use crate::enums::{request_error::RequestError, request_success::RequestSuccess};
use rocket::{
    http::{Header, Status},
    response::{self, stream::ByteStream, Responder, Response, Result},
    tokio::sync::mpsc,
    Request,
};
use std::io::Cursor;

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

impl<'r> Responder<'r, 'static> for RequestError {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        let status = match self {
            RequestError::MissingSessionId
            | RequestError::MissingActiveSession
            | RequestError::FailedToCreateUserSession
            | RequestError::InvalidApiKey
            | RequestError::Unauthorized => Status::Unauthorized,

            RequestError::FailedToProcessData
            | RequestError::FailedToWriteData
            | RequestError::FailedToRemoveFile
            | RequestError::FailedToAddFile
            | RequestError::FailedToCreateFolder
            | RequestError::FailedToReadFolderContents
            | RequestError::FailedToMoveFile
            | RequestError::FailedToRenameFile
            | RequestError::InternalServerError => Status::InternalServerError,

            RequestError::UnsupportedFileType => Status::UnsupportedMediaType,
            RequestError::PasswordDoesNotMeetRequirements | RequestError::BadRequest(_) => {
                Status::BadRequest
            }
            RequestError::NotFound => Status::NotFound,
            RequestError::RangeNotSatisfiable => Status::RangeNotSatisfiable,
            RequestError::TooManyActiveUploads => Status::TooManyRequests,
        };

        let message = self.to_string();
        Response::build()
            .status(status)
            .sized_body(message.len(), Cursor::new(message))
            .ok()
    }
}

impl<'r> Responder<'r, 'static> for RequestSuccess {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        let response = match self {
            RequestSuccess::Created => Response::build().status(Status::Created).ok(),
            RequestSuccess::NoContent => Response::build().status(Status::NoContent).ok(),
        };

        response
    }
}
