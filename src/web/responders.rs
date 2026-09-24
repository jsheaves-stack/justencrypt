use std::io::Cursor;

use rocket::{
    http::{Header, Status},
    response::{self, stream::ByteStream, Responder, Response, Result},
    tokio::sync::mpsc,
    Request,
};

use crate::enums::{request_error::RequestError, request_success::RequestSuccess};

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

        // An empty file has no byte range at all: `start` and `end` are both 0
        // but there is nothing to send.
        let content_length = if self.total_size == 0 {
            0
        } else {
            self.end - self.start + 1
        };

        let mut response = Response::build_from(stream.respond_to(req)?);
        response.status(self.status);
        response.header(Header::new("Accept-Ranges", "bytes"));
        response.header(Header::new("Content-Length", content_length.to_string()));

        if self.status == Status::PartialContent {
            response.header(Header::new(
                "Content-Range",
                format!("bytes {}-{}/{}", self.start, self.end, self.total_size),
            ));
        }

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
            },
            RequestError::NotFound => Status::NotFound,
            RequestError::RangeNotSatisfiable { .. } => Status::RangeNotSatisfiable,
            RequestError::TooManyActiveUploads => Status::TooManyRequests,
            RequestError::PayloadTooLarge => Status::PayloadTooLarge,
            RequestError::AccountAlreadyExists | RequestError::Conflict(_) => Status::Conflict,
        };

        let message = self.to_string();
        let mut response = Response::build();
        response
            .status(status)
            .sized_body(message.len(), Cursor::new(message));

        if let RequestError::RangeNotSatisfiable { total_size } = self {
            response.header(Header::new(
                "Content-Range",
                format!("bytes */{}", total_size),
            ));
        }

        response.ok()
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
