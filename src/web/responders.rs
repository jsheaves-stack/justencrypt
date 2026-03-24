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
        let response = match self {
            RequestError::MissingSessionId => Response::build()
                .status(Status::Unauthorized)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::MissingActiveSession => Response::build()
                .status(Status::Unauthorized)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToProcessData => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToWriteData => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToCreateUserSession => Response::build()
                .status(Status::Unauthorized)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::UnsupportedFileType => Response::build()
                .status(Status::UnsupportedMediaType)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToRemoveFile => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToAddFile => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToCreateFolder => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToReadFolderContents => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::PasswordDoesNotMeetRequirements => Response::build()
                .status(Status::BadRequest)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToMoveFile => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToRenameFile => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::InvalidApiKey => Response::build()
                .status(Status::Unauthorized)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::NotFound => Response::build()
                .status(Status::NotFound)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::Unauthorized => Response::build()
                .status(Status::Unauthorized)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::BadRequest(_) => Response::build()
                .status(Status::BadRequest)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::RangeNotSatisfiable => Response::build()
                .status(Status::RangeNotSatisfiable)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::InternalServerError => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),
        };

        response
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
