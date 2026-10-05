use std::io::Cursor;

use rocket::{
    http::{ContentType, Header, Status},
    response::{self, stream::ByteStream, Responder, Response, Result},
    tokio::sync::mpsc,
    Request,
};

use crate::{
    encryption::CHUNK_SIZE,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::folder_archive::FolderArchive,
};

/// How much of a streamed body Rocket hands to the connection at once. Its
/// default of 4 KiB splits every chunk into 16 pieces, which halves download
/// speed over HTTP/2 and costs a third or more of the server's CPU time on a
/// download; a whole chunk at a time avoids both.
const MAX_BODY_CHUNK: usize = CHUNK_SIZE;

/// A file download: the decrypted bytes `start..=end` of a `total_size`-byte
/// file as they arrive on `rx`, with the matching `Content-Length` and, for a
/// range, `Content-Range`.
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
        response.max_chunk_size(MAX_BODY_CHUNK);
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

/// A folder download: a TAR archive, offered to the browser as a file to save.
pub struct ArchiveResponder(pub FolderArchive);

impl<'r> Responder<'r, 'r> for ArchiveResponder {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'r> {
        let FolderArchive {
            mut rx,
            len,
            file_name,
        } = self.0;
        let stream = ByteStream! {
            while let Some(chunk) = rx.recv().await {
                yield chunk;
            }
        };

        Response::build_from(stream.respond_to(req)?)
            .max_chunk_size(MAX_BODY_CHUNK)
            .header(ContentType::new("application", "x-tar"))
            .header(Header::new("Content-Length", len.to_string()))
            .header(Header::new(
                "Content-Disposition",
                attachment_disposition(&file_name),
            ))
            .ok()
    }
}

/// A `Content-Disposition` value naming the file to save. Clients that read
/// `filename*` get the exact UTF-8 name; others get `filename`, with every
/// character a quoted string can't safely hold replaced by `_`.
fn attachment_disposition(file_name: &str) -> String {
    let fallback: String = file_name
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let mut encoded = String::new();

    for byte in file_name.bytes() {
        if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }

    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

impl<'r> Responder<'r, 'static> for RequestError {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        let status = match self {
            RequestError::MissingSessionId
            | RequestError::MissingActiveSession
            | RequestError::InvalidApiKey
            | RequestError::Unauthorized => Status::Unauthorized,

            RequestError::FailedToProcessData | RequestError::InternalServerError => {
                Status::InternalServerError
            },

            RequestError::UnsupportedFileType => Status::UnsupportedMediaType,
            RequestError::ImageTooLarge => Status::UnprocessableEntity,
            RequestError::PasswordDoesNotMeetRequirements | RequestError::BadRequest(_) => {
                Status::BadRequest
            },
            RequestError::NotFound => Status::NotFound,
            RequestError::RangeNotSatisfiable { .. } => Status::RangeNotSatisfiable,
            RequestError::TooManyActiveUploads
            | RequestError::TooManyActiveDownloads
            | RequestError::Busy => Status::TooManyRequests,
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
