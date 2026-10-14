use std::convert::Infallible;

use axum::{
    body::{Body, Bytes},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{service::files::FileDownload, util::folder_archive::FolderArchive};

/// A file download, with the matching `Content-Length` and, for a range,
/// `206` and `Content-Range`.
pub struct FileResponse(pub FileDownload);

/// A folder download: a TAR archive, offered to the browser as a file to save.
pub struct ArchiveResponse(pub FolderArchive);

/// A body that streams the chunks arriving on `rx`.
fn stream_body(rx: mpsc::Receiver<Vec<u8>>) -> Body {
    Body::from_stream(ReceiverStream::new(rx).map(|chunk| Ok::<_, Infallible>(Bytes::from(chunk))))
}

impl IntoResponse for FileResponse {
    fn into_response(self) -> Response {
        let FileDownload {
            chunks,
            start,
            end,
            total_size,
            partial,
        } = self.0;

        // An empty file has no byte range at all: `start` and `end` are both 0
        // but there is nothing to send.
        let content_length = if total_size == 0 { 0 } else { end - start + 1 };

        let mut response = Response::new(stream_body(chunks));
        let headers = response.headers_mut();

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(content_length));

        if partial {
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;

            if let Ok(value) =
                HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size))
            {
                response.headers_mut().insert(header::CONTENT_RANGE, value);
            }
        }

        response
    }
}

impl IntoResponse for ArchiveResponse {
    fn into_response(self) -> Response {
        let FolderArchive { rx, len, file_name } = self.0;

        let mut response = Response::new(stream_body(rx));
        let headers = response.headers_mut();

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));

        if let Ok(value) = HeaderValue::from_str(&attachment_disposition(&file_name)) {
            headers.insert(header::CONTENT_DISPOSITION, value);
        }

        response
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
