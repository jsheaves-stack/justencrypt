//! Error responses. Every error is reported as RFC 9457 Problem Details: a
//! JSON object with the status, its reason phrase as the `title`, and a
//! `detail` saying what went wrong.

use axum::{
    extract::rejection::{JsonRejection, PathRejection, QueryRejection},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::enums::service_error::ServiceError;

/// The media type of a Problem Details body.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// An error response: a status and what went wrong.
pub struct Problem {
    pub status: StatusCode,
    pub detail: Option<String>,
}

impl Problem {
    /// A problem with `status` and no detail beyond its reason phrase.
    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            detail: None,
        }
    }

    /// The JSON body for this problem.
    pub fn body(&self) -> String {
        let mut body = json!({
            "type": "about:blank",
            "title": self.status.canonical_reason().unwrap_or("Error"),
            "status": self.status.as_u16(),
        });

        if let Some(detail) = &self.detail {
            body["detail"] = json!(detail);
        }

        body.to_string()
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON))],
            self.body(),
        )
            .into_response()
    }
}

/// The status code each error is reported with.
pub fn status_of(error: &ServiceError) -> StatusCode {
    match error {
        ServiceError::MissingSessionId
        | ServiceError::MissingActiveSession
        | ServiceError::InvalidApiKey
        | ServiceError::InvalidCredentials => StatusCode::UNAUTHORIZED,

        ServiceError::FailedToProcessData | ServiceError::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        },

        ServiceError::UnsupportedFileType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ServiceError::ImageTooLarge => StatusCode::UNPROCESSABLE_ENTITY,
        ServiceError::PasswordDoesNotMeetRequirements | ServiceError::InvalidInput(_) => {
            StatusCode::BAD_REQUEST
        },
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::RangeNotSatisfiable { .. } => StatusCode::RANGE_NOT_SATISFIABLE,
        ServiceError::TooManyActiveUploads
        | ServiceError::TooManyActiveDownloads
        | ServiceError::Busy => StatusCode::TOO_MANY_REQUESTS,
        ServiceError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ServiceError::AccountAlreadyExists | ServiceError::Conflict(_) => StatusCode::CONFLICT,
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let problem = Problem {
            status: status_of(&self),
            detail: Some(self.to_string()),
        };
        let mut response = problem.into_response();

        if let ServiceError::RangeNotSatisfiable { total_size } = self {
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{}", total_size)) {
                response.headers_mut().insert(header::CONTENT_RANGE, value);
            }
        }

        response
    }
}

/// A JSON body that is missing, of the wrong type, malformed or too large.
impl From<JsonRejection> for Problem {
    fn from(rejection: JsonRejection) -> Self {
        Self {
            status: rejection.status(),
            detail: Some(rejection.body_text()),
        }
    }
}

/// A URL parameter that doesn't decode or parse, such as an upload id that
/// isn't valid UTF-8.
impl From<PathRejection> for Problem {
    fn from(rejection: PathRejection) -> Self {
        Self {
            status: rejection.status(),
            detail: Some(rejection.body_text()),
        }
    }
}

/// A query string without the parameters a route needs, or with ones that
/// don't parse. Reported as `422`.
impl From<QueryRejection> for Problem {
    fn from(rejection: QueryRejection) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            detail: Some(rejection.body_text()),
        }
    }
}
