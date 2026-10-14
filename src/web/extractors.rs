use std::{convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRequest, FromRequestParts, Path, Query},
    http::{request::Parts, HeaderMap},
    Json,
};
use axum_extra::extract::PrivateCookieJar;

use crate::{
    enums::service_error::ServiceError,
    service::{admin, auth, files::ByteRangeSpec},
    session::user_session::UserSession,
    web::{cookies::SESSION_COOKIE, problem::Problem, range::parse_range, state::WebState},
};

/// The session of the request's `sid` cookie. A request without a live
/// session is refused with `401`.
pub struct AuthenticatedSession {
    pub session: Arc<UserSession>,
}

/// The request's `Range` header, if any.
pub struct RangeHeader(pub Option<String>);

/// Proof that the request carries the admin API key in `X-Admin-Api-Key`. Other
/// requests are refused with `401`.
pub struct AdminGuard;

/// A JSON request body. The request must say it is JSON
/// (`Content-Type: application/json`), or it is refused with `415`.
#[derive(FromRequest)]
#[from_request(via(Json), rejection(Problem))]
pub struct JsonBody<T>(pub T);

/// A parameter from the URL, such as an upload id. One that doesn't decode or
/// parse is refused with `400`.
#[derive(FromRequestParts)]
#[from_request(via(Path), rejection(Problem))]
pub struct PathParam<T>(pub T);

/// The query string's parameters. Missing or unparsable ones are refused with
/// `422`.
#[derive(FromRequestParts)]
#[from_request(via(Query), rejection(Problem))]
pub struct QueryParams<T>(pub T);

impl RangeHeader {
    /// The byte range the header asks for; `None` for the whole file.
    pub fn parse(&self) -> Result<Option<ByteRangeSpec>, ServiceError> {
        match &self.0 {
            Some(header) => parse_range(header),
            None => Ok(None),
        }
    }
}

/// The first value of the header `name`, if it is text. Values that aren't
/// valid UTF-8 count as missing.
pub fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
}

impl FromRequestParts<WebState> for RangeHeader {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &WebState,
    ) -> Result<Self, Self::Rejection> {
        Ok(RangeHeader(
            header_text(&parts.headers, "Range").map(str::to_string),
        ))
    }
}

impl FromRequestParts<WebState> for AdminGuard {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &WebState,
    ) -> Result<Self, Self::Rejection> {
        admin::verify_api_key(&state.app, header_text(&parts.headers, "X-Admin-Api-Key"))?;

        Ok(AdminGuard)
    }
}

impl FromRequestParts<WebState> for AuthenticatedSession {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &WebState,
    ) -> Result<Self, Self::Rejection> {
        let jar = PrivateCookieJar::from_headers(&parts.headers, state.cookie_key.clone());

        let cookie = match jar.get(SESSION_COOKIE) {
            Some(cookie) => {
                trace!("Found private sid cookie.");

                cookie
            },
            None => {
                trace!("Private sid cookie not found.");

                return Err(ServiceError::MissingSessionId);
            },
        };

        let session = auth::authenticate(&state.app, cookie.value()).await?;

        Ok(AuthenticatedSession { session })
    }
}
