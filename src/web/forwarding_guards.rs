use std::{env, sync::Arc};

use rocket::{async_trait, http::Status, outcome::Outcome, request::FromRequest, Request, State};

use crate::{enums::request_error::RequestError, session::user_session::UserSession, AppState};

pub struct AuthenticatedSession {
    pub session: Arc<UserSession>,
}

pub struct RangeHeader(pub Option<String>);

#[async_trait]
impl<'r> FromRequest<'r> for RangeHeader {
    type Error = RequestError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<Self, (Status, Self::Error), Status> {
        Outcome::Success(RangeHeader(
            request.headers().get_one("Range").map(|s| s.to_string()),
        ))
    }
}

pub struct AdminGuard;

#[async_trait]
impl<'r> FromRequest<'r> for AdminGuard {
    type Error = RequestError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<Self, (Status, Self::Error), Status> {
        trace!("Entering forwarding_guard::AdminGuard::from_request");

        let api_key = match env::var("JUSTENCRYPT_ADMIN_API_KEY") {
            Ok(key) => key,
            Err(_) => {
                return Outcome::Error((Status::InternalServerError, RequestError::InvalidApiKey))
            },
        };

        match request.headers().get_one("X-Admin-Api-Key") {
            Some(key) if key == api_key => Outcome::Success(AdminGuard),
            _ => Outcome::Error((Status::Unauthorized, RequestError::InvalidApiKey)),
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for AuthenticatedSession {
    type Error = RequestError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<Self, (Status, Self::Error), Status> {
        trace!("Entering forwarding_guard::AuthenticatedSession::from_request");

        let cookies = request.cookies();

        let state: &State<AppState> = match request.guard::<&State<AppState>>().await {
            Outcome::Success(s) => {
                trace!("Successfully retrieved AppState.");

                s
            },
            Outcome::Error(e) => {
                trace!("Failed to retrieve AppState.");

                return Outcome::Error((e.0, RequestError::MissingActiveSession));
            },
            Outcome::Forward(f) => {
                trace!("Forwarding request from AppState guard.");

                return Outcome::Forward(f);
            },
        };

        let cookie = match cookies.get_private("sid") {
            Some(cookie) => {
                trace!("Found private sid cookie.");

                cookie
            },
            None => {
                trace!("Private sid cookie not found.");

                return Outcome::Error((Status::Unauthorized, RequestError::MissingSessionId));
            },
        };

        let user_token = cookie.value();

        let session = match state.sessions.get(user_token).await {
            Some(s) => {
                trace!("Found active session for token.");

                s
            },
            None => {
                trace!("No active session found for token.");

                return Outcome::Error((Status::Unauthorized, RequestError::MissingActiveSession));
            },
        };

        trace!("Exiting forwarding_guard::AuthenticatedSession::from_request successfully.");

        Outcome::Success(AuthenticatedSession { session })
    }
}
