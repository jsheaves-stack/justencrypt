use std::sync::Arc;

use rocket::{
    http::Status, outcome::Outcome, request::FromRequest, tokio::sync::RwLock, Request, State,
};

use crate::{enums::request_error::RequestError, session::user_session::UserSession, AppState};

pub struct AuthenticatedSession {
    pub session: Arc<RwLock<UserSession>>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedSession {
    type Error = RequestError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<Self, (Status, Self::Error), Status> {
        trace!("Entering forwarding_guard::AuthenticatedSession::from_request");
        let cookies = request.cookies();

        // Extract the state.
        let state: &State<AppState> = match request.guard::<&State<AppState>>().await {
            Outcome::Success(s) => {
                trace!("Successfully retrieved AppState.");
                s
            }
            Outcome::Error(e) => {
                trace!("Failed to retrieve AppState.");
                return Outcome::Error((e.0, RequestError::MissingActiveSession));
            }
            Outcome::Forward(f) => {
                trace!("Forwarding request from AppState guard.");
                return Outcome::Forward(f);
            }
        };

        let cookie = match cookies.get_private("session_id") {
            Some(cookie) => {
                trace!("Found private session_id cookie.");
                cookie
            }
            None => {
                trace!("Private session_id cookie not found.");
                return Outcome::Error((Status::Unauthorized, RequestError::MissingSessionId));
            }
        };

        let active_sessions = state.active_sessions.read().await;
        let session = match active_sessions.get(cookie.value()) {
            Some(s) => {
                trace!("Found active session for cookie value.");
                s.clone()
            }
            None => {
                trace!("No active session found for cookie value.");
                return Outcome::Error((Status::Unauthorized, RequestError::MissingActiveSession));
            }
        };

        trace!("Exiting forwarding_guard::AuthenticatedSession::from_request successfully.");

        Outcome::Success(AuthenticatedSession { session })
    }
}
