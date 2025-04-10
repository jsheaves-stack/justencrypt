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
        let cookies = request.cookies();

        // Extract the state.
        let state: &State<AppState> = match request.guard::<&State<AppState>>().await {
            Outcome::Success(s) => s,
            Outcome::Error(e) => return Outcome::Error((e.0, RequestError::MissingActiveSession)),
            Outcome::Forward(f) => return Outcome::Forward(f),
        };

        let cookie = match cookies.get_private("session_id") {
            Some(cookie) => cookie,
            None => return Outcome::Error((Status::Unauthorized, RequestError::MissingSessionId)),
        };

        let active_sessions = state.active_sessions.read().await;
        let session = match active_sessions.get(cookie.value()) {
            Some(s) => s.clone(),
            None => {
                return Outcome::Error((Status::Unauthorized, RequestError::MissingActiveSession))
            }
        };

        Outcome::Success(AuthenticatedSession { session })
    }
}
