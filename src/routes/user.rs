use rocket::{http::CookieJar, serde::json::Json, State};

use crate::{session::session::UserManifest, AppState};

#[get("/manifest")]
pub async fn get_user_manifest(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Option<Json<UserManifest>> {
    let active_sessions = state.active_sessions.read().await;

    let session = match cookies.get_private("session_id") {
        Some(cookie) => match active_sessions.get(cookie.value()) {
            Some(s) => s,
            None => panic!(),
        },
        None => panic!(),
    };

    Some(Json(session.manifest.clone()))
}
