use rocket::{
    http::{Cookie, CookieJar, SameSite},
    serde::json::Json,
    State,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{AppSession, AppState};

#[derive(Deserialize)]
pub struct CreateSession {
    user_name: String,
    pass_phrase: String,
}

#[post("/create_session", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Option<String> {
    let session = AppSession::open(&reqbody.user_name, &reqbody.pass_phrase).await;

    match session {
        Ok(v) => {
            let uuid = Uuid::new_v4().to_hyphenated().to_string();

            let mut cookie = Cookie::new("session_id", uuid.clone());

            cookie.set_same_site(Some(SameSite::Strict));

            cookies.add_private(cookie);

            let mut active_sessions = state.active_sessions.write().await;

            active_sessions.insert(uuid, *v);

            Some("Success".to_string())
        }
        Err(e) => Some(e),
    }
}

#[post("/destroy_session")]
pub async fn destroy_session(state: &State<AppState>, cookies: &CookieJar<'_>) -> Option<String> {
    let mut active_sessions = state.active_sessions.write().await;

    let _ = match cookies.get_private("session_id") {
        Some(cookie) => match active_sessions.remove(cookie.value()) {
            Some(_) => (),
            None => panic!(),
        },
        None => panic!(),
    };

    Some(String::new())
}
