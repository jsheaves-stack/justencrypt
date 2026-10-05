use rocket::serde::json::Json;
use serde::Serialize;

/// The body of `GET /`.
#[derive(Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// The server's name and version. Needs no session.
#[get("/")]
pub fn get_server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
