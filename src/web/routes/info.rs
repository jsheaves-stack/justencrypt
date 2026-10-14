use axum::Json;
use serde::Serialize;

use crate::util::version::VERSION;

/// The body of `GET /`.
#[derive(Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// The server's name and version. Needs no session.
pub async fn get_server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: VERSION.to_string(),
    })
}
