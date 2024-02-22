use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Header, Method, Status},
    launch, routes,
    tokio::sync::RwLock,
    Request, Response,
};
use routes::{
    session::{create_session, destroy_session},
    file::{download, upload},
    user::{create_user, get_user_manifest},
};
use session::session::AppSession;
use std::collections::HashMap;
mod routes;
mod session;

#[macro_use]
extern crate rocket;
extern crate serde;

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let figment = request.rocket().figment();
        let domain: String = figment
            .extract_inner("domain")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let methods = "POST, GET, PATCH, OPTIONS";

        response.set_header(Header::new("Allow", methods));
        response.set_header(Header::new("Access-Control-Allow-Origin", domain));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
        response.set_header(Header::new("Access-Control-Allow-Methods", methods));
        response.set_header(Header::new("Access-Control-Request-Methods", methods));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

        if request.method() == Method::Options {
            response.set_status(Status::Ok);
        }
    }
}

pub struct AppState {
    active_sessions: RwLock<HashMap<String, AppSession>>,
}

#[launch]
async fn rocket() -> _ {
    dotenv::dotenv().ok();

    let state = AppState {
        active_sessions: RwLock::default(),
    };

    rocket::build()
        .mount("/file", routes![upload, download])
        .mount("/session", routes![create_session, destroy_session])
        .mount("/user", routes![get_user_manifest, create_user])
        .attach(CORS)
        .manage(state)
}
