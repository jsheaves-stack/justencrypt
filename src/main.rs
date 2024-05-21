use rocket::{launch, routes, tokio::sync::RwLock};
use routes::{
    file::{get_file, put_file},
    folder::get_folder,
    session::{create_session, destroy_session},
    user::{create_user, get_user_manifest},
};
use session::session::AppSession;
use std::collections::HashMap;
use web::fairings::CORS;

mod enums;
mod routes;
mod session;
mod web;

#[macro_use]
extern crate rocket;
extern crate serde;

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
        .mount("/file", routes![get_file, put_file])
        .mount("/folder", routes![get_folder])
        .mount("/session", routes![create_session, destroy_session])
        .mount("/user", routes![get_user_manifest, create_user])
        .attach(CORS)
        .manage(state)
}
