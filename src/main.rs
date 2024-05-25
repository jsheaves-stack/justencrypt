use rocket::{launch, routes, tokio::sync::RwLock};
use routes::{
    file::{delete_file, get_file, put_file},
    folder::get_folder,
    session::{check_session, create_session, destroy_session},
    thumbnail::get_thumbnail,
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
        .attach(CORS)
        .manage(state)
        .mount("/file", routes![get_file, put_file, delete_file])
        .mount("/thumbnail", routes![get_thumbnail])
        .mount("/folder", routes![get_folder])
        .mount("/user", routes![get_user_manifest, create_user])
        .mount(
            "/session",
            routes![create_session, destroy_session, check_session],
        )
}
