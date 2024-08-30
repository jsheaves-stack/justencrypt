use rocket::{launch, tokio::sync::RwLock};
use routes::{
    file::{delete_file, file_options, get_file, put_file},
    folder::{create_folder, folder_options, get_folder},
    session::{
        check_session, check_session_options, create_session, create_session_options,
        destroy_session, destroy_session_options,
    },
    thumbnail::{get_thumbnail, thumbnail_options},
    user::{create_user, create_user_options, get_user_manifest, manifest_options},
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
        .mount(
            "/file",
            routes![get_file, put_file, delete_file, file_options],
        )
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount(
            "/folder",
            routes![get_folder, create_folder, folder_options],
        )
        .mount(
            "/user",
            routes![
                get_user_manifest,
                create_user,
                manifest_options,
                create_user_options
            ],
        )
        .mount(
            "/session",
            routes![
                create_session,
                destroy_session,
                check_session,
                create_session_options,
                destroy_session_options,
                check_session_options
            ],
        )
}
