use rocket::{launch, routes};
use routes::file::{download, upload};
mod routes;

#[launch]
async fn rocket() -> _ {
    dotenv::dotenv().ok();

    rocket::build().mount("/file", routes![upload, download])
}
