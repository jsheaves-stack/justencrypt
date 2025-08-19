use std::env;

use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Header, Method, Status},
    Request, Response,
};

pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        trace!("Entering fairing::Cors::info");
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        trace!("Entering fairing::Cors::on_response");
        let methods = "POST, GET, PATCH, PUT, HEAD, OPTIONS, DELETE";

        if let Ok(origin) = env::var("JUSTENCRYPT_ALLOW_ORIGIN") {
            trace!("Setting Access-Control-Allow-Origin to: {}", origin);
            response.set_header(Header::new("Access-Control-Allow-Origin", origin));
        }

        response.set_header(Header::new("Allow", methods));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
        response.set_header(Header::new("Access-Control-Allow-Methods", methods));
        response.set_header(Header::new("Access-Control-Request-Methods", methods));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
        trace!("Set standard CORS headers.");

        if request.method() == Method::Options {
            trace!("Request method is OPTIONS, setting status to OK.");
            response.set_status(Status::Ok);
        }
        trace!("Exiting fairing::Cors::on_response");
    }
}
