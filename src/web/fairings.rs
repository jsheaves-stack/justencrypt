use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Header, Method, Status},
    Request, Response,
};

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
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        let methods = "POST, GET, PATCH, PUT, HEAD, OPTIONS";

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
