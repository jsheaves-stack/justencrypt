use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    http::{Header, Method},
    Request, Response,
};

/// Methods and request headers a cross-origin page may use. The admin header
/// `X-Admin-Api-Key` is left out on purpose, so browsers can't send it.
const ALLOWED_METHODS: &str = "GET, HEAD, POST, PUT, PATCH, DELETE";
const ALLOWED_HEADERS: &str = "Content-Type, Range";
/// Response headers a cross-origin page may read, for ranged downloads and
/// the file name of a folder download.
const EXPOSED_HEADERS: &str = "Content-Range, Content-Length, Accept-Ranges, Content-Disposition";
/// How long, in seconds, a browser may reuse a preflight answer.
const PREFLIGHT_MAX_AGE: &str = "600";

/// Grants CORS access, with credentials, to the one configured origin.
/// Requests from any other origin get no CORS headers, so browsers keep their
/// pages from reading the responses. The fairing never changes a status:
/// preflight requests are answered by the `OPTIONS` routes.
pub struct Cors {
    allow_origin: Option<String>,
}

impl Cors {
    /// `allow_origin` is the only origin granted access; with none, no
    /// origin is.
    pub fn new(allow_origin: Option<String>) -> Self {
        Self { allow_origin }
    }
}

#[async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let Some(allow_origin) = &self.allow_origin else {
            return;
        };

        // The headers depend on the request's origin, so a cache must not
        // reuse one origin's response for another.
        response.adjoin_header(Header::new("Vary", "Origin"));

        if request.headers().get_one("Origin") != Some(allow_origin.as_str()) {
            return;
        }

        response.set_header(Header::new(
            "Access-Control-Allow-Origin",
            allow_origin.clone(),
        ));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
        response.set_header(Header::new(
            "Access-Control-Expose-Headers",
            EXPOSED_HEADERS,
        ));

        let is_preflight = request.method() == Method::Options
            && request.headers().contains("Access-Control-Request-Method");

        if is_preflight {
            response.set_header(Header::new("Access-Control-Allow-Methods", ALLOWED_METHODS));
            response.set_header(Header::new("Access-Control-Allow-Headers", ALLOWED_HEADERS));
            response.set_header(Header::new("Access-Control-Max-Age", PREFLIGHT_MAX_AGE));
        }
    }
}

/// Headers every response gets. Responses hold decrypted files and user
/// data, so browsers and proxies must never store them, and requests the
/// client makes from a page must not leak its URL.
pub struct SecurityHeaders;

#[async_trait]
impl Fairing for SecurityHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Add security headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Cache-Control", "no-store"));
        response.set_header(Header::new("Referrer-Policy", "no-referrer"));
    }
}
