//! What happens to every request and response, around the route handlers.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::web::{extractors::header_text, problem::Problem, state::WebState};

/// Methods and request headers a cross-origin page may use. The admin header
/// `X-Admin-Api-Key` is left out on purpose, so browsers can't send it.
const ALLOWED_METHODS: &str = "GET, HEAD, POST, PUT, PATCH, DELETE";
const ALLOWED_HEADERS: &str = "Content-Type, Range";
/// Response headers a cross-origin page may read, for ranged downloads and
/// the file name of a folder download.
const EXPOSED_HEADERS: &str = "Content-Range, Content-Length, Accept-Ranges, Content-Disposition";
/// How long, in seconds, a browser may reuse a preflight answer.
const PREFLIGHT_MAX_AGE: &str = "600";

/// Headers every response gets. Responses hold decrypted files and user data,
/// so browsers and proxies must never store them, and requests the client
/// makes from a page must not leak its URL. The rest keep browsers from
/// guessing content types or framing the responses, and ask them to use only
/// HTTPS for the next year.
const SECURITY_HEADERS: [(&str, &str); 6] = [
    ("cache-control", "no-store"),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "SAMEORIGIN"),
    ("permissions-policy", "interest-cohort=()"),
    ("strict-transport-security", "max-age=31536000"),
];

/// The log target of the one line logged per request, which
/// `JUSTENCRYPT_HTTP_LOG_LEVEL` controls.
pub const ACCESS_LOG_TARGET: &str = "justencrypt::web::access";

/// Rewrites the request path without empty segments: no repeated or trailing
/// `/`. Routes then match `/folder/`, `/folder//a` and `/folder/a` alike, and
/// every route works with or without a trailing slash.
pub fn normalize_path(mut request: Request) -> Request {
    let path = request.uri().path();

    if path == "/" || !(path.ends_with('/') || path.contains("//")) {
        return request;
    }

    let mut normalized: String = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .flat_map(|segment| ["/", segment])
        .collect();

    if normalized.is_empty() {
        normalized.push('/');
    }

    if let Some(query) = request.uri().query() {
        normalized = format!("{normalized}?{query}");
    }

    let mut parts = request.uri().clone().into_parts();

    if let Ok(path_and_query) = normalized.parse() {
        parts.path_and_query = Some(path_and_query);

        if let Ok(uri) = Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }

    request
}

/// Grants CORS access, with credentials, to the one configured origin.
/// Requests from any other origin get no CORS headers, so browsers keep their
/// pages from reading the responses. It never changes a status: preflight
/// requests are answered by the `OPTIONS` routes.
pub async fn cors(State(state): State<WebState>, request: Request, next: Next) -> Response {
    let Some(allow_origin) = state.app.config.http.allow_origin.clone() else {
        return next.run(request).await;
    };

    let from_allowed_origin =
        header_text(request.headers(), "Origin") == Some(allow_origin.as_str());
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key("Access-Control-Request-Method");

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // The headers depend on the request's origin, so a cache must not reuse
    // one origin's response for another.
    headers.append(header::VARY, HeaderValue::from_static("Origin"));

    if !from_allowed_origin {
        return response;
    }

    if let Ok(origin) = HeaderValue::from_str(&allow_origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }

    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSED_HEADERS),
    );

    if is_preflight {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(ALLOWED_METHODS),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(ALLOWED_HEADERS),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(PREFLIGHT_MAX_AGE),
        );
    }

    response
}

/// Adds the [`SECURITY_HEADERS`] to every response, without overwriting one
/// the response already has.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    for (name, value) in SECURITY_HEADERS {
        let name = HeaderName::from_static(name);

        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }

    response
}

/// Gives the bare error responses the router makes itself, such as `405` for
/// a method a route doesn't have, a Problem Details body like every other
/// error. Their headers, such as `Allow`, are kept.
pub async fn problem_bodies(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();

    if !(status.is_client_error() || status.is_server_error())
        || response.headers().contains_key(header::CONTENT_TYPE)
    {
        return response;
    }

    let (mut parts, _) = response.into_parts();
    let problem = Problem::status(status);

    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::web::problem::PROBLEM_JSON),
    );
    parts.headers.remove(header::CONTENT_LENGTH);

    Response::from_parts(parts, Body::from(problem.body()))
}

/// Logs one line per request: its method, path and status.
pub async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    let response = next.run(request).await;

    info!(target: ACCESS_LOG_TARGET, "{} {} => {}", method, path, response.status());

    response
}

/// The response for a path no route matches.
pub async fn not_found() -> Response {
    Problem::status(StatusCode::NOT_FOUND).into_response()
}
