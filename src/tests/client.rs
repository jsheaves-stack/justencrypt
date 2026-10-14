//! A client for the whole application that runs requests in-process, as a
//! browser would send them: it keeps the cookies responses set and sends them
//! back, and leaves each response's body unread until a test asks for it, so
//! a test can hold a download open without reading it.

use std::sync::{Arc, Mutex};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
};
use cookie::{Cookie, CookieJar, Key};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tower::ServiceExt;

use crate::{
    app::App,
    web::{
        router::{build_service, web_state, AppService},
        state::WebState,
    },
};

/// Sends requests to one application and keeps its cookies between them.
pub struct TestClient {
    service: AppService,
    app: Arc<App>,
    key: Key,
    jar: Mutex<CookieJar>,
}

/// A request being built; [`dispatch`](TestRequest::dispatch) sends it.
pub struct TestRequest<'c> {
    client: &'c TestClient,
    method: Method,
    uri: String,
    headers: HeaderMap,
    cookies: Vec<Cookie<'static>>,
    body: Bytes,
}

/// A response whose body has not been read yet.
pub struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

/// A response's headers, by name.
pub struct TestHeaders<'r>(&'r HeaderMap);

/// The cookies the client keeps.
pub struct TrackedCookies<'c>(&'c TestClient);

/// An error response's Problem Details body.
#[derive(Debug, Deserialize)]
pub struct ProblemBody {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
}

impl TestClient {
    /// A client for `app`, wired as the server wires it.
    pub fn new(app: Arc<App>) -> Self {
        let WebState { app, cookie_key } = web_state(app);
        let service = build_service(WebState {
            app: app.clone(),
            cookie_key: cookie_key.clone(),
        });

        Self {
            service,
            app,
            key: cookie_key,
            jar: Mutex::new(CookieJar::new()),
        }
    }

    /// The application the client talks to.
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    pub fn get(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::GET, uri)
    }

    pub fn head(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::HEAD, uri)
    }

    pub fn put(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::PUT, uri)
    }

    pub fn post(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::POST, uri)
    }

    pub fn patch(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::PATCH, uri)
    }

    pub fn delete(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::DELETE, uri)
    }

    pub fn options(&self, uri: impl Into<String>) -> TestRequest<'_> {
        self.request(Method::OPTIONS, uri)
    }

    /// The cookies the client has kept from earlier responses.
    pub fn cookies(&self) -> TrackedCookies<'_> {
        TrackedCookies(self)
    }

    fn request(&self, method: Method, uri: impl Into<String>) -> TestRequest<'_> {
        TestRequest {
            client: self,
            method,
            uri: uri.into(),
            headers: HeaderMap::new(),
            cookies: Vec::new(),
            body: Bytes::new(),
        }
    }

    /// `cookie` encrypted the way the server encrypts private cookies.
    fn encrypt(&self, cookie: Cookie<'static>) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        jar.private_mut(&self.key).add(cookie.clone());

        jar.get(cookie.name()).cloned().unwrap_or(cookie)
    }
}

impl TestRequest<'_> {
    pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Self {
        self.headers.append(
            HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            HeaderValue::from_str(value.as_ref()).expect("a valid header value"),
        );

        self
    }

    /// Sends `cookie` as it is.
    pub fn cookie(mut self, cookie: Cookie<'static>) -> Self {
        self.cookies.push(cookie);

        self
    }

    /// Sends `cookie` encrypted, as the server sets private cookies.
    pub fn private_cookie(mut self, cookie: Cookie<'static>) -> Self {
        let cookie = self.client.encrypt(cookie);
        self.cookies.push(cookie);

        self
    }

    pub fn body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = Bytes::copy_from_slice(body.as_ref());

        self
    }

    /// Sends `value` as a JSON body, with its content type.
    pub fn json<T: Serialize>(self, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("a serializable body");

        self.header("Content-Type", "application/json").body(body)
    }

    /// Sends the request through the whole application. Cookies the client
    /// kept are sent too, unless the request sets one of the same name.
    pub async fn dispatch(self) -> TestResponse {
        let mut cookies = self.client.jar.lock().unwrap().clone();

        for cookie in self.cookies {
            cookies.add(cookie);
        }

        // Sent percent-encoded, as browsers send back what servers set.
        let cookie_header = cookies
            .iter()
            .map(|cookie| cookie.encoded().stripped().to_string())
            .collect::<Vec<_>>()
            .join("; ");

        let mut request = Request::builder()
            .method(self.method)
            .uri(self.uri)
            .body(Body::from(self.body))
            .expect("a valid request");

        *request.headers_mut() = self.headers;

        if !cookie_header.is_empty() {
            request.headers_mut().insert(
                header::COOKIE,
                HeaderValue::from_str(&cookie_header).expect("valid cookies"),
            );
        }

        let response = self
            .client
            .service
            .clone()
            .oneshot(request)
            .await
            .expect("the application never fails");
        let (parts, body) = response.into_parts();

        let mut jar = self.client.jar.lock().unwrap();

        for set_cookie in parts.headers.get_all(header::SET_COOKIE) {
            let Some(cookie) = set_cookie
                .to_str()
                .ok()
                .and_then(|value| Cookie::parse_encoded(value.to_string()).ok())
            else {
                continue;
            };

            let removed =
                cookie.max_age().is_some_and(|age| age.is_zero()) || cookie.value().is_empty();

            if removed {
                jar.remove(Cookie::from(cookie.name().to_string()));
            } else {
                jar.add(cookie);
            }
        }

        TestResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }
}

impl TestResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> TestHeaders<'_> {
        TestHeaders(&self.headers)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.headers().get_one("Content-Type")
    }

    /// The cookies the response sets.
    pub fn cookies(&self) -> Vec<Cookie<'static>> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| Cookie::parse_encoded(value.to_str().ok()?.to_string()).ok())
            .collect()
    }

    /// Reads the whole body. A body that breaks off is returned as far as it
    /// got.
    pub async fn into_bytes(self) -> Option<Vec<u8>> {
        to_bytes(self.body, usize::MAX)
            .await
            .ok()
            .map(|bytes| bytes.to_vec())
    }

    pub async fn into_string(self) -> Option<String> {
        String::from_utf8(self.into_bytes().await?).ok()
    }

    pub async fn into_json<T: DeserializeOwned>(self) -> Option<T> {
        serde_json::from_slice(&self.into_bytes().await?).ok()
    }

    /// Reads an error response's Problem Details body.
    pub async fn into_problem(self) -> ProblemBody {
        assert_eq!(
            self.content_type(),
            Some("application/problem+json"),
            "an error response"
        );

        self.into_json().await.expect("a Problem Details body")
    }
}

impl<'r> TestHeaders<'r> {
    /// The first value of the header `name`, if it is text.
    pub fn get_one(&self, name: &str) -> Option<&'r str> {
        self.0.get(name).and_then(|value| value.to_str().ok())
    }

    /// Every value of the header `name` that is text.
    pub fn get(&self, name: &str) -> impl Iterator<Item = &'r str> {
        self.0
            .get_all(name)
            .into_iter()
            .filter_map(|value| value.to_str().ok())
    }
}

impl TrackedCookies<'_> {
    /// The decrypted value of the private cookie `name`, if the client has
    /// one.
    pub fn get_private(&self, name: &str) -> Option<Cookie<'static>> {
        let jar = self.0.jar.lock().unwrap();

        jar.private(&self.0.key).get(name)
    }
}
