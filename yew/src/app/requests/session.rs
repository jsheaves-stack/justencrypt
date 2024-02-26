use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    wasm_bindgen::{self, JsValue},
    Request, RequestCredentials, RequestInit, RequestMode, Response,
};
use yew::Callback;

use crate::app::UserManifest;

pub fn submit_login(user_name: String, password: String, on_auth_change: Callback<bool>) {
    let payload = serde_json::json!({
        "user_name": (*user_name),
        "passphrase": (*password)
    })
    .to_string();

    let mut request_init = RequestInit::new();

    request_init.method("POST");
    request_init.mode(RequestMode::Cors);
    request_init.body(Some(&JsValue::from_str(&payload)));
    request_init.credentials(RequestCredentials::Include);

    let request =
        Request::new_with_str_and_init("http://localhost:8000/session/create", &request_init)
            .unwrap();
    request
        .headers()
        .set("Content-Type", "application/json")
        .unwrap();

    let window = web_sys::window().unwrap();

    let request_promise = window.fetch_with_request(&request);

    let future = async move {
        let response: Response = wasm_bindgen_futures::JsFuture::from(request_promise)
            .await
            .unwrap()
            .dyn_into()
            .unwrap();

        if response.ok() {
            wasm_bindgen_futures::JsFuture::from(response.text().unwrap())
                .await
                .unwrap();

            on_auth_change.emit(true);
        } else {
            // Handle HTTP error
            panic!()
        }
    };

    spawn_local(future);
}

pub fn submit_logout(on_auth_change: Callback<bool>) {
    let mut request_init = RequestInit::new();

    request_init.method("POST");
    request_init.mode(RequestMode::Cors);
    request_init.credentials(RequestCredentials::Include);

    let request =
        Request::new_with_str_and_init("http://localhost:8000/session/destroy", &request_init)
            .unwrap();

    let window = web_sys::window().unwrap();

    let request_promise = window.fetch_with_request(&request);

    let future = async move {
        let response: Response = wasm_bindgen_futures::JsFuture::from(request_promise)
            .await
            .unwrap()
            .dyn_into()
            .unwrap();

        if response.ok() {
            wasm_bindgen_futures::JsFuture::from(response.text().unwrap())
                .await
                .unwrap();

            on_auth_change.emit(false);
        } else {
            // Handle HTTP error
            // panic!()
        }
    };

    spawn_local(future);
}

pub fn get_user_manifest(
    on_user_manifest_change: Callback<UserManifest>,
    on_initial_render_change: Callback<bool>,
    on_auth_change: Callback<bool>,
) {
    let mut request_init = RequestInit::new();

    request_init.method("GET");
    request_init.mode(RequestMode::Cors);
    request_init.credentials(RequestCredentials::Include);

    let request =
        Request::new_with_str_and_init("http://localhost:8000/user/manifest", &request_init)
            .unwrap();

    let window = web_sys::window().unwrap();

    let request_promise = window.fetch_with_request(&request);

    let future = async move {
        let response: Response = wasm_bindgen_futures::JsFuture::from(request_promise)
            .await
            .unwrap()
            .dyn_into()
            .unwrap();

        if response.ok() {
            let user_manifest_str = wasm_bindgen_futures::JsFuture::from(response.text().unwrap())
                .await
                .unwrap()
                .as_string()
                .unwrap();

            let user_manifest: UserManifest = serde_json::from_str(&user_manifest_str).unwrap();

            on_user_manifest_change.emit(user_manifest);
            on_initial_render_change.emit(false);
            on_auth_change.emit(true);
        } else {
            // Handle HTTP error
            // panic!("{:?}", response);
        }
    };

    spawn_local(future);
}
