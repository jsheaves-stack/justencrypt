use std::collections::HashMap;

use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    wasm_bindgen::JsCast, Request, RequestCredentials, RequestInit, RequestMode, Response,
};
use yew::prelude::*;

use crate::app::components::login_form::LoginForm;

mod components;

fn convert_to_folder_structure(
    data: HashMap<String, String>,
) -> HashMap<String, HashMap<String, String>> {
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (path, value) in data {
        let parts: Vec<&str> = path.split("\\").collect();
        let mut current_level: &mut HashMap<String, HashMap<String, String>> = &mut result;

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part of the path; insert the file
                let file_map: &mut HashMap<String, String> = current_level
                    .entry(part.to_string())
                    .or_insert_with(HashMap::new);
                file_map.insert(part.to_string(), value.clone());
            } else {
                // Ensure the folder exists and then descend into it
                let next_level: &mut HashMap<String, String> = current_level
                    .entry(part.to_string())
                    .or_insert_with(HashMap::new);
                // Update current_level to point to the next level
                current_level = unsafe { std::mem::transmute(next_level) };
            }
        }
    }

    result
}

fn get_user_manifest(
    on_user_manifest_change: Callback<UserManifest>,
    on_initial_render_change: Callback<bool>,
    on_auth_change: Callback<bool>,
    on_file_map_change: Callback<HashMap<String, HashMap<String, String>>>,
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
            let files = user_manifest.files.clone();
            on_user_manifest_change.emit(user_manifest);
            on_initial_render_change.emit(false);
            on_auth_change.emit(true);
            on_file_map_change.emit(convert_to_folder_structure(files))
        } else {
            // Handle HTTP error
            panic!("{:?}", response);
        }
    };

    spawn_local(future);
}

#[derive(Deserialize)]
struct UserManifest {
    pub files: HashMap<String, String>,
}

#[function_component(App)]
pub fn app() -> Html {
    let initial_render = use_state(|| true);
    let is_authenticated = use_state(|| false);
    let user_manifest = use_state(|| UserManifest {
        files: HashMap::default(),
    });
    let file_map = use_state(|| HashMap::<String, HashMap<String, String>>::new());

    let on_initial_render_change = {
        let initial_render = initial_render.clone();
        Callback::from(move |new_value: bool| initial_render.set(new_value))
    };

    let on_auth_change = {
        let is_authenticated = is_authenticated.clone();
        Callback::from(move |new_value: bool| is_authenticated.set(new_value))
    };

    let on_user_manifest_change = {
        let user_manifest = user_manifest.clone();
        Callback::from(move |new_value: UserManifest| user_manifest.set(new_value))
    };

    let on_file_map_change = {
        let file_map = file_map.clone();
        Callback::from(move |new_value: HashMap<String, HashMap<String, String>>| {
            file_map.set(new_value)
        })
    };

    if *initial_render {
        get_user_manifest(
            on_user_manifest_change,
            on_initial_render_change,
            on_auth_change.clone(),
            on_file_map_change,
        );
    }

    // get_user_manifest(on_user_manifest_change);

    html! {
        <main>
            if !*is_authenticated {
                <LoginForm {on_auth_change} />
            }
            else {
                <div>
                </div>
            }
        </main>
    }
}
