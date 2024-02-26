use serde::{Deserialize, Serialize};
use yew::prelude::*;

use crate::app::{
    components::{file_viewer::FileViewer, header::Header, login_form::LoginForm},
    requests::session::{get_user_manifest, submit_logout},
};

use self::methods::manifest::FileSystemNode;

mod components;
mod methods;
mod requests;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserManifest {
    pub files: FileSystemNode,
}

#[function_component(App)]
pub fn app() -> Html {
    let initial_render = use_state(|| true);

    let is_authenticated = use_state(|| false);

    let user_manifest = use_state(|| UserManifest {
        files: FileSystemNode::default(),
    });

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

    let on_logout_click = {
        let on_auth_change = on_auth_change.clone();

        Callback::from(move |e: MouseEvent| {
            e.prevent_default();

            let on_auth_change = on_auth_change.clone();

            // Call the new function
            submit_logout(on_auth_change);
        })
    };

    if *initial_render {
        get_user_manifest(
            on_user_manifest_change,
            on_initial_render_change,
            on_auth_change.clone(),
        );
    }

    html! {
        <main>
            <div>
                <Header {on_logout_click} />
            </div>
            <div>
                if !*is_authenticated {
                    <LoginForm {on_auth_change} />
                } else {
                    <FileViewer file_tree={user_manifest.files.clone()} />
                }
            </div>
        </main>
    }
}
