use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    wasm_bindgen::{self, JsValue},
    HtmlInputElement, Request, RequestCredentials, RequestInit, RequestMode, Response,
};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ChildProps {
    pub on_auth_change: Callback<bool>,
}

fn submit_login(user_name: String, password: String, on_auth_change: Callback<bool>) {
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

#[function_component(LoginForm)]
pub fn login_form(props: &ChildProps) -> Html {
    let user_name = use_state(|| String::new());
    let password = use_state(|| String::new());

    let on_user_name_change = {
        let user_name = user_name.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            user_name.set(input.value());
        })
    };

    let on_password_change = {
        let password = password.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            password.set(input.value());
        })
    };

    let on_submit = {
        let user_name = user_name.clone();
        let password = password.clone();
        let on_auth_change = props.on_auth_change.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let user_name = (*user_name).clone();
            let password = (*password).clone();
            let on_auth_change = on_auth_change.clone();

            // Call the new function
            submit_login(user_name, password, on_auth_change);
        })
    };

    html! {
        <div class={classes!("login__main")}>
            <form onsubmit={on_submit} class={classes!("login__form")}>
                <div class={classes!("login__form__title")}>
                    <span>{"Login"}</span>
                </div>
                <div class={classes!("login__form__body")}>
                    <div class={classes!("login__form__input")}>
                        <label for="user_name">{"user_name: "}</label>
                        <input id="user_name" name="user_name" type="text" value={(*user_name).clone()} oninput={on_user_name_change}/>
                    </div>
                    <div class={classes!("login__form__input")}>
                        <label for="password">{"Password: "}</label>
                        <input id="password" name="password" type="password" value={(*password).clone()} oninput={on_password_change}/>
                    </div>
                    <div class={classes!("login__form__submit")}>
                        <button type="submit">{"Submit"}</button>
                    </div>
                </div>
            </form>
        </div>
    }
}
