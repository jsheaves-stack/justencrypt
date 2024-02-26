use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::app::requests::session::submit_login;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub on_auth_change: Callback<bool>,
}

#[function_component(LoginForm)]
pub fn login_form(props: &Props) -> Html {
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
                        <label for="user_name">{"Username: "}</label>
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
