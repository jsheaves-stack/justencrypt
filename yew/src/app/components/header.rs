use yew::{classes, function_component, html, Callback, Html, MouseEvent, Properties};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub on_logout_click: Callback<MouseEvent>,
}

#[function_component(Header)]
pub fn header(_props: &Props) -> Html {
    html! {
        <div class={classes!("header")}>
            <div></div>
            <div></div>
            <div></div>
        </div>
    }
}
