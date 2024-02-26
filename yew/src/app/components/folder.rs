use yew::prelude::*;

use crate::app::methods::manifest::FileSystemNode;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub node: FileSystemNode,
    pub file_name: String,
    pub on_folder_click: Callback<String>,
}

#[function_component(Folder)]
pub fn folder(props: &Props) -> Html {
    let on_folder_click = props.on_folder_click.clone();
    let file_name = props.file_name.clone();

    let onclick = Callback::from(move |_| {
        on_folder_click.emit(file_name.clone());
    });

    html! {
        <div {onclick} class={classes!("file_viewer__folder")}>
            {&props.file_name}
            {" - "}
            {props.node.children.len()}
        </div>
    }
}
