use yew::prelude::*;

use crate::app::methods::manifest::FileSystemNode;

const SUPPORTED_IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp"];

#[derive(Properties, PartialEq)]
pub struct Props {
    pub node: FileSystemNode,
    pub file_name: String,
    pub file_path: Vec<String>,
}

#[function_component(File)]
pub fn file(props: &Props) -> Html {
    let full_path = format!("{}/{}", props.file_path.join("/"), props.file_name);
    let url = format!("http://localhost:8000/file/{}", full_path);

    let is_image = props
        .node
        .file_extension
        .as_ref()
        .map(|ext| SUPPORTED_IMAGE_EXTENSIONS.contains(&ext.as_str()))
        .unwrap_or(false);

    html! {
        <div class={classes!("file_viewer__file")}>
            if is_image {
                <img src={url.clone()} />
            } else {
                <a href={url.clone()} target="_blank">{props.file_name.clone()}</a>
            }
        </div>
    }
}
