use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::app::{
    components::{file::File, folder::Folder},
    methods::manifest::FileSystemNode,
    requests::file::upload_file,
};

fn get_node_by_path<'a>(root: &'a FileSystemNode, path: &[String]) -> Option<&'a FileSystemNode> {
    let mut current_node = root;

    for component in path {
        if current_node.is_file {
            // If we hit a file before exhausting the path, return None
            return None;
        }

        match current_node.children.get(component) {
            Some(node) => current_node = node,
            None => return None, // Path component not found
        }
    }

    Some(current_node)
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub file_tree: FileSystemNode,
}

#[function_component(FileViewer)]
pub fn file_viewer(props: &Props) -> Html {
    let current_path = use_state(|| Vec::new());
    let current_node = get_node_by_path(&props.file_tree, &current_path);
    let file_input_ref = use_node_ref();

    let on_go_back = {
        let current_path = current_path.clone();
        Callback::from(move |_| {
            let mut path = (*current_path).clone();
            path.pop(); // Remove the last component of the path
            current_path.set(path);
        })
    };

    let on_file_upload = {
        let file_input_ref = file_input_ref.clone();
        let current_path = current_path.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if let Some(input) = file_input_ref.cast::<HtmlInputElement>() {
                upload_file(
                    input,
                    current_path.to_vec(),
                    Callback::from(move |success: bool| if success { () } else { () }),
                );
            }
        })
    };

    html! {
        <div class={classes!("file_viewer")}>
            <div class={classes!("file_viewer__back_button")}>
                <button onclick={on_go_back.clone()}>{"Back"}</button>
            </div>
            <div>
                <form onsubmit={on_file_upload}>
                    <input type="file" ref={file_input_ref} />
                    <button type="submit">{"Upload"}</button>
                </form>
            </div>
            <div class={classes!("file_viewer__files")}>
            {
                if let Some(node) = current_node {
                        node.children.iter().map(|(key, child_node)| {
                        let current_path_clone = current_path.clone(); // Clone the current path

                        html! {
                            if child_node.is_file {
                                <File node={child_node.clone()} file_name={key.clone()} file_path={(*current_path_clone).clone()} />
                            } else {
                                <Folder
                                    node={child_node.clone()}
                                    file_name={key.clone()}
                                    on_folder_click={
                                            Callback::from(move |file_name: String| {
                                            let mut new_path = (*current_path_clone).clone();

                                            new_path.push(file_name);

                                            current_path_clone.set(new_path.to_vec());
                                        })
                                    }
                                />
                            }
                        }
                    }).collect::<Html>()
                } else {
                    html! { <div>{"Folder not found or is a file."}</div> }
                }
            }
            </div>
        </div>
    }
}
