use crate::app::requests::file::wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    wasm_bindgen::{self, JsValue},
    HtmlInputElement,
};
use yew::prelude::*;
#[wasm_bindgen(module = "/src/app/js/requests/file.js")]

extern "C" {
    fn uploadFileStream(file: JsValue, file_path: JsValue) -> web_sys::js_sys::Promise;
}

pub fn upload_files(
    file_input: HtmlInputElement,
    file_path: Vec<String>,
    on_complete: Callback<usize>,
) {
    if let Some(files) = file_input.files() {
        let total_files = files.length();
        let mut successful_uploads = 0usize;

        for i in 0..total_files {
            if let Some(file) = files.get(i) {
                let file_name = file.name();
                let full_path = format!("{}/{}", file_path.join("/"), file_name);

                let promise = uploadFileStream(JsValue::from(file), JsValue::from(full_path));

                // Clone the callback to use in the async move block
                let on_complete_clone = on_complete.clone();

                let future = async move {
                    match JsFuture::from(promise).await {
                        Ok(_) => {
                            // Use a counter to track successful uploads
                            successful_uploads += 1;
                            // If all files have been processed, emit the total number of successful uploads
                            if successful_uploads == total_files as usize {
                                web_sys::console::log_1(
                                    &format!(
                                        "Successfully uploaded all {} files.",
                                        successful_uploads
                                    )
                                    .into(),
                                );

                                web_sys::console::log_1(
                                    &format!("Successfully uploaded file {}.", successful_uploads)
                                        .into(),
                                );

                                on_complete_clone.emit(successful_uploads);
                            }
                        }
                        Err(e) => {
                            // Handle the error, e.g., by logging or panicking
                            web_sys::console::log_1(
                                &format!("Error uploading file: {:?}", e).into(),
                            );
                        }
                    }
                };
                spawn_local(future);
            }
        }
    }
}

// pub fn upload_file(file: File, upload_path: String, on_upload_complete: Callback<bool>) {
//     let form_data = FormData::new().unwrap();
//     form_data.append_with_blob("file", &file).unwrap();

//     let mut opts = RequestInit::new();
//     opts.method("POST");
//     opts.body(Some(&form_data));
//     opts.mode(RequestMode::Cors);
//     opts.credentials(RequestCredentials::Include);

//     let request_url = format!("http://localhost:8000/file/{}", upload_path); // Construct the full URL
//     let request = Request::new_with_str_and_init(&request_url, &opts).unwrap();

//     let window = window().unwrap();
//     let fetch = window.fetch_with_request(&request);

//     let future = async move {
//         let response: Response = JsFuture::from(fetch).await.unwrap().dyn_into().unwrap();

//         if response.ok() {
//             on_upload_complete.emit(true);
//         } else {
//             // Handle HTTP error
//             on_upload_complete.emit(false);
//         }
//     };

//     spawn_local(future);
// }

// pub fn upload_file(file: File, upload_path: String, on_upload_complete: Callback<bool>) {
//     let mut opts = RequestInit::new();
//     opts.method("POST");
//     opts.mode(RequestMode::Cors);

//     // Create a ReadableStream from the file
//     let stream = ReadableStream::new_with_underlying_source(&make_stream_source(&file)).unwrap();
//     opts.body(Some(&JsValue::from(stream)));

//     let request_url = format!("http://localhost:8000{}", upload_path); // Construct the full URL
//     let request = Request::new_with_str_and_init(&request_url, &opts).unwrap();

//     let window = window().unwrap();
//     let fetch = window.fetch_with_request(&request);

//     let future = async move {
//         let response: Response = JsFuture::from(fetch)
//             .await
//             .unwrap()
//             .dyn_into()
//             .unwrap();

//         if response.ok() {
//             on_upload_complete.emit(true);
//         } else {
//             on_upload_complete.emit(false);
//         }
//     };

//     spawn_local(future);
// }
