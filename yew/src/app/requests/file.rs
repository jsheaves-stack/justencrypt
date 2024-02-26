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

// In your Rust component
pub fn upload_file(file: HtmlInputElement, file_path: Vec<String>, on_complete: Callback<bool>) {
    if let Some(files) = file.files() {
        if let Some(file) = files.get(0) {
            let full_path = format!("{}/{}", file_path.join("/"), file.name());

            let promise = uploadFileStream(JsValue::from(file), JsValue::from(full_path));

            let future = async move {
                match JsFuture::from(promise).await {
                    Ok(_) => on_complete.emit(true),
                    Err(e) => { panic!("{:?}", e)},
                }
            };
            spawn_local(future);
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
