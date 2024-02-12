use std::{fs::File, path::PathBuf};

pub struct AppSession {
    pub user_name: String,
    pub pass_phrase: String,
    pub user_path: PathBuf,
    _manifest_file: File,
}

impl AppSession {
    pub fn open<'a>(user_name: &String, pass_phrase: &String) -> Result<Box<Self>, String> {
        let user_path = PathBuf::from(format!(".\\user_data\\{}", user_name));

        let _manifest_file = File::open(user_path.join("manifest")).unwrap();

        if user_path.exists() {
            Ok(Box::new(Self {
                user_name: user_name.to_string(),
                pass_phrase: pass_phrase.to_string(),
                user_path,
                _manifest_file,
            }))
        } else {
            Err(String::from("Failed to find user data."))
        }
    }
}
