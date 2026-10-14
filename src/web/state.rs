use std::sync::Arc;

use axum::extract::FromRef;
use cookie::Key;

use crate::app::App;

/// What every request handler can reach: the application, and the key the
/// session cookies are encrypted with.
#[derive(Clone)]
pub struct WebState {
    pub app: Arc<App>,
    pub cookie_key: Key,
}

impl FromRef<WebState> for Key {
    fn from_ref(state: &WebState) -> Self {
        state.cookie_key.clone()
    }
}
