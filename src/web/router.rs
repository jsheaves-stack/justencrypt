use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware,
    routing::{delete, get, post, put, MethodRouter},
    Router,
};
use tower::{
    util::{MapRequest, MapRequestLayer},
    Layer,
};

use crate::{
    app::App,
    web::{
        cookies::cookie_key,
        middleware::{
            access_log, cors, normalize_path, not_found, problem_bodies, security_headers,
        },
        routes::{admin, file, folder, info, session, thumbnail, upload},
        state::WebState,
    },
};

/// The whole application as one service: the router behind
/// [`normalize_path`], which has to see each request before routing does.
pub type AppService = MapRequest<Router, fn(Request) -> Request>;

/// The state the handlers share, for `app`, with the cookie key its
/// configuration gives.
pub fn web_state(app: Arc<App>) -> WebState {
    let cookie_key = cookie_key(app.config.http.secret_key.as_ref());

    WebState { app, cookie_key }
}

/// Builds the application's service: its routes and middleware, as the
/// application's configuration asks.
pub fn build_service(state: WebState) -> AppService {
    let normalize: fn(Request) -> Request = normalize_path;

    MapRequestLayer::new(normalize).layer(build_router(state))
}

/// The routes and the middleware around them.
pub fn build_router(state: WebState) -> Router {
    let config = state.app.config.clone();

    let file_routes = || -> MethodRouter<WebState> {
        get(file::get_file)
            .put(file::put_file)
            .delete(file::delete_file)
            .patch(file::patch_file)
            .options(file::file_options)
    };
    let folder_routes = || -> MethodRouter<WebState> {
        get(folder::get_folder)
            .put(folder::create_folder)
            .delete(folder::delete_folder)
            .patch(folder::patch_folder)
            .options(folder::folder_options)
    };
    let thumbnail_routes = || -> MethodRouter<WebState> {
        get(thumbnail::get_thumbnail).options(thumbnail::thumbnail_options)
    };
    let initiate_routes =
        || -> MethodRouter<WebState> { post(upload::init_upload).options(upload::upload_options) };

    let mut router = Router::new()
        .route("/", get(info::get_server_info))
        .route("/file", file_routes())
        .route("/file/{*path}", file_routes())
        .route("/folder", folder_routes())
        .route("/folder/{*path}", folder_routes())
        .route("/thumbnail", thumbnail_routes())
        .route("/thumbnail/{*path}", thumbnail_routes())
        .route("/upload/initiate", initiate_routes())
        .route("/upload/initiate/{*path}", initiate_routes())
        .route(
            "/upload/chunk/{upload_id}",
            put(upload::upload_chunk).options(upload::upload_options),
        )
        .route(
            "/upload/finalize/{upload_id}",
            post(upload::finalize_upload).options(upload::upload_options),
        )
        .route(
            "/session",
            post(session::create_session)
                .delete(session::destroy_session)
                .options(session::session_options),
        );

    if config.admin_api_key.is_some() {
        trace!("JUSTENCRYPT_ADMIN_API_KEY is set, mounting admin routes.");

        router = router
            .route(
                "/admin/session",
                get(admin::get_session).options(admin::admin_options),
            )
            .route(
                "/admin/session/{session_id}",
                delete(admin::delete_session).options(admin::admin_options),
            )
            .route(
                "/admin/users",
                post(admin::create_user).options(admin::admin_options),
            );
    } else {
        warn!("JUSTENCRYPT_ADMIN_API_KEY is not set, admin routes will NOT be available.");
    }

    let json_limit = usize::try_from(config.http.json_limit.as_u64()).unwrap_or(usize::MAX);

    router
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(json_limit))
        .layer(middleware::from_fn(access_log))
        .layer(middleware::from_fn(problem_bodies))
        .layer(middleware::from_fn_with_state(state.clone(), cors))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}
