use actix_web::{web, HttpResponse};

use crate::{
    encryption::{generate_key, show_encryption_setup},
    has_any_users,
    login::{handle_login_form, login, show_login},
    logout::log_out_client,
    models::AppState,
    register::{handle_register_form, show_register},
    sync::handle_sync,
};

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            // Web routes
            .route("/", web::get().to(determine_root))
            .route("/login", web::get().to(show_login))
            .route("/login", web::post().to(handle_login_form))
            .route("/register", web::get().to(show_register))
            .route("/register", web::post().to(handle_register_form))
            .route("/encryption", web::get().to(show_encryption_setup))
            // API Routes
            .route("/api/encryption/generate", web::post().to(generate_key))
            .route("/api/login", web::post().to(login))
            .route("/api/logout", web::post().to(log_out_client))
            .route("/api/sync", web::post().to(handle_sync)),
    );

    // #[cfg(feature = "official")]
    // cfg.service(
    //     web::scope("")
    //         .route(
    //             "/subscription",
    //             web::get().to(super::subscription::show_subscription),
    //         )
    // );
}

async fn determine_root(state: web::Data<AppState>) -> HttpResponse {
    match has_any_users(&state.db).await {
        Ok(true) => HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish(),
        Ok(false) => HttpResponse::Found()
            .append_header(("Location", "/register"))
            .finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
