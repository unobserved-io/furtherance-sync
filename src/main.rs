// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

mod auth;
mod database;
mod encryption;
mod login;
mod logout;
mod models;
mod register;
mod routes;
mod sync;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use handlebars::Handlebars;
use models::AppState;
use std::sync::Arc;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{error, info};
use tracing_subscriber::{self, EnvFilter};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_logger();
    let pool = match database::db_init().await {
        Ok(pool) => Arc::new(pool),
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database initialization failed: {}", e),
            ));
        }
    };

    // Initialize Handlebars
    let mut hb = Handlebars::new();
    // Register templates
    hb.register_template_file("base", "templates/layouts/base.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("encryption", "templates/pages/encryption.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("login", "templates/pages/login.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("register", "templates/pages/register.hbs")
        .map_err(to_io_error)?;
    #[cfg(feature = "official")]
    hb.register_template_file("billing", "templates/pages/billing.hbs")
        .map_err(to_io_error)?;
    // Register partials
    hb.register_template_file("nav", "templates/partials/nav.hbs")
        .map_err(to_io_error)?;
    // Register error template
    hb.register_template_file("error", "templates/error.hbs")
        .map_err(to_io_error)?;
    let hb = Arc::new(hb);

    let state = AppState {
        db: pool,
        hb: hb.clone(),
    };

    let app = Router::new()
        .route("/", get(determine_root))
        // Web interface routes
        .route(
            "/register",
            get(register::show_register).post(register::handle_register),
        )
        .route("/login", get(login::show_login).post(login::handle_login))
        .route("/logout", post(logout::handle_logout))
        .route("/encryption", get(encryption::show_encryption))
        // API routes
        .route("/api/register", post(register::api_register))
        .route("/api/login", post(login::api_login))
        .route("/api/encryption/generate", post(encryption::generate_key))
        .route("/api/sync", post(sync::handle_sync))
        .route("/api/logout", post(logout::api_logout))
        // Serve static files
        .nest_service("/static", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Add billing routes for official server
    #[cfg(feature = "official")]
    let app = app
        .route("/billing", get(billing::show_billing))
        .route("/api/billing/change-plan", post(billing::change_plan))
        .route("/api/billing/cancel", post(billing::cancel_subscription));

    let server = "127.0.0.1:8662";

    let listener = tokio::net::TcpListener::bind(&server).await?;
    info!("Server running on {}", &server);

    axum::serve(listener, app).await?;
    Ok(())
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
                .add_directive(tracing::Level::ERROR.into()),
        )
        .init();
}

async fn determine_root(state: axum::extract::State<AppState>) -> axum::response::Response {
    match database::has_any_users(&state.db).await {
        Ok(true) => axum::response::Redirect::to("/login").into_response(),
        Ok(false) => axum::response::Redirect::to("/register").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn to_io_error<E>(err: E) -> std::io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
