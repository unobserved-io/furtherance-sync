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

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{database, encryption, login, logout, models::AppState, register, sync};

pub fn configure_routes(state: AppState) -> Router {
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

    app
}

async fn determine_root(state: axum::extract::State<AppState>) -> axum::response::Response {
    match database::has_any_users(&state.db).await {
        Ok(true) => axum::response::Redirect::to("/login").into_response(),
        Ok(false) => axum::response::Redirect::to("/register").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
