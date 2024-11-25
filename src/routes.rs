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
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_extra::extract::CookieJar;
use tower_http::services::ServeDir;

use crate::middleware::{api_auth_middleware, web_auth_middleware};
use crate::{billing, database, encryption, login, logout, models::AppState, register, sync};

#[cfg(feature = "official")]
use crate::password_reset;

pub fn configure_routes(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(determine_root))
        .route(
            "/register",
            get(register::show_register).post(register::handle_register),
        )
        .route("/login", get(login::show_login).post(login::handle_login))
        .route("/api/register", post(register::api_register))
        .route("/api/login", post(login::api_login))
        .nest_service("/static", ServeDir::new("static"));

    // Protected web routes - requires session cookie
    let web_routes = Router::new()
        .route("/encryption", get(encryption::show_encryption))
        .route("/logout", post(logout::handle_logout))
        .layer(from_fn_with_state(
            state.clone(),
            |state: State<AppState>, jar: CookieJar, req: Request<Body>, next: Next| async move {
                web_auth_middleware(state, jar, req, next).await
            },
        ));

    // Protected API routes - requires Bearer token
    let api_routes = Router::new()
        .route("/api/encryption/generate", post(encryption::generate_key))
        .route("/api/sync", post(sync::handle_sync))
        .route("/api/logout", post(logout::api_logout))
        .layer(from_fn_with_state(
            state.clone(),
            |state: State<AppState>, req: Request<Body>, next: Next| async move {
                api_auth_middleware(state, req, next).await
            },
        ));

    // Additional routes for official server
    #[cfg(feature = "official")]
    let official_routes = Router::new()
        .route(
            "/forgot-password",
            get(password_reset::show_forgot_password).post(password_reset::handle_forgot_password),
        )
        .route(
            "/reset-password",
            get(password_reset::show_reset_password).post(password_reset::handle_reset_password),
        );

    #[cfg(feature = "official")]
    let official_protected_routes = Router::new()
        .route(
            "/customer-portal",
            get(billing::redirect_to_customer_portal),
        )
        .layer(from_fn_with_state(
            state.clone(),
            |state: State<AppState>, jar: CookieJar, req: Request<Body>, next: Next| async move {
                web_auth_middleware(state, jar, req, next).await
            },
        ));

    // Special routes (like webhooks) that need different handling
    #[cfg(feature = "official")]
    let webhook_routes =
        Router::new().route("/stripe-webhook", post(billing::handle_stripe_webhook));

    // Combine all routes
    #[cfg(feature = "official")]
    let app = Router::new()
        .merge(public_routes)
        .merge(web_routes)
        .merge(api_routes)
        .merge(official_routes)
        .merge(official_protected_routes)
        .merge(webhook_routes);

    #[cfg(not(feature = "official"))]
    let app = Router::new()
        .merge(public_routes)
        .merge(web_routes)
        .merge(api_routes);

    app.with_state(state)
}

async fn determine_root(state: axum::extract::State<AppState>) -> axum::response::Response {
    match database::has_any_users(&state.db).await {
        Ok(true) => axum::response::Redirect::to("/login").into_response(),
        Ok(false) => axum::response::Redirect::to("/register").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
