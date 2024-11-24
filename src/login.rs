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

use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{auth, database, models::AppState};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    encryption_key: String,
    device_id: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginPageData {
    error_msg: Option<String>,
    success_msg: Option<String>,
    #[cfg(feature = "official")]
    official: bool,
}

pub async fn api_login(State(state): State<AppState>, Json(login): Json<LoginRequest>) -> Response {
    let (user_id, key_hash) = match database::fetch_user_credentials(&state.db, &login.email).await
    {
        Ok(Some(credentials)) => match credentials {
            (id, Some(hash)) => (id, hash),
            (_, None) => {
                return Json(serde_json::json!({
                    "error": "No encryption key found. Generate a key."
                }))
                .into_response();
            }
        },
        Ok(None) => {
            return Json(serde_json::json!({
                "error": "Invalid email or encryption key"
            }))
            .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if !bcrypt::verify(&login.encryption_key, &key_hash).unwrap_or(false) {
        return Json(serde_json::json!({
            "error": "Invalid email or encryption key"
        }))
        .into_response();
    }

    let access_token = match auth::generate_access_token(user_id) {
        Ok(token) => token,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body("Internal Server Error".to_string())
                .unwrap()
                .into_response()
        }
    };
    let refresh_token = auth::generate_refresh_token();
    let device_id_hash = crate::login::hash_device_id(&login.device_id);

    if let Err(_) =
        database::store_user_token(&state.db, user_id, &refresh_token, &device_id_hash).await
    {
        return Response::builder()
            .status(500)
            .body("Internal Server Error".to_string())
            .unwrap()
            .into_response();
    }

    Json(LoginResponse {
        access_token,
        refresh_token,
    })
    .into_response()
}

pub async fn show_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // If already logged in, redirect to encryption page
    if jar.get("session").is_some() {
        return Redirect::to("/encryption").into_response();
    }

    let error_msg = match params.get("message").map(|s| s.as_str()) {
        Some("session_expired") => {
            Some("Your session has expired. Please log in again.".to_string())
        }
        _ => None,
    };

    let success_msg = match params.get("message").map(|s| s.as_str()) {
        Some("registration_success") => Some("Registration successful! Please log in.".to_string()),
        Some("password_reset") => Some("Password reset. Please log in.".to_string()),
        Some("logout_success") => Some("You have been logged out.".to_string()),
        _ => None,
    };

    let data = LoginPageData {
        error_msg,
        success_msg,
        #[cfg(feature = "official")]
        official: true,
    };

    match state.hb.render("login", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn handle_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    match database::verify_user(&state.db, &form.email, &form.password).await {
        Ok(Some(user_id)) => {
            let mut cookie = Cookie::new("session", user_id.to_string());
            cookie.set_path("/");
            cookie.set_secure(true);
            cookie.set_http_only(true);

            let jar = jar.add(cookie);
            (jar, Redirect::to("/encryption")).into_response()
        }
        Ok(None) => {
            let data = LoginPageData {
                error_msg: Some("Invalid email or password".to_string()),
                success_msg: None,
                #[cfg(feature = "official")]
                official: true,
            };

            match state.hb.render("login", &data) {
                Ok(html) => Html(html).into_response(),
                Err(err) => {
                    error!("Template error: {}", err);
                    Html(format!("Error: {}", err)).into_response()
                }
            }
        }
        Err(err) => {
            error!("Login error: {}", err);
            let data = LoginPageData {
                error_msg: Some("An error occurred. Please try again.".to_string()),
                success_msg: None,
                #[cfg(feature = "official")]
                official: true,
            };

            match state.hb.render("login", &data) {
                Ok(html) => Html(html).into_response(),
                Err(err) => {
                    error!("Template error: {}", err);
                    Html(format!("Error: {}", err)).into_response()
                }
            }
        }
    }
}

pub fn hash_device_id(device_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(device_id.as_bytes());
    hasher.finalize().to_hex().to_string()
}
