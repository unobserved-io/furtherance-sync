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

use actix_web::{cookie::Cookie, http::header, web, HttpResponse, Responder};
use askama::Template;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth, database, models::AppState, store_user_token, verify_user};

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

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error_msg: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

pub async fn login(data: web::Data<AppState>, login: web::Json<LoginRequest>) -> impl Responder {
    let (user_id, key_hash) = match database::fetch_user_credentials(&data.db, &login.email).await {
        Ok(Some(credentials)) => match credentials {
            (id, Some(hash)) => (id, hash),
            (_, None) => {
                return HttpResponse::NotFound().json(json!({
                    "error": "No encryption key found. Generate a key."
                }))
            }
        },
        Ok(None) => {
            return HttpResponse::Unauthorized().json(json!({
                "error": "Invalid email or password"
            }))
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if !bcrypt::verify(&login.encryption_key, &key_hash).unwrap_or(false) {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Invalid email or encryption key"
        }));
    }

    // Generate tokens
    let access_token = match auth::generate_access_token(user_id) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let refresh_token = auth::generate_refresh_token();
    let device_id_hash = hash_device_id(&login.device_id);

    if let Err(_) = store_user_token(&data.db, user_id, &refresh_token, &device_id_hash).await {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().json(LoginResponse {
        access_token,
        refresh_token,
    })
}

pub async fn show_login(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let error_msg = query.get("error").map(|e| e.to_string());
    let html = LoginTemplate { error_msg }.render().unwrap();
    HttpResponse::Ok().content_type("text/html").body(html)
}

pub async fn handle_login_form(
    data: web::Data<AppState>,
    form: web::Form<LoginForm>,
) -> impl Responder {
    match verify_user(&data.db, &form.email, &form.password).await {
        Ok(Some(user_id)) => {
            // Create session cookie
            HttpResponse::Found()
                .cookie(
                    Cookie::build("session", user_id.to_string())
                        .http_only(true)
                        .secure(true)
                        .finish(),
                )
                .append_header((header::LOCATION, "/encryption"))
                .finish()
        }
        Ok(None) => HttpResponse::Found()
            .append_header((header::LOCATION, "/login?error=Invalid email or password"))
            .finish(),
        Err(_) => HttpResponse::Found()
            .append_header((header::LOCATION, "/login?error=Internal server error"))
            .finish(),
    }
}

pub fn hash_device_id(device_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(device_id.as_bytes());
    hasher.finalize().to_hex().to_string()
}
