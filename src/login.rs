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

use actix_web::{http::header, web, HttpResponse, Responder};
use askama::Template;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{verify_user, AppState};

// For client app API
#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    password_hash: String,
    salt: String,
}

// For web interface
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub exp: usize,
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

pub const FUR_SECRET_KEY: &[u8] = b"fur-secret-key"; // TODO: Change

pub async fn login(data: web::Data<AppState>, login: web::Json<LoginRequest>) -> impl Responder {
    let user = match sqlx::query!(
        r#"
        SELECT password_hash, encryption_salt
        FROM users
        WHERE email = $1
        "#,
        login.email
    )
    .fetch_optional(&*data.db)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(json!({
                "error": "Invalid email or password"
            }))
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if !bcrypt::verify(&login.password, &user.password_hash).unwrap_or(false) {
        return HttpResponse::Unauthorized().json(json!({
            "error": "Invalid email or password"
        }));
    }

    // Just return hash and salt - no token
    let response = LoginResponse {
        password_hash: user.password_hash,
        salt: BASE64.encode(user.encryption_salt),
    };
    HttpResponse::Ok().json(response)
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
            let claims = Claims {
                sub: user_id,
                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };

            match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(FUR_SECRET_KEY),
            ) {
                Ok(token) => HttpResponse::Found()
                    .append_header((header::LOCATION, "/sync"))
                    .append_header((header::SET_COOKIE, format!("auth={}", token)))
                    .finish(),
                Err(_) => HttpResponse::Found()
                    .append_header((header::LOCATION, "/login?error=Internal server error"))
                    .finish(),
            }
        }
        Ok(None) => HttpResponse::Found()
            .append_header((header::LOCATION, "/login?error=Invalid email or password"))
            .finish(),
        Err(_) => HttpResponse::Found()
            .append_header((header::LOCATION, "/login?error=Internal server error"))
            .finish(),
    }
}
