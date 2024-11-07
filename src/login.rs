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
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth, models::AppState, store_user_token, verify_user};

// use crate::{auth::Claims, verify_user, AppState};

// For client app API
#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
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
    let user = match sqlx::query!(
        "SELECT id, password_hash FROM users WHERE email = $1",
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

    // Generate tokens
    let access_token = match auth::generate_access_token(user.id) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let refresh_token = auth::generate_refresh_token();
    let device_id_hash = match bcrypt::hash(&login.device_id, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if let Err(_) = store_user_token(&data.db, user.id, &refresh_token, &device_id_hash).await {
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
            let secret_key = std::env::var("FUR_SECRET_KEY")
                .expect("FUR_SECRET_KEY must be set")
                .into_bytes();

            let claims = auth::Claims {
                sub: user_id,
                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };

            match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(&secret_key),
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
