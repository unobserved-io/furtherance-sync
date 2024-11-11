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

use actix_web::{
    error::ErrorUnauthorized, http::header, web, Error, HttpRequest, HttpResponse, Responder,
};
use askama::Template;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{database, models::AppState};

#[derive(Template)]
#[template(path = "encryption.html")]
struct EncryptionSetupTemplate {
    error_msg: Option<String>,
    success_msg: Option<String>,
    has_key: bool,
}

#[derive(Serialize)]
struct GenerateKeyResponse {
    key: String,
}

#[derive(Deserialize)]
pub struct GenerateConfirmation {
    pub confirmation: String,
}

pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    URL_SAFE_NO_PAD.encode(key)
}

pub async fn show_encryption_setup(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let user_id = match verify_session(&req).await {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Found()
                .append_header((header::LOCATION, "/login"))
                .finish()
        }
    };

    let query = web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .unwrap_or(web::Query(HashMap::new()));

    let error_msg = query.get("error").map(|e| e.to_string());
    let success_msg = query.get("message").map(|m| m.to_string());

    let has_key = database::fetch_encryption_key(&data.db, user_id)
        .await
        .map(|key| key.is_some())
        .unwrap_or(false);

    let html = EncryptionSetupTemplate {
        error_msg,
        success_msg,
        has_key,
    }
    .render()
    .unwrap();

    HttpResponse::Ok().content_type("text/html").body(html)
}

pub async fn generate_key(
    data: web::Data<AppState>,
    req: HttpRequest,
    confirmation: Option<web::Json<GenerateConfirmation>>,
) -> Result<impl Responder, Error> {
    let user_id = match verify_session(&req).await {
        Ok(id) => id,
        Err(_) => return Ok(HttpResponse::Unauthorized().finish()),
    };

    // Check if user already has a key
    let has_key = database::fetch_encryption_key(&data.db, user_id)
        .await
        .map(|key| key.is_some())
        .unwrap_or(false);

    // If user has a key, require confirmation
    if has_key {
        match confirmation {
            Some(conf) if conf.confirmation == "generate" => {}
            _ => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "confirmation_required",
                    "message": "Existing key found. Confirmation required."
                })));
            }
        }
    }

    let new_key = generate_encryption_key();
    let key_hash = bcrypt::hash(&new_key, bcrypt::DEFAULT_COST)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to hash key"))?;

    database::update_encryption_key(&data.db, user_id, &key_hash)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to update key"))?;

    Ok(HttpResponse::Ok().json(GenerateKeyResponse { key: new_key }))
}

async fn verify_session(req: &HttpRequest) -> Result<i32, Error> {
    let session_cookie = req
        .cookie("session")
        .ok_or_else(|| ErrorUnauthorized("No session cookie"))?;

    let user_id = session_cookie
        .value()
        .parse::<i32>()
        .map_err(|_| ErrorUnauthorized("Invalid session"))?;

    Ok(user_id)
}
