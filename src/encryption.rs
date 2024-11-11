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

use actix_web::{
    error::ErrorUnauthorized, http::header, web, Error, HttpRequest, HttpResponse, Responder,
};
use askama::Template;
use serde::Deserialize;

use crate::{database, models::AppState};

#[derive(Template)]
#[template(path = "encryption.html")]
struct EncryptionSetupTemplate {
    error_msg: Option<String>,
    success_msg: Option<String>,
    current_key: Option<String>,
}

impl EncryptionSetupTemplate {
    fn current_key_or_default(&self) -> String {
        self.current_key.clone().unwrap_or_default()
    }
}

#[derive(Deserialize)]
pub struct KeySetupForm {
    encryption_key: String,
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

    let current_key = match database::fetch_encryption_key(&data.db, user_id).await {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error fetching encryption key from database: {}", e);
            None
        }
    };

    let html = EncryptionSetupTemplate {
        error_msg,
        success_msg,
        current_key: current_key.map(|_| "Key is set".to_string()),
    }
    .render()
    .unwrap();

    HttpResponse::Ok().content_type("text/html").body(html)
}

pub async fn handle_key_setup(
    data: web::Data<AppState>,
    req: HttpRequest,
    form: web::Form<KeySetupForm>,
) -> impl Responder {
    let user_id = match verify_session(&req).await {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Found()
                .append_header((header::LOCATION, "/login"))
                .finish()
        }
    };

    // TODO: Remove depending on formatting
    // Remove any formatting from the key
    let clean_key = form.encryption_key.replace("-", "");

    let key_hash = match bcrypt::hash(&clean_key, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::Found()
                .append_header((header::LOCATION, "/encryption?error=Could not hash key"))
                .finish()
        }
    };

    match database::update_encryption_key(&data.db, user_id, &key_hash).await {
        Ok(_) => HttpResponse::Found()
            .append_header((
                header::LOCATION,
                "/encryption?message=Encryption key saved successfully",
            ))
            .finish(),
        Err(_) => HttpResponse::Found()
            .append_header((
                header::LOCATION,
                "/encryption?error=Could not save encryption key",
            ))
            .finish(),
    }
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
