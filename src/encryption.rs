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
    extract::{Json, State},
    response::{Html, IntoResponse},
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{database, middleware::AuthUser, AppState};

#[derive(Serialize)]
struct EncryptionPageData {
    title: String,
    active_page: String,
    has_key: bool,
    error_msg: Option<String>,
    success_msg: Option<String>,
    #[cfg(feature = "official")]
    official: bool,
}

#[derive(Deserialize)]
pub struct GenerateConfirmation {
    pub confirmation: String,
}

#[derive(Serialize)]
pub struct GenerateKeyResponse {
    key: String,
}

pub async fn show_encryption(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> impl IntoResponse {
    let has_key = database::fetch_encryption_key(&state.db, user_id)
        .await
        .map(|key| key.is_some())
        .unwrap_or(false);

    let data = EncryptionPageData {
        title: "Encryption Setup".to_string(),
        active_page: "encryption".to_string(),
        has_key,
        error_msg: None,
        success_msg: None,
        #[cfg(feature = "official")]
        official: true,
    };

    match state.hb.render("encryption", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(render_error(&state, "Template error")).into_response()
        }
    }
}

pub async fn generate_key(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    confirmation: Option<Json<GenerateConfirmation>>,
) -> Json<serde_json::Value> {
    let has_key = database::fetch_encryption_key(&state.db, user_id)
        .await
        .map(|key| key.is_some())
        .unwrap_or(false);

    // If user has a key, require confirmation
    if has_key {
        match confirmation {
            Some(conf) if conf.confirmation == "generate" => {}
            _ => {
                return Json(serde_json::json!({
                    "error": "confirmation_required",
                    "message": "Existing key found. Confirmation required."
                }));
            }
        }
    }

    let new_key = crate::encryption::generate_encryption_key();
    let key_hash = match bcrypt::hash(&new_key, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return Json(serde_json::json!({
                "error": "server_error",
                "message": "Failed to hash key"
            }))
        }
    };

    if let Err(_) = database::update_encryption_key(&state.db, user_id, &key_hash).await {
        return Json(serde_json::json!({
            "error": "server_error",
            "message": "Failed to update key"
        }));
    }

    Json(serde_json::json!({
        "key": new_key
    }))
}

fn render_error(state: &AppState, error: &str) -> String {
    let data = serde_json::json!({
        "title": "Error",
        "error_msg": error,
    });

    state
        .hb
        .render("error", &data)
        .unwrap_or_else(|_| format!("Error: {}", error))
}

pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    BASE64_URL_SAFE_NO_PAD.encode(key)
}
