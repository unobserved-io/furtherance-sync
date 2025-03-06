// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use tracing::error;

use crate::{database, login, middleware::AuthUser, AppState};

#[derive(Deserialize)]
pub struct LogoutRequest {
    device_id: String,
}

// Web interface logout
pub async fn handle_logout(AuthUser(_): AuthUser, jar: CookieJar) -> Response {
    // Remove the session cookie
    let mut removal_cookie = Cookie::new("session", "");
    removal_cookie.set_path("/");
    let jar = jar.remove(removal_cookie);

    (jar, Redirect::to("/login?message=logout_success")).into_response()
}

// API logout
pub async fn api_logout(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(logout_data): Json<LogoutRequest>,
) -> Response {
    let device_id_hash = login::hash_device_id(&logout_data.device_id);

    let refresh_token =
        match database::fetch_refresh_token(&state.db, user_id, &logout_data.device_id).await {
            Ok(Some(token)) => token,
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(e) => {
                error!("Error getting refresh token: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    if let Err(e) = database::delete_user_token(&state.db, user_id, &device_id_hash).await {
        error!("Error deleting user token: {}", e);
    }

    if let Err(e) = database::cleanup_device_tokens(&state.db, user_id, &[refresh_token]).await {
        error!("Error cleaning up device tokens: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "Successfully logged out"
    }))
    .into_response()
}
