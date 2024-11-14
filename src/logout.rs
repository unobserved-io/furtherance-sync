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

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::{auth, delete_user_token, login, models::AppState};

#[derive(Deserialize)]
pub struct LogoutRequest {
    device_id: String,
}

pub async fn log_out_client(
    data: web::Data<AppState>,
    logout_data: web::Json<LogoutRequest>,
    req: HttpRequest,
) -> HttpResponse {
    // Extract token from Authorization header
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(auth_str) => auth_str.replace("Bearer ", ""),
            Err(_) => return HttpResponse::Unauthorized().finish(),
        },
        None => return HttpResponse::Unauthorized().finish(),
    };

    // Verify token and get user_id
    let user_id = match auth::verify_access_token(&auth_header) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    let device_id_hash = login::hash_device_id(&logout_data.device_id);

    if let Err(e) = delete_user_token(&data.db, user_id, &device_id_hash).await {
        eprintln!("Error deleting user token: {}", e);
    }

    HttpResponse::Ok().into()
}
