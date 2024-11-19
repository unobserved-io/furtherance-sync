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
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{database, AppState};

// API registration structures
#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    user_id: i32,
    message: String,
}

// Web interface registration structures
#[derive(Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterPageData {
    error_msg: Option<String>,
    success_msg: Option<String>,
}

// Web interface handlers
pub async fn show_register(State(state): State<AppState>) -> impl IntoResponse {
    let data = RegisterPageData {
        error_msg: None,
        success_msg: None,
    };

    match state.hb.render("register", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn handle_register(
    State(state): State<AppState>,
    Form(form): Form<RegisterForm>,
) -> Response {
    // Basic validation
    if form.password.len() < 8 {
        let data = RegisterPageData {
            error_msg: Some("Password must be at least 8 characters long".to_string()),
            success_msg: None,
        };
        return render_register_page(&state, data);
    }

    match database::create_user(&state.db, &form.email, &form.password).await {
        Ok(_) => {
            // Redirect to login page with success message
            Redirect::to("/login?message=Registration successful").into_response()
        }
        Err(err) => {
            let error_msg = if err.to_string().contains("unique constraint") {
                "Email already registered".to_string()
            } else {
                "Registration failed. Please try again.".to_string()
            };

            let data = RegisterPageData {
                error_msg: Some(error_msg),
                success_msg: None,
            };
            render_register_page(&state, data)
        }
    }
}

// API registration handler
pub async fn api_register(
    State(state): State<AppState>,
    Json(register): Json<RegisterRequest>,
) -> Response {
    // Basic validation
    if register.password.len() < 8 {
        return Json(serde_json::json!({
            "error": "Password must be at least 8 characters long"
        }))
        .into_response();
    }

    match database::create_user(&state.db, &register.email, &register.password).await {
        Ok(user_id) => Json(RegisterResponse {
            user_id,
            message: "Registration successful".to_string(),
        })
        .into_response(),
        Err(err) => {
            let error_msg = if err.to_string().contains("unique constraint") {
                "Email already registered"
            } else {
                "Registration failed"
            };
            Json(serde_json::json!({
                "error": error_msg
            }))
            .into_response()
        }
    }
}

fn render_register_page(state: &AppState, data: RegisterPageData) -> Response {
    match state.hb.render("register", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}
