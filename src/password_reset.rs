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
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::error;
use uuid::Uuid;

use crate::{database, email, AppState};

#[derive(Serialize)]
struct ForgotPasswordPageData {
    error_msg: Option<String>,
    success_msg: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    token: String,
    password: String,
    #[allow(dead_code)]
    confirm_password: String,
}

#[derive(Serialize)]
struct ResetPasswordPageData {
    error_msg: Option<String>,
    success_msg: Option<String>,
    token: Option<String>,
}

pub async fn show_forgot_password(State(state): State<AppState>) -> impl IntoResponse {
    let data = ForgotPasswordPageData {
        error_msg: None,
        success_msg: None,
    };

    match state.hb.render("forgot-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn handle_forgot_password(
    State(state): State<AppState>,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let user_id = match database::get_user_id_by_email(&state.db, &form.email).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            // Don't reveal if email exists
            return render_success_page(&state);
        }
        Err(e) => {
            error!("Database error: {}", e);
            return render_error_page(&state, "An error occurred. Please try again.");
        }
    };

    // Generate reset token
    let token = Uuid::new_v4().to_string();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    if let Err(e) = database::store_reset_token(&state.db, user_id, &token, expires_at).await {
        error!("Failed to store reset token: {}", e);
        return render_error_page(&state, "An error occurred. Please try again.");
    }

    // Send the reset email
    if let Err(e) = email::send_password_reset_email(&state.email_config, &form.email, &token).await
    {
        error!("Failed to send reset email: {}", e);
        // Don't expose email sending failure to user
        return render_success_page(&state);
    }

    render_success_page(&state)
}

fn render_success_page(state: &AppState) -> Response {
    let data = ForgotPasswordPageData {
        error_msg: None,
        success_msg: Some(
            "If an account exists with this email, you will receive a password reset link shortly."
                .to_string(),
        ),
    };

    match state.hb.render("forgot-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

fn render_error_page(state: &AppState, error: &str) -> Response {
    let data = ForgotPasswordPageData {
        error_msg: Some(error.to_string()),
        success_msg: None,
    };

    match state.hb.render("forgot-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn show_reset_password(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let token = params.get("token").cloned();

    let data = ResetPasswordPageData {
        error_msg: None,
        success_msg: None,
        token,
    };

    match state.hb.render("reset-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn handle_reset_password(
    State(state): State<AppState>,
    Form(form): Form<ResetPasswordForm>,
) -> Response {
    let user_id = match database::verify_reset_token(&state.db, &form.token).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return render_reset_error_page(&state, "Invalid or expired reset token");
        }
        Err(e) => {
            error!("Database error: {}", e);
            return render_reset_error_page(&state, "An error occurred. Please try again.");
        }
    };

    if let Err(e) = database::update_password(&state.db, user_id, &form.password).await {
        error!("Failed to update password: {}", e);
        return render_reset_error_page(&state, "Failed to update password");
    }

    if let Err(e) = database::mark_reset_token_used(&state.db, &form.token).await {
        error!("Failed to mark token as used: {}", e);
    }

    let data = ResetPasswordPageData {
        error_msg: None,
        success_msg: Some("Your password has been successfully reset.".to_string()),
        token: None,
    };

    match state.hb.render("reset-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

fn render_reset_error_page(state: &AppState, error: &str) -> Response {
    let data = ResetPasswordPageData {
        error_msg: Some(error.to_string()),
        success_msg: None,
        token: None,
    };

    match state.hb.render("reset-password", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}
