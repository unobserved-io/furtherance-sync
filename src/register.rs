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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::error;

#[cfg(feature = "official")]
use axum::extract::Query;

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
    #[cfg(feature = "official")]
    official: bool,
}

#[cfg(feature = "official")]
#[derive(Deserialize)]
pub struct RegistrationCompleteParams {
    token: String,
}

#[cfg(feature = "official")]
#[derive(Debug)]
pub struct TempRegistration {
    pub email: String,
    pub password_hash: String,
    pub verification_token: String,
}

#[derive(Serialize)]
struct StripeRegistrationData {
    email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
    verification_token: String, // To verify when returning from Stripe
}

#[derive(Serialize)]
struct StripeCheckoutResponse {
    checkout_url: String,
}

// Web interface handlers
pub async fn show_register(State(state): State<AppState>) -> impl IntoResponse {
    let data = RegisterPageData {
        error_msg: None,
        success_msg: None,
        #[cfg(feature = "official")]
        official: true,
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
            #[cfg(feature = "official")]
            official: true,
        };
        return render_register_page(&state, data);
    }

    if let Ok(Some(_)) = database::get_user_id_by_email(&state.db, &form.email).await {
        return render_register_page(
            &state,
            RegisterPageData {
                error_msg: Some("Email already registered".to_string()),
                success_msg: None,
                #[cfg(feature = "official")]
                official: true,
            },
        );
    }

    #[cfg(feature = "official")]
    {
        // Official version - handle Stripe registration flow
        handle_official_registration(state, form).await
    }

    #[cfg(not(feature = "official"))]
    {
        // Self-hosted version - direct registration
        match database::create_user(&state.db, &form.email, &form.password).await {
            Ok(_) => Redirect::to("/login?message=Registration successful").into_response(),
            Err(err) => {
                let error_msg = if err.to_string().contains("unique constraint") {
                    "Email already registered".to_string()
                } else {
                    "Registration failed. Please try again.".to_string()
                };

                render_register_page(
                    &state,
                    RegisterPageData {
                        error_msg: Some(error_msg),
                        success_msg: None,
                    },
                )
            }
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

#[cfg(feature = "official")]
async fn handle_official_registration(state: AppState, form: RegisterForm) -> Response {
    use uuid::Uuid;

    // Hash password early to avoid storing plaintext
    let password_hash = match bcrypt::hash(form.password.as_bytes(), bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return render_register_page(
                &state,
                RegisterPageData {
                    error_msg: Some("Error processing registration".to_string()),
                    success_msg: None,
                    official: true,
                },
            )
        }
    };

    // Generate verification token
    let verification_token = Uuid::new_v4().to_string();

    if let Err(_) = database::store_temporary_registration(
        &state.db,
        &form.email,
        &password_hash,
        &verification_token,
    )
    .await
    {
        return render_register_page(
            &state,
            RegisterPageData {
                error_msg: Some("Error processing registration".to_string()),
                success_msg: None,
                official: true,
            },
        );
    }

    // Construct Stripe payment link
    let stripe_url = format!(
        "https://buy.stripe.com/9AQdSY78F62CaZy3cc\
            ?prefilled_email={}\
            &client_reference_id={}\
            &success_url={}",
        urlencoding::encode(&form.email),
        urlencoding::encode(&verification_token),
        urlencoding::encode(&format!(
            "https://sync.furtherance.app/register/complete?token={}",
            verification_token
        ))
    );

    Redirect::to(&stripe_url).into_response()
}

#[cfg(feature = "official")]
pub async fn handle_registration_complete(
    State(state): State<AppState>,
    params: Query<RegistrationCompleteParams>,
) -> Response {
    let params: RegistrationCompleteParams = params.0;
    // Get the temporary registration data
    let temp_reg = match database::get_temporary_registration(&state.db, &params.token).await {
        Ok(Some(reg)) => reg,
        Ok(None) => return Redirect::to("/register?error=expired_token").into_response(),
        Err(e) => {
            error!("Database error: {}", e);
            return Redirect::to("/register?error=server_error").into_response();
        }
    };

    // Create the user account first
    if let Err(e) = database::create_user(&state.db, &temp_reg.email, &temp_reg.password_hash).await
    {
        error!("Failed to create user account: {}", e);
        return Redirect::to("/register?error=registration_failed").into_response();
    }

    // Then mark the registration as used
    if let Err(e) = database::mark_temp_registration_used(&state.db, &params.token).await {
        error!("Failed to mark temporary registration as used: {}", e);
        // Continue anyway as the user account was created
    }

    Redirect::to("/login?message=Registration successful").into_response()
}
