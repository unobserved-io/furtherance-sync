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
    Form,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{database, AppState};

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
#[allow(dead_code)]
#[derive(Debug)]
pub struct TempRegistration {
    pub email: String,
    pub password_hash: String,
    pub verification_token: String,
}

fn is_valid_email(email: &str) -> bool {
    let email_regex = Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$").unwrap();
    !email.is_empty() && email_regex.is_match(email) && email.contains('.')
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
    // Email validation
    if !is_valid_email(&form.email) {
        let data = RegisterPageData {
            error_msg: Some("Enter a valid email address".to_string()),
            success_msg: None,
            #[cfg(feature = "official")]
            official: true,
        };
        return render_register_page(&state, data);
    }

    // Password length validation
    if form.password.len() < 8 {
        let data = RegisterPageData {
            error_msg: Some("Password must be at least 8 characters long".to_string()),
            success_msg: None,
            #[cfg(feature = "official")]
            official: true,
        };
        return render_register_page(&state, data);
    }

    // Unique email validation
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

    // Get Stripe payment URL from environment
    let stripe_base_url = match std::env::var("STRIPE_PAYMENT_URL") {
        Ok(url) => url,
        Err(_) => {
            return render_register_page(
                &state,
                RegisterPageData {
                    error_msg: Some("Error fetching STRIPE_PAYMENT_URL".to_string()),
                    success_msg: None,
                    official: true,
                },
            )
        }
    };

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
        "{}?prefilled_email={}&client_reference_id={}",
        stripe_base_url,
        urlencoding::encode(&form.email),
        urlencoding::encode(&verification_token),
    );

    Redirect::to(&stripe_url).into_response()
}
