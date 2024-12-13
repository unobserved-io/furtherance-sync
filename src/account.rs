// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{database, middleware::AuthUser, register, AppState};

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

#[derive(Deserialize)]
pub struct ChangeEmailForm {
    new_email: String,
    password: String,
}

#[derive(Serialize)]
struct AccountPageData {
    title: String,
    error_msg: Option<String>,
    success_msg: Option<String>,
    user_email: String,
    #[cfg(feature = "official")]
    official: bool,
}

pub async fn show_account(State(state): State<AppState>, AuthUser(user_id): AuthUser) -> Response {
    let user_email = match database::get_user_email(&state.db, user_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            error!("No user found for id: {}", user_id);
            return render_account_page(
                &state,
                user_id,
                Some("Unable to load account information"),
                None,
            )
            .await;
        }
        Err(e) => {
            error!("Database error fetching user email: {}", e);
            return render_account_page(
                &state,
                user_id,
                Some("Unable to load account information"),
                None,
            )
            .await;
        }
    };

    let data = AccountPageData {
        title: "Account Settings".to_string(),
        error_msg: None,
        success_msg: None,
        user_email,
        #[cfg(feature = "official")]
        official: true,
    };

    match state.hb.render("account", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}

pub async fn handle_change_password(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    // Check if passwords match
    if form.new_password != form.confirm_password {
        return render_account_page(&state, user_id, Some("New passwords do not match"), None)
            .await;
    }

    let verified =
        match database::verify_current_password(&state.db, user_id, &form.current_password).await {
            Ok(result) => result,
            Err(_) => {
                return render_account_page(&state, user_id, Some("Server error"), None).await
            }
        };

    if !verified {
        return render_account_page(&state, user_id, Some("Current password is incorrect"), None)
            .await;
    }

    #[cfg(feature = "official")]
    {
        if !crate::register::is_password_valid(&form.new_password) {
            return render_account_page(
                &state,
                user_id,
                Some("New password does not meet security requirements"),
                None,
            )
            .await;
        }
    }

    // Update password
    if let Err(_) = database::update_password(&state.db, user_id, &form.new_password).await {
        return render_account_page(&state, user_id, Some("Failed to update password"), None).await;
    }

    render_account_page(&state, user_id, None, Some("Password successfully updated")).await
}

pub async fn handle_change_email(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Form(form): Form<ChangeEmailForm>,
) -> Response {
    if !register::is_valid_email(&form.new_email) {
        return render_account_page(
            &state,
            user_id,
            Some("Please enter a valid email address"),
            None,
        )
        .await;
    }

    let verified = match database::verify_current_password(&state.db, user_id, &form.password).await
    {
        Ok(result) => result,
        Err(_) => return render_account_page(&state, user_id, Some("Server error"), None).await,
    };

    if !verified {
        return render_account_page(&state, user_id, Some("Current password is incorrect"), None)
            .await;
    }

    // Check if email is already registered
    if let Ok(Some(_)) = database::get_user_id_by_email(&state.db, &form.new_email).await {
        return render_account_page(&state, user_id, Some("Email is already registered"), None)
            .await;
    }

    #[cfg(feature = "official")]
    {
        // Generate and store email change token
        use uuid::Uuid;
        let token = Uuid::new_v4().to_string();

        if let Err(_) =
            database::store_email_change_token(&state.db, user_id, &form.new_email, &token).await
        {
            return render_account_page(
                &state,
                user_id,
                Some("Failed to initiate email change"),
                None,
            )
            .await;
        }

        // Send verification email
        if let Err(_) = crate::official::email::send_email_change_verification(
            &state.email_config,
            &form.new_email,
            &token,
        )
        .await
        {
            return render_account_page(
                &state,
                user_id,
                Some("Failed to send verification email"),
                None,
            )
            .await;
        }

        render_account_page(
            &state,
            user_id,
            None,
            Some("Please check your new email address for verification instructions"),
        )
        .await
    }

    #[cfg(feature = "self-hosted")]
    {
        // Direct email update for self-hosted version
        if let Err(_) = database::update_email(&state.db, user_id, &form.new_email).await {
            return render_account_page(&state, user_id, Some("Failed to update email"), None)
                .await;
        }

        render_account_page(&state, user_id, None, Some("Email successfully updated")).await
    }
}

async fn render_account_page(
    state: &AppState,
    user_id: i32,
    error_msg: Option<&str>,
    success_msg: Option<&str>,
) -> Response {
    // Now we can just await directly
    let user_email = match database::get_user_email(&state.db, user_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            error!("No user found for id: {}", user_id);
            String::from("Error loading email")
        }
        Err(e) => {
            error!("Database error fetching user email: {}", e);
            String::from("Error loading email")
        }
    };

    let data = AccountPageData {
        title: "Account Settings".to_string(),
        error_msg: error_msg.map(String::from),
        success_msg: success_msg.map(String::from),
        user_email,
        #[cfg(feature = "official")]
        official: true,
    };

    match state.hb.render("account", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}
