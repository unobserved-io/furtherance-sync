use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{database, middleware::AuthUser, AppState};

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    #[allow(dead_code)]
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
    active_page: String,
    error_msg: Option<String>,
    success_msg: Option<String>,
    #[cfg(feature = "official")]
    official: bool,
}

pub async fn show_account(State(state): State<AppState>, AuthUser(_): AuthUser) -> Response {
    let data = AccountPageData {
        title: "Account Settings".to_string(),
        active_page: "account".to_string(),
        error_msg: None,
        success_msg: None,
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
    let verified =
        match database::verify_current_password(&state.db, user_id, &form.current_password).await {
            Ok(result) => result,
            Err(_) => return render_account_page(&state, Some("Server error"), None),
        };

    if !verified {
        return render_account_page(&state, Some("Current password is incorrect"), None);
    }

    #[cfg(feature = "official")]
    {
        if !crate::register::is_password_valid(&form.new_password) {
            return render_account_page(
                &state,
                Some("New password does not meet security requirements"),
                None,
            );
        }
    }

    // Update password
    if let Err(_) = database::update_password(&state.db, user_id, &form.new_password).await {
        return render_account_page(&state, Some("Failed to update password"), None);
    }

    render_account_page(&state, None, Some("Password successfully updated"))
}

pub async fn handle_change_email(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Form(form): Form<ChangeEmailForm>,
) -> Response {
    let verified = match database::verify_current_password(&state.db, user_id, &form.password).await
    {
        Ok(result) => result,
        Err(_) => return render_account_page(&state, Some("Server error"), None),
    };

    if !verified {
        return render_account_page(&state, Some("Current password is incorrect"), None);
    }

    // Check if email is already registered
    if let Ok(Some(_)) = database::get_user_id_by_email(&state.db, &form.new_email).await {
        return render_account_page(&state, Some("Email is already registered"), None);
    }

    #[cfg(feature = "official")]
    {
        // Generate and store email change token
        use uuid::Uuid;
        let token = Uuid::new_v4().to_string();

        if let Err(_) =
            database::store_email_change_token(&state.db, user_id, &form.new_email, &token).await
        {
            return render_account_page(&state, Some("Failed to initiate email change"), None);
        }

        // Send verification email
        if let Err(_) = crate::official::email::send_email_change_verification(
            &state.email_config,
            &form.new_email,
            &token,
        )
        .await
        {
            return render_account_page(&state, Some("Failed to send verification email"), None);
        }

        render_account_page(
            &state,
            None,
            Some("Please check your new email address for verification instructions"),
        )
    }

    #[cfg(feature = "self-hosted")]
    {
        // Direct email update for self-hosted version
        if let Err(_) = database::update_email(&state.db, user_id, &form.new_email).await {
            return render_account_page(&state, Some("Failed to update email"), None);
        }

        render_account_page(&state, None, Some("Email successfully updated"))
    }
}

fn render_account_page(
    state: &AppState,
    error_msg: Option<&str>,
    success_msg: Option<&str>,
) -> Response {
    let data = AccountPageData {
        title: "Account Settings".to_string(),
        active_page: "account".to_string(),
        error_msg: error_msg.map(String::from),
        success_msg: success_msg.map(String::from),
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
