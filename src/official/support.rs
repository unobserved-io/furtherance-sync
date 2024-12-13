// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use std::env;

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use serde::Serialize;

use crate::models::AppState;

#[derive(Serialize)]
struct SupportPageData {
    title: String,
    active_page: String,
    support_email: String,
    simplex_link: String,
    simplex_qr_path: String,
}

pub async fn show_support(State(state): State<AppState>) -> impl IntoResponse {
    let support_email =
        env::var("SUPPORT_EMAIL").unwrap_or("Contact details not available".to_string());
    let simplex_link = env::var("SIMPLEX_LINK").unwrap_or("Link not available".to_string());
    let simplex_qr_path =
        env::var("SIMPLEX_QR_PATH").unwrap_or("/static/placeholder-qr.svg".to_string());

    let data = SupportPageData {
        title: "Support".to_string(),
        active_page: "support".to_string(),
        support_email,
        simplex_link,
        simplex_qr_path,
    };

    match state.hb.render("support", &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            tracing::error!("Template error: {}", err);
            Html(format!("Error: {}", err)).into_response()
        }
    }
}
