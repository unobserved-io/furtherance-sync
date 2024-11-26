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

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use handlebars::Handlebars;
use sqlx::PgPool;
use tower::ServiceExt;

use crate::email::EmailConfig;
use crate::models::AppState;
use crate::routes::configure_routes;
use crate::tests::common::test_app;

#[tokio::test]
async fn test_login_message_sanitization() {
    let app = test_app().await;

    // Test invalid message
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login?message=invalid_message")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect (either 302 Found or 303 See Other)
    assert!(response.status().is_redirection());

    // Test valid message
    let response = app
        .oneshot(
            Request::builder()
                .uri("/login?message=session_expired")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be successful (200)
    assert_eq!(response.status(), StatusCode::OK);
}