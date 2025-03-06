// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use axum::http::StatusCode;

use crate::tests::common;

#[tokio::test]
async fn test_login_message_sanitization() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    // Test invalid message
    let response = client
        .get(&format!("{}/login?message=invalid_message", app.address))
        .send()
        .await
        .unwrap();

    // Should redirect to /login
    assert_eq!(response.url().to_string(), format!("{}/login", app.address));

    // Test valid message
    let response = client
        .get(&format!("{}/login?message=session_expired", app.address))
        .send()
        .await
        .unwrap();

    // Should be successful (200)
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_middleware() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    // Test protected route without auth
    let response = client
        .get(&format!("{}/api/sync", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test public route without auth
    let response = client
        .get(&format!("{}/login", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
