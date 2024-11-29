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

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

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
