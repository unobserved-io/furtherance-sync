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
    body::Body,
    http::{Request, Response, StatusCode},
};
use tower::ServiceExt;

use crate::tests::common;

async fn get_html_response(response: Response<Body>) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    (status, html)
}

#[tokio::test]
async fn test_email_validation() {
    let app = common::setup_test_router().await;

    let invalid_emails = vec![
        "notanemail",
        "missing@tld",
        "@nodomain.com",
        "spaces in@email.com",
        "",
    ];

    for invalid_email in invalid_emails {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "email={}&password=validpassword123",
                        invalid_email
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Don't follow redirects, just get the response
        let (status, html) = get_html_response(response).await;

        // Successful validation errors should return 200 OK with error message
        assert_eq!(
            status,
            StatusCode::OK,
            "Expected 200 status code for invalid email: {}",
            invalid_email
        );
        assert!(
            html.contains("Enter a valid email address"),
            "Failed to validate invalid email: {}. Response HTML: {}",
            invalid_email,
            html
        );
    }
}

#[tokio::test]
async fn test_password_length_validation() {
    let app = common::setup_test_router().await;

    let invalid_passwords = vec!["", "1234", "short", "7chars"];

    for invalid_password in invalid_passwords {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "email=test@example.com&password={}",
                        invalid_password
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (_, html) = get_html_response(response).await;
        assert!(
            html.contains("Password must be at least 8 characters long"),
            "Failed to validate short password: {}",
            invalid_password
        );
    }
}

#[tokio::test]
async fn test_duplicate_email_validation() {
    let app = common::setup_test_router().await;
    let test_email = "duplicate@example.com";
    let valid_password = "password123";

    // First registration should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email={}&password={}",
                    test_email, valid_password
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    let (status, _) = get_html_response(response).await;
    assert!(
        status == StatusCode::SEE_OTHER || status == StatusCode::OK,
        "Expected either 303 (self hosted) or 200 (official) status code"
    );

    // Second registration with same email should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email={}&password={}",
                    test_email, valid_password
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    let (_, html) = get_html_response(response).await;
    assert!(html.contains("Email already registered"));
}

#[tokio::test]
async fn test_successful_registration() {
    let app = common::setup_test_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("email=newuser@example.com&password=password123"))
                .unwrap(),
        )
        .await
        .unwrap();

    #[allow(unused_variables)]
    let headers = response.headers().clone();
    let (status, _html) = get_html_response(response).await;

    #[cfg(feature = "official")]
    {
        assert_eq!(
            status,
            StatusCode::OK,
            "Official build should return OK status"
        );
    }

    #[cfg(not(feature = "official"))]
    {
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Self-hosted build should redirect to login page"
        );

        let location = headers
            .get("location")
            .and_then(|l| l.to_str().ok())
            .expect("Should have a location header");

        assert!(location.contains("/login"), "Should redirect to login page");
        assert!(
            location.contains("message=Registration%20successful"),
            "Should include success message"
        );
    }
}
