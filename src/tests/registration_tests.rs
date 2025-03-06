// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use axum::http::StatusCode;

use crate::tests::common;

#[tokio::test]
async fn test_email_validation() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    let invalid_emails = vec![
        "notanemail",
        "missing@tld",
        "@nodomain.com",
        "spaces in@email.com",
        "",
    ];

    for invalid_email in invalid_emails {
        let response = client
            .post(&format!("{}/register", app.address))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("email={}&password=validpassword123", invalid_email))
            .send()
            .await
            .unwrap();

        let html = response.text().await.unwrap();
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
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    let invalid_passwords = vec!["", "1234", "short", "7chars"];

    for invalid_password in invalid_passwords {
        let response = client
            .post(&format!("{}/register", app.address))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "email=test@example.com&password={}",
                invalid_password
            ))
            .send()
            .await
            .unwrap();

        let html = response.text().await.unwrap();
        assert!(
            html.contains("Password must be at least 8 characters long"),
            "Failed to validate short password: {}. Response HTML: {}",
            invalid_password,
            html
        );
    }
}

#[tokio::test]
async fn test_duplicate_email_validation() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();
    let test_email = "duplicate@example.com";
    let valid_password = "password123";

    // First registration should succeed
    let response = client
        .post(&format!("{}/register", app.address))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("email={}&password={}", test_email, valid_password))
        .send()
        .await
        .unwrap();

    let status = response.status();
    assert!(
        status == StatusCode::SEE_OTHER || status == StatusCode::OK,
        "Expected either 303 (self hosted) or 200 (official) status code"
    );

    // Second registration with same email should fail
    let response = client
        .post(&format!("{}/register", app.address))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("email={}&password={}", test_email, valid_password))
        .send()
        .await
        .unwrap();

    let html = response.text().await.unwrap();
    assert!(html.contains("Email already registered"));
}

#[tokio::test]
async fn test_successful_registration() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    let response = client
        .post(&format!("{}/register", app.address))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("email=newuser@example.com&password=password123")
        .send()
        .await
        .unwrap();

    let status = response.status();

    assert_eq!(status, StatusCode::OK);
}

#[cfg(feature = "official")]
#[tokio::test]
async fn test_password_requirements() {
    let app = common::TestApp::new().await;
    let client = reqwest::Client::new();

    let test_cases = vec![
        ("short", "Too short"),
        ("nouppercase123!", "No uppercase letter"),
        ("NOLOWERCASE123!", "No lowercase letter"),
        ("NoSpecialChars123", "No special character"),
        ("NoNumbers@Abcdefg", "No number"),
        ("Valid@Password123", "Valid password"),
    ];

    for (i, (password, description)) in test_cases.iter().enumerate() {
        let email = format!("test{}@example.com", i);

        let response = client
            .post(&format!("{}/register", app.address))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("email={}&password={}", email, password))
            .send()
            .await
            .unwrap();

        let html = response.text().await.unwrap();

        if password == &"Valid@Password123" {
            assert!(
                !html.contains("Password must be at least 8 characters"),
                "Valid password '{}' was rejected",
                description
            );
        } else {
            assert!(
                html.contains("Password must be at least 8 characters"),
                "Invalid password '{}' ({}) was not properly validated",
                password,
                description
            );
        }
    }
}
