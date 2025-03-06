// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use crate::official::email;

#[tokio::test]
async fn test_password_reset_email() {
    let config = email::EmailConfig::from_env().unwrap();
    let result = email::send_password_reset_email(&config, "test@example.com", "test-token").await;
    assert!(result.is_ok());
}
