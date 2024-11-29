// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use crate::{auth, tests::common::setup_test_state};

#[tokio::test]
async fn test_refresh_token_uniqueness() {
    let token1 = auth::generate_refresh_token();
    let token2 = auth::generate_refresh_token();
    assert_ne!(token1, token2);
}

#[tokio::test]
async fn test_token_generation_and_verification() {
    let state = setup_test_state().await;
    let user_id = 1;
    let token = auth::generate_access_token(&state.db, user_id)
        .await
        .unwrap();
    let verified_id = auth::verify_access_token(&state.db, &token).await.unwrap();
    assert_eq!(user_id, verified_id);
}
