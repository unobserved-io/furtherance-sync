// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use crate::{database, encryption, tests::common::setup_test_state};

#[tokio::test]
async fn test_encryption_key_generation() {
    let key1 = encryption::generate_encryption_key();
    let key2 = encryption::generate_encryption_key();

    // Test keys are different
    assert_ne!(key1, key2);

    // Test key length (Base64 encoded 32-byte key)
    assert_eq!(key1.len(), 43);
}

#[tokio::test]
async fn test_encryption_key_update() {
    let state = setup_test_state().await;
    let user_id = 1;

    let initial_key = encryption::generate_encryption_key();
    let key_hash = bcrypt::hash(&initial_key, bcrypt::DEFAULT_COST).unwrap();
    database::update_encryption_key(&state.db, user_id, &key_hash)
        .await
        .unwrap();

    // Verify key was stored
    let stored_hash = database::fetch_encryption_key(&state.db, user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(bcrypt::verify(&initial_key, &stored_hash).unwrap());
}
