// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
