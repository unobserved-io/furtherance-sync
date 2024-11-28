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
