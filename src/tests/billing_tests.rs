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

use crate::{database, tests::common::setup_test_state};

#[tokio::test]
async fn test_subscription_status() {
    let state = setup_test_state().await;
    let user_id = 1;

    // Test inactive subscription
    let is_active = database::is_subscription_active(&state.db, user_id)
        .await
        .unwrap();
    assert!(!is_active);

    // Update subscription status
    database::update_subscription_status(&state.db, "customer_id", "active".to_string())
        .await
        .unwrap();

    // Test active subscription
    let is_active = database::is_subscription_active(&state.db, user_id)
        .await
        .unwrap();
    assert!(is_active);
}
