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

use crate::{database, models::EncryptedTask, tests::common::setup_test_state};

#[tokio::test]
async fn test_task_sync() {
    let state = setup_test_state().await;
    let user_id = 1;
    let device_id = "test-device";

    let task = EncryptedTask {
        encrypted_data: "encrypted".to_string(),
        nonce: "nonce".to_string(),
        uid: "test-uid".to_string(),
        last_updated: 12345,
    };

    database::insert_task(&state.db, &task, user_id, device_id)
        .await
        .unwrap();

    // Verify task was stored
    let tasks = database::fetch_tasks_for_device(&state.db, user_id, device_id, 0)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].uid, task.uid);
}
