// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

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
