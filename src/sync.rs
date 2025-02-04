// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use crate::{
    database::*,
    middleware::AuthUser,
    models::{AppState, EncryptedShortcut, EncryptedTask},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;

#[derive(Deserialize)]
pub struct SyncRequest {
    last_sync: i64,
    device_id: String,
    tasks: Vec<EncryptedTask>,
    shortcuts: Vec<EncryptedShortcut>,
}

#[derive(Serialize, Deserialize)]
struct SyncResponse {
    server_timestamp: i64,
    tasks: Vec<EncryptedTask>,
    shortcuts: Vec<EncryptedShortcut>,
    orphaned_tasks: Vec<String>,
    orphaned_shortcuts: Vec<String>,
}

pub async fn get_orphaned_items(pool: &PgPool, user_id: i32) -> (Vec<String>, Vec<String>) {
    // Fetch orphaned items from database
    let task_uids = match fetch_orphaned_task_uids(&pool, user_id).await {
        Ok(uids) => uids,
        Err(e) => {
            error!("Error fetching orphaned task UIDs: {}", e);
            Vec::new()
        }
    };

    let shortcut_uids = match fetch_orphaned_shortcut_uids(&pool, user_id).await {
        Ok(uids) => uids,
        Err(e) => {
            error!("Error fetching orphaned shortcut UIDs: {}", e);
            Vec::new()
        }
    };

    (task_uids, shortcut_uids)
}

pub async fn handle_sync(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(sync_data): Json<SyncRequest>,
) -> Response {
    // Get refresh token for this device
    let refresh_token = match fetch_refresh_token(&state.db, user_id, &sync_data.device_id).await {
        Ok(Some(token)) => token,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            error!("Error getting refresh token: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let server_timestamp = time::OffsetDateTime::now_utc().unix_timestamp();

    // Process incoming tasks
    for encrypted_task in &sync_data.tasks {
        if let Err(e) = insert_task(&state.db, encrypted_task, user_id, &refresh_token).await {
            error!("Error processing task: {}", e);
        }
    }

    // Process incoming shortcuts
    for encrypted_shortcut in &sync_data.shortcuts {
        if let Err(e) =
            insert_shortcut(&state.db, encrypted_shortcut, user_id, &refresh_token).await
        {
            error!("Error processing shortcut: {}", e);
        }
    }

    // Fetch unknown and updated items
    let tasks_to_send =
        match fetch_tasks_for_device(&state.db, user_id, &refresh_token, sync_data.last_sync).await
        {
            Ok(tasks) => tasks,
            Err(e) => {
                error!("Error fetching tasks: {}", e);
                Vec::new()
            }
        };

    let shortcuts_to_send =
        match fetch_shortcuts_for_device(&state.db, user_id, &refresh_token, sync_data.last_sync)
            .await
        {
            Ok(shortcuts) => shortcuts,
            Err(e) => {
                error!("Error fetching shortcuts: {}", e);
                Vec::new()
            }
        };

    // Get orphaned items
    let (orphaned_tasks, orphaned_shortcuts) = get_orphaned_items(&state.db, user_id).await;

    // Mark sent items as known by this device
    if !tasks_to_send.is_empty() {
        let task_uids: Vec<String> = tasks_to_send.iter().map(|t| t.uid.clone()).collect();
        if let Err(e) = mark_tasks_known(&state.db, &task_uids, user_id, &refresh_token).await {
            error!("Error marking tasks as known: {}", e);
        }
    }

    if !shortcuts_to_send.is_empty() {
        let shortcut_uids: Vec<String> = shortcuts_to_send.iter().map(|s| s.uid.clone()).collect();
        if let Err(e) =
            mark_shortcuts_known(&state.db, &shortcut_uids, user_id, &refresh_token).await
        {
            error!("Error marking shortcuts as known: {}", e);
        }
    }

    let response = SyncResponse {
        server_timestamp,
        tasks: tasks_to_send,
        shortcuts: shortcuts_to_send,
        orphaned_tasks,
        orphaned_shortcuts,
    };

    Json(response).into_response()
}
