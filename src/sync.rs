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

use crate::{
    auth::verify_access_token,
    database::*,
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
    headers: axum::http::HeaderMap,
    Json(sync_data): Json<SyncRequest>,
) -> Response {
    // Extract token from Authorization header
    let auth_header = match headers.get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(auth_str) => auth_str.replace("Bearer ", ""),
            Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
        },
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Verify token and get user_id
    let user_id = match verify_access_token(&auth_header) {
        Ok(id) => id,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Get refresh token for this device
    let refresh_token = match fetch_refresh_token(&state.db, user_id, &sync_data.device_id).await {
        Ok(Some(token)) => token,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            error!("Error getting refresh token: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let server_timestamp = chrono::Utc::now().timestamp();

    // TODO: Check later if these actually make a difference
    let mut task_ids_updated: Vec<&str> = Vec::new();
    let mut shortcut_ids_updated: Vec<&str> = Vec::new();

    // Process incoming tasks
    for encrypted_task in &sync_data.tasks {
        if let Err(e) = insert_task(&state.db, encrypted_task, user_id, &refresh_token).await {
            error!("Error processing task: {}", e);
        } else {
            task_ids_updated.push(&encrypted_task.uid);
        }
    }

    // Process incoming shortcuts
    for encrypted_shortcut in &sync_data.shortcuts {
        if let Err(e) =
            insert_shortcut(&state.db, encrypted_shortcut, user_id, &refresh_token).await
        {
            error!("Error processing shortcut: {}", e);
        } else {
            shortcut_ids_updated.push(&encrypted_shortcut.uid);
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

    // TODO: Remove
    println!("{} Client tasks received", sync_data.tasks.len());
    println!("{} Client shortcuts received", sync_data.shortcuts.len());

    let response = SyncResponse {
        server_timestamp,
        tasks: tasks_to_send,
        shortcuts: shortcuts_to_send,
        orphaned_tasks,
        orphaned_shortcuts,
    };

    // TODO: Check if task_id_update or shortcut_ids_updated matches any of the tasks to send. If so, will need to remove them before sending.

    println!("{} tasks sent", response.tasks.len());
    println!("{} shortcuts sent", response.shortcuts.len());
    println!("{} orphaned tasks sent", response.orphaned_tasks.len());
    println!(
        "{} orphaned shortcuts sent",
        response.orphaned_shortcuts.len()
    );

    StatusCode::OK.into_response()
}
