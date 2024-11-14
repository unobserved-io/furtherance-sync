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
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SyncRequest {
    last_sync: i64,
    tasks: Vec<EncryptedTask>,
    shortcuts: Vec<EncryptedShortcut>,
}

#[derive(Serialize, Deserialize)]
struct SyncResponse {
    server_timestamp: i64,
    tasks: Vec<EncryptedTask>,
    shortcuts: Vec<EncryptedShortcut>,
}

#[derive(Serialize)]
struct OrphanedItemsResponse {
    task_uids: Vec<String>,
    shortcut_uids: Vec<String>,
}

pub async fn get_orphaned_items(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    // Extract and verify token (same as in handle_sync)
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(auth_str) => auth_str.replace("Bearer ", ""),
            Err(_) => return HttpResponse::Unauthorized().finish(),
        },
        None => return HttpResponse::Unauthorized().finish(),
    };

    let user_id = match verify_access_token(&auth_header) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    // Fetch orphaned items from database
    let task_uids = match fetch_orphaned_task_uids(&data.db, user_id).await {
        Ok(uids) => uids,
        Err(e) => {
            eprintln!("Error fetching orphaned task UIDs: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let shortcut_uids = match fetch_orphaned_shortcut_uids(&data.db, user_id).await {
        Ok(uids) => uids,
        Err(e) => {
            eprintln!("Error fetching orphaned shortcut UIDs: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    HttpResponse::Ok().json(OrphanedItemsResponse {
        task_uids,
        shortcut_uids,
    })
}

pub async fn handle_sync(
    data: web::Data<AppState>,
    sync_data: web::Json<SyncRequest>,
    req: HttpRequest,
) -> impl Responder {
    // Extract token from Authorization header
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(auth_str) => auth_str.replace("Bearer ", ""),
            Err(_) => return HttpResponse::Unauthorized().finish(),
        },
        None => return HttpResponse::Unauthorized().finish(),
    };

    // Verify token and get user_id
    let user_id = match verify_access_token(&auth_header) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    let server_timestamp = chrono::Utc::now().timestamp();

    let mut task_ids_updated: Vec<&str> = Vec::new();
    let mut shortcut_ids_updated: Vec<&str> = Vec::new();

    // TODO: Remove
    println!("{} Client tasks received", sync_data.tasks.len());
    println!("{} Client shortcuts received", sync_data.shortcuts.len());

    for encrypted_task in &sync_data.tasks {
        match get_task_by_uid(&data.db, &encrypted_task.uid, user_id).await {
            Ok(Some((server_task, is_orphaned))) => {
                // Task exists - update it if it changed
                if is_orphaned || encrypted_task.last_updated > server_task.last_updated {
                    match update_task(&data.db, &encrypted_task, user_id).await {
                        Ok(_) => task_ids_updated.push(&encrypted_task.uid),
                        Err(e) => eprintln!("Error updating task: {}", e),
                    }
                } else if encrypted_task.last_updated == server_task.last_updated {
                    // This task is up to date and does not need to be sent back to client
                    task_ids_updated.push(&encrypted_task.uid);
                }
            }
            Ok(None) => {
                // Task does not exist - insert it
                match insert_task(&data.db, &encrypted_task, user_id).await {
                    Ok(_) => task_ids_updated.push(&encrypted_task.uid),
                    Err(e) => eprintln!("Error inserting new task: {}", e),
                }
            }
            Err(e) => eprintln!("Error checking for existing task: {}", e),
        }
    }

    for encrypted_shortcut in &sync_data.shortcuts {
        match get_shortcut_by_uid(&data.db, &encrypted_shortcut.uid, user_id).await {
            Ok(Some((server_shortcut, is_orphaned))) => {
                // Shortcut exists - update it if it changed
                if is_orphaned || encrypted_shortcut.last_updated > server_shortcut.last_updated {
                    match update_shortcut(&data.db, &encrypted_shortcut, user_id).await {
                        Ok(_) => shortcut_ids_updated.push(&encrypted_shortcut.uid),
                        Err(e) => eprintln!("Error updating shortcut: {}", e),
                    }
                } else if encrypted_shortcut.last_updated == server_shortcut.last_updated {
                    // This shortcut is up to date and does not need to be sent back to client
                    shortcut_ids_updated.push(&encrypted_shortcut.uid);
                }
            }
            Ok(None) => {
                // Shortcut does not exist - insert it
                match insert_shortcut(&data.db, &encrypted_shortcut, user_id).await {
                    Ok(_) => shortcut_ids_updated.push(&encrypted_shortcut.uid),
                    Err(e) => eprintln!("Error inserting new task: {}", e),
                }
            }
            Err(e) => eprintln!("Error checking for existing task: {}", e),
        }
    }

    // Fetch new or updated data since last_sync, but remove already updated data
    let new_tasks = fetch_new_tasks(&data.db, sync_data.last_sync, user_id)
        .await
        .unwrap_or_default();
    let new_shortcuts = fetch_new_shortcuts(&data.db, sync_data.last_sync, user_id)
        .await
        .unwrap_or_default();

    let response = SyncResponse {
        server_timestamp,
        tasks: new_tasks
            .into_iter()
            .filter(|task| !task_ids_updated.contains(&task.uid.as_str()))
            .collect(),
        shortcuts: new_shortcuts
            .into_iter()
            .filter(|shortcut| !shortcut_ids_updated.contains(&shortcut.uid.as_str()))
            .collect(),
    };

    println!("{} tasks sent", response.tasks.len());
    println!("{} shortcuts sent", response.shortcuts.len());

    HttpResponse::Ok().json(response)
}
