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

mod database;
mod login;
mod models;
mod register;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use database::*;
use login::*;
use models::{AppState, SyncRequest, SyncResponse};
use register::*;
use std::sync::Arc;
use uuid::Uuid;

async fn handle_sync(
    data: web::Data<AppState>,
    sync_data: web::Json<SyncRequest>,
) -> impl Responder {
    let user_id =
        match verify_user_hash(&*data.db, &sync_data.email, &sync_data.password_hash).await {
            Ok(Some(id)) => id,
            Ok(None) => return HttpResponse::Unauthorized().finish(),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

    let server_timestamp = chrono::Utc::now().timestamp();

    let mut task_ids_updated: Vec<Uuid> = Vec::new();
    let mut shortcut_ids_updated: Vec<Uuid> = Vec::new();

    println!("{} Client tasks received", sync_data.tasks.len());

    for encrypted_task in &sync_data.tasks {
        match get_task_by_uuid(&data.db, &encrypted_task.uuid, user_id).await {
            Ok(Some(server_task)) => {
                // Task exists - update it if it changed
                if encrypted_task.last_updated > server_task.last_updated {
                    match update_task(&data.db, &encrypted_task, user_id).await {
                        Ok(_) => task_ids_updated.push(encrypted_task.uuid),
                        Err(e) => eprintln!("Error updating task: {}", e),
                    }
                } else if encrypted_task.last_updated == server_task.last_updated {
                    // This task is up to date and does not need to be sent back to client
                    task_ids_updated.push(encrypted_task.uuid);
                }
            }
            Ok(None) => {
                // Task does not exist - insert it
                match insert_task(&data.db, &encrypted_task, user_id).await {
                    Ok(_) => task_ids_updated.push(encrypted_task.uuid),
                    Err(e) => eprintln!("Error inserting new task: {}", e),
                }
            }
            Err(e) => eprintln!("Error checking for existing task: {}", e),
        }
    }

    for encrypted_shortcut in &sync_data.shortcuts {
        match get_shortcut_by_uuid(&data.db, &encrypted_shortcut.uuid, user_id).await {
            Ok(Some(server_shortcut)) => {
                // Shortcut exists - update it if it changed
                if encrypted_shortcut.last_updated > server_shortcut.last_updated {
                    match update_shortcut(&data.db, &encrypted_shortcut, user_id).await {
                        Ok(_) => shortcut_ids_updated.push(encrypted_shortcut.uuid),
                        Err(e) => eprintln!("Error updating shortcut: {}", e),
                    }
                } else if encrypted_shortcut.last_updated == server_shortcut.last_updated {
                    // This shortcut is up to date and does not need to be sent back to client
                    shortcut_ids_updated.push(encrypted_shortcut.uuid);
                }
            }
            Ok(None) => {
                // Shortcut does not exist - insert it
                match insert_shortcut(&data.db, &encrypted_shortcut, user_id).await {
                    Ok(_) => shortcut_ids_updated.push(encrypted_shortcut.uuid),
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
            .filter(|task| !task_ids_updated.contains(&task.uuid))
            .collect(),
        shortcuts: new_shortcuts
            .into_iter()
            .filter(|shortcut| !shortcut_ids_updated.contains(&shortcut.uuid))
            .collect(),
    };

    println!("{} tasks sent", response.tasks.len());
    println!("{} shortcuts sent", response.shortcuts.len());

    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = db_init().await.expect("Failed to initialize database");
    let app_state = web::Data::new(AppState { db: Arc::new(pool) });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/", web::get().to(show_login))
            .route("/api/login", web::post().to(login))
            .route("/login", web::get().to(show_login))
            .route("/login", web::post().to(handle_login_form))
            .route("/register", web::get().to(show_register))
            .route("/register", web::post().to(handle_register_form))
            .route("/sync", web::post().to(handle_sync))
    })
    .bind("127.0.0.1:8662")?
    .run()
    .await
}
