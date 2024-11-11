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

mod auth;
mod database;
mod encryption;
mod login;
mod models;
mod register;
mod sync;

use actix_web::{web, App, HttpServer};
use database::*;
use encryption::{generate_key, show_encryption_setup};
use login::*;
use models::AppState;
use register::*;
use std::sync::Arc;
use sync::{get_orphaned_items, handle_sync};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = db_init().await.expect("Failed to initialize database");
    let app_state = web::Data::new(AppState { db: Arc::new(pool) });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            // Web interface routes
            .route("/", web::get().to(show_login))
            .route("/login", web::get().to(show_login))
            .route("/login", web::post().to(handle_login_form))
            .route("/register", web::get().to(show_register))
            .route("/register", web::post().to(handle_register_form))
            .route("/encryption", web::get().to(show_encryption_setup))
            .route("/sync", web::post().to(handle_sync))
            // API Routes
            .route("/api/encryption/generate", web::post().to(generate_key))
            .route("/api/login", web::post().to(login))
            .route("/api/orphaned", web::get().to(get_orphaned_items))
    })
    .bind("127.0.0.1:8662")?
    .run()
    .await
}
