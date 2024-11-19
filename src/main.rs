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
mod logout;
mod models;
mod register;
mod routes;
mod sync;

use actix_web::{web, App, HttpServer};
use models::AppState;
use std::sync::Arc;
use tracing::error;
use tracing_subscriber::{self, EnvFilter};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_logger();
    let pool = match database::db_init().await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database initialization failed: {}", e),
            ));
        }
    };
    let app_state = web::Data::new(AppState { db: Arc::new(pool) });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .configure(routes::configure_routes)
    })
    .bind("127.0.0.1:8662")?
    .run()
    .await
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
                .add_directive(tracing::Level::ERROR.into()),
        )
        .init();
}
