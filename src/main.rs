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
mod email;
mod encryption;
mod login;
mod logout;
mod middleware;
mod models;
mod password_reset;
mod register;
mod routes;
mod sync;
mod tasks;

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod auth_tests;
    #[cfg(test)]
    mod billing_tests;
    #[cfg(test)]
    mod common;
    #[cfg(test)]
    mod email_tests;
    #[cfg(test)]
    mod encryption_tests;
    #[cfg(test)]
    mod middleware_tests;
    #[cfg(test)]
    mod registration_tests;
    #[cfg(test)]
    mod sync_tests;
}

#[cfg(feature = "official")]
mod billing;

use email::EmailConfig;
use handlebars::Handlebars;
use models::AppState;
use routes::configure_routes;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{self, EnvFilter};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_logger();
    let pool = match database::db_init().await {
        Ok(pool) => Arc::new(pool),
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database initialization failed: {}", e),
            ));
        }
    };

    // Start background tasks
    #[cfg(feature = "official")]
    let _ = tasks::start_cleanup_task(pool.clone());

    // Initialize Handlebars
    let mut hb = Handlebars::new();
    // Register templates
    hb.register_template_file("base", "templates/layouts/base.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("encryption", "templates/pages/encryption.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("login", "templates/pages/login.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("register", "templates/pages/register.hbs")
        .map_err(to_io_error)?;
    // Register partials
    hb.register_template_file("nav", "templates/partials/nav.hbs")
        .map_err(to_io_error)?;
    // Register error template
    hb.register_template_file("error", "templates/error.hbs")
        .map_err(to_io_error)?;
    let hb = Arc::new(hb);

    #[cfg(feature = "official")]
    let email_config = EmailConfig::from_env().expect("Failed to load email configuration");

    let state = AppState {
        db: pool,
        hb: hb.clone(),
        #[cfg(feature = "official")]
        email_config: Arc::new(email_config),
    };

    let router = configure_routes(state);

    let server = "127.0.0.1:8662";

    let listener = tokio::net::TcpListener::bind(&server).await?;
    info!("Server running on {}", &server);

    axum::serve(listener, router).await?;
    Ok(())
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
                .add_directive(tracing::Level::ERROR.into()),
            // .add_directive(tracing::Level::DEBUG.into()),
        )
        .init();
}

fn to_io_error<E>(err: E) -> std::io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
