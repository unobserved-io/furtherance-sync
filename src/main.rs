// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

mod auth;
mod database;
mod encryption;
mod login;
mod logout;
mod middleware;
mod models;
mod register;
mod routes;
mod sync;

#[cfg(feature = "official")]
mod official {
    pub mod billing;
    pub mod email;
    pub mod password_reset;
    pub mod tasks;
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod auth_tests;
    #[cfg(test)]
    mod common;
    #[cfg(feature = "official")]
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

use handlebars::Handlebars;
use models::AppState;
use routes::configure_routes;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{self, EnvFilter};

#[cfg(feature = "official")]
use official::email::EmailConfig;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_logger();

    info!("Starting Furtherance Sync v0.1.1");

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
    let _ = official::tasks::start_cleanup_task(pool.clone());

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
    hb.register_template_file("forgot-password", "templates/pages/forgot-password.hbs")
        .map_err(to_io_error)?;
    hb.register_template_file("reset-password", "templates/pages/reset-password.hbs")
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

    let server = "0.0.0.0:8662";

    let listener = tokio::net::TcpListener::bind(&server).await?;
    info!("Server running on {}", &server);

    let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();

    axum::serve(listener, service).await?;
    Ok(())
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("furtherance_sync=info".parse().unwrap())
                .add_directive(tracing::Level::ERROR.into()),
            // .add_directive("sqlx=info".parse().unwrap())
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
