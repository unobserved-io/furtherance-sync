// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use std::sync::Arc;

use crate::{database, models::AppState, routes::configure_routes};
use handlebars::Handlebars;
use sqlx::PgPool;

#[cfg(feature = "official")]
use crate::official::email::EmailConfig;

use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct TestApp {
    pub address: String,
}

impl TestApp {
    pub async fn new() -> TestApp {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind random port");
        let address = listener.local_addr().unwrap().to_string();

        let app_state = setup_test_state().await;
        let app = configure_routes(app_state);

        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );

        tokio::spawn(async move {
            server.await.unwrap();
        });

        TestApp {
            address: format!("http://{}", address),
        }
    }
}

// Helper function to create test database connection
async fn setup_test_db() -> PgPool {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for tests");

    let pool = PgPool::connect(&database_url).await.unwrap();

    // Initialize server key
    database::ensure_server_key(&pool).await.unwrap();

    pool
}

// Helper to create test app state
pub async fn setup_test_state() -> AppState {
    let db = setup_test_db().await;

    let mut hb = Handlebars::new();
    // Register minimal templates needed for tests
    hb.register_template_string("base", include_str!("../../templates/layouts/base.hbs"))
        .unwrap();
    hb.register_template_string(
        "register",
        include_str!("../../templates/pages/register.hbs"),
    )
    .unwrap();
    hb.register_template_string("login", include_str!("../../templates/pages/login.hbs"))
        .unwrap();
    hb.register_template_string("error", include_str!("../../templates/error.hbs"))
        .unwrap();

    AppState {
        db: Arc::new(db),
        hb: Arc::new(hb),
        #[cfg(feature = "official")]
        email_config: Arc::new(EmailConfig::from_env().unwrap()),
    }
}
