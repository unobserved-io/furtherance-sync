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

use std::sync::Arc;

use crate::{email::EmailConfig, models::AppState, routes::configure_routes};
use axum::Router;
use handlebars::Handlebars;
use sqlx::PgPool;

// Helper function to create test database connection
async fn setup_test_db() -> PgPool {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for tests");
    PgPool::connect(&database_url).await.unwrap()
}

// Helper to create test app state
pub async fn setup_test_state() -> AppState {
    let db = setup_test_db().await;
    let mut hb = Handlebars::new();
    // Register minimal templates needed for tests
    hb.register_template_string(
        "register",
        include_str!("../../templates/pages/register.hbs"),
    )
    .unwrap();
    hb.register_template_string("login", include_str!("../../templates/pages/login.hbs"))
        .unwrap();
    hb.register_template_string("error", include_str!("../../templates/error.hbs"))
        .unwrap();
    // hb.register_template_string("error", "templates/error.hbs")
    //     .unwrap();
    // hb.register_template_string("encryption", "templates/pages/encryption.hbs")
    //     .unwrap();
    // hb.register_template_string("login", "templates/pages/login.hbs")
    //     .unwrap();
    // hb.register_template_string("nav", "templates/pages/nav.hbs")
    //     .unwrap();
    // hb.register_template_string("register", "templates/pages/register.hbs")
    //     .unwrap();

    AppState {
        db: Arc::new(db),
        hb: Arc::new(hb),
        #[cfg(feature = "official")]
        email_config: Arc::new(EmailConfig::from_env().unwrap()),
    }
}

pub async fn setup_test_router() -> Router {
    let app_state = setup_test_state().await;

    configure_routes(app_state)
}
