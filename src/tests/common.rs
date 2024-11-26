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

pub async fn test_app() -> Router {
    let db = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let mut hb = Handlebars::new();
    hb.register_template_file("login", "templates/pages/login.hbs")
        .unwrap();
    // Register other required templates

    let app_state = AppState {
        db: Arc::new(db),
        hb: Arc::new(hb),
        #[cfg(feature = "official")]
        email_config: Arc::new(EmailConfig::from_env().unwrap()),
    };

    configure_routes(app_state)
}
