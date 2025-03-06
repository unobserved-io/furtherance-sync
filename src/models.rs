// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::sync::Arc;

use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[cfg(feature = "official")]
use crate::official::email::EmailConfig;

#[derive(Serialize, Deserialize)]
pub struct EncryptedTask {
    pub encrypted_data: String,
    pub nonce: String,
    pub uid: String,
    pub last_updated: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedShortcut {
    pub encrypted_data: String,
    pub nonce: String,
    pub uid: String,
    pub last_updated: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedTodo {
    pub encrypted_data: String,
    pub nonce: String,
    pub uid: String,
    pub last_updated: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<PgPool>,
    pub hb: Arc<Handlebars<'static>>,
    #[cfg(feature = "official")]
    pub email_config: Arc<EmailConfig>,
}
