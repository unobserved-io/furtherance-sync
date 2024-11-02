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

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct EncryptedShortcut {
    pub encrypted_data: String,
    pub nonce: String,
    pub uuid: Uuid,
    pub last_updated: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedTask {
    pub encrypted_data: String,
    pub nonce: String,
    pub uuid: Uuid,
    pub last_updated: i64,
}

pub struct AppState {
    pub db: Arc<PgPool>,
}

#[derive(Deserialize)]
pub struct SyncRequest {
    pub email: String,
    pub password_hash: String,
    pub last_sync: i64,
    pub tasks: Vec<EncryptedTask>,
    pub shortcuts: Vec<EncryptedShortcut>,
}

#[derive(Serialize, Deserialize)]
pub struct SyncResponse {
    pub server_timestamp: i64,
    pub tasks: Vec<EncryptedTask>,
    pub shortcuts: Vec<EncryptedShortcut>,
}
