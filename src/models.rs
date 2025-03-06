// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

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
