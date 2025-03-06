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

use std::error::Error;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use tracing::error;
use uuid::Uuid;

use crate::database;

const ACCESS_TOKEN_DURATION: Duration = Duration::days(30);

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32, // user_id
    pub exp: usize,
}

pub async fn generate_access_token(
    pool: &PgPool,
    user_id: i32,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let secret_key = get_server_key(pool).await?;

    let expiration = (OffsetDateTime::now_utc() + ACCESS_TOKEN_DURATION).unix_timestamp() as usize;
    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret_key),
    )?)
}

pub fn generate_refresh_token() -> String {
    Uuid::new_v4().to_string()
}

pub async fn verify_access_token(
    pool: &PgPool,
    token: &str,
) -> Result<i32, Box<dyn Error + Send + Sync>> {
    let secret_key = get_server_key(pool).await?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret_key),
        &Validation::default(),
    )?;

    Ok(token_data.claims.sub)
}

pub async fn get_server_key(pool: &PgPool) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    match database::fetch_server_key(pool).await {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("Failed to get server key from database: {}", e);
            Err(Box::new(e))
        }
    }
}
