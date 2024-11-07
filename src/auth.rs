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

use std::error::Error;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACCESS_TOKEN_DURATION: i64 = 30 * 24 * 60 * 60; // 30 days

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32, // user_id
    pub exp: usize,
}

pub fn generate_access_token(user_id: i32) -> Result<String, Box<dyn Error>> {
    let secret_key = std::env::var("FUR_SECRET_KEY")
        .expect("FUR_SECRET_KEY must be set")
        .into_bytes();

    let expiration = (Utc::now() + Duration::seconds(ACCESS_TOKEN_DURATION)).timestamp() as usize;
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

pub fn verify_access_token(token: &str) -> Result<i32, Box<dyn Error>> {
    let secret_key = std::env::var("FUR_SECRET_KEY")
        .expect("FUR_SECRET_KEY must be set")
        .into_bytes();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret_key),
        &Validation::default(),
    )?;

    Ok(token_data.claims.sub)
}