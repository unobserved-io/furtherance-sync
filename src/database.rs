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

use rand::{thread_rng, RngCore};
use sqlx::postgres::PgPool;
use std::error::Error;
use uuid::Uuid;

use crate::models::{EncryptedShortcut, EncryptedTask};

pub async fn db_init() -> Result<PgPool, Box<dyn Error>> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url).await?;

    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            encryption_salt BYTEA NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );"#,
    )
    .execute(&pool)
    .await?;

    // Create tasks table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            encrypted_data TEXT NOT NULL,
            nonce TEXT NOT NULL,
            uuid UUID DEFAULT gen_random_uuid(),
            last_updated BIGINT,
            user_id INTEGER REFERENCES users(id),
            UNIQUE(user_id, uuid),
            PRIMARY KEY (user_id, uuid)
        );"#,
    )
    .execute(&pool)
    .await?;

    // Create shortcuts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shortcuts (
            encrypted_data TEXT NOT NULL,
            nonce TEXT NOT NULL,
            uuid UUID DEFAULT gen_random_uuid(),
            last_updated BIGINT,
            user_id INTEGER REFERENCES users(id),
            UNIQUE(user_id, uuid),
            PRIMARY KEY (user_id, uuid)
        );"#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn insert_task(
    pool: &PgPool,
    encrypted_task: &EncryptedTask,
    user_id: i32,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!(
        r#"
            INSERT INTO tasks (encrypted_data, nonce, uuid, last_updated, user_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        encrypted_task.encrypted_data,
        encrypted_task.nonce,
        encrypted_task.uuid,
        encrypted_task.last_updated,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_shortcut(
    pool: &PgPool,
    encrypted_shortcut: &EncryptedShortcut,
    user_id: i32,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!(
        r#"
            INSERT INTO shortcuts (encrypted_data, nonce, uuid, last_updated, user_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        encrypted_shortcut.encrypted_data,
        encrypted_shortcut.nonce,
        encrypted_shortcut.uuid,
        encrypted_shortcut.last_updated,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_task_by_uuid(
    pool: &PgPool,
    uuid: &Uuid,
    user_id: i32,
) -> Result<Option<EncryptedTask>, Box<dyn Error>> {
    let record = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uuid, last_updated
        FROM tasks WHERE uuid = $1 AND user_id = $2
        "#,
        uuid,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| EncryptedTask {
        encrypted_data: r.encrypted_data,
        nonce: r.nonce,
        uuid: r.uuid,
        last_updated: r.last_updated.unwrap_or_default(),
    }))
}

pub async fn get_shortcut_by_uuid(
    pool: &PgPool,
    uuid: &Uuid,
    user_id: i32,
) -> Result<Option<EncryptedShortcut>, Box<dyn Error>> {
    let record = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uuid, last_updated
        FROM shortcuts WHERE uuid = $1 AND user_id = $2
        "#,
        uuid,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| EncryptedShortcut {
        encrypted_data: r.encrypted_data,
        nonce: r.nonce,
        uuid: r.uuid,
        last_updated: r.last_updated.unwrap_or_default(),
    }))
}

pub async fn update_task(
    pool: &PgPool,
    task: &EncryptedTask,
    user_id: i32,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!(
        r#"
        UPDATE tasks SET
            encrypted_data = $1,
            nonce = $2,
            last_updated = $3
        WHERE uuid = $4 AND user_id = $5
        "#,
        task.encrypted_data,
        task.nonce,
        task.last_updated,
        task.uuid,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn update_shortcut(
    pool: &PgPool,
    shortcut: &EncryptedShortcut,
    user_id: i32,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!(
        r#"
        UPDATE shortcuts SET
            encrypted_data = $1,
            nonce = $2,
            last_updated = $3
        WHERE uuid = $4 AND user_id = $5
        "#,
        shortcut.encrypted_data,
        shortcut.nonce,
        shortcut.last_updated,
        shortcut.uuid,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn fetch_new_tasks(
    pool: &PgPool,
    last_sync: i64,
    user_id: i32,
) -> Result<Vec<EncryptedTask>, Box<dyn Error>> {
    let records = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uuid, last_updated
        FROM tasks
        WHERE user_id = $1 AND last_updated >= $2
        ORDER BY last_updated ASC
        "#,
        user_id,
        last_sync
    )
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|r| EncryptedTask {
            encrypted_data: r.encrypted_data,
            nonce: r.nonce,
            uuid: r.uuid,
            last_updated: r.last_updated.unwrap_or_default(),
        })
        .collect())
}

pub async fn fetch_new_shortcuts(
    pool: &PgPool,
    last_sync: i64,
    user_id: i32,
) -> Result<Vec<EncryptedShortcut>, Box<dyn Error>> {
    let records = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uuid, last_updated
        FROM shortcuts
        WHERE user_id = $1 AND last_updated >= $2
        ORDER BY last_updated ASC
        "#,
        user_id,
        last_sync
    )
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|r| EncryptedShortcut {
            encrypted_data: r.encrypted_data,
            nonce: r.nonce,
            uuid: r.uuid,
            last_updated: r.last_updated.unwrap_or_default(),
        })
        .collect())
}

pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<i32, Box<dyn Error>> {
    use bcrypt::{hash, DEFAULT_COST};

    let password_hash = hash(password.as_bytes(), DEFAULT_COST)?;
    let encryption_salt = generate_salt().to_vec();

    let result = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash, encryption_salt)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        email,
        password_hash,
        encryption_salt,
    )
    .fetch_one(pool)
    .await?;

    Ok(result.id)
}

pub async fn verify_user(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<Option<i32>, Box<dyn Error>> {
    use bcrypt::verify;

    let result = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    if let Some(user) = result {
        if verify(password.as_bytes(), &user.password_hash)? {
            return Ok(Some(user.id));
        }
    }

    Ok(None)
}

pub async fn verify_user_hash(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> Result<Option<i32>, Box<dyn Error>> {
    let result = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1 AND password_hash = $2
        "#,
        email,
        password_hash
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.id))
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt_bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut salt_bytes);
    salt_bytes
}
