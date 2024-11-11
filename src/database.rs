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

use sqlx::postgres::PgPool;
use std::error::Error;

use crate::models::{EncryptedShortcut, EncryptedTask};

pub async fn db_init() -> Result<PgPool, Box<dyn Error>> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url).await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            encryption_key_hash VARCHAR(255),
            encryption_key_version INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );"#,
    )
    .execute(&pool)
    .await?;

    sqlx::query!(
        r#"
            CREATE TABLE IF NOT EXISTS user_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                refresh_token TEXT NOT NULL UNIQUE,
                device_id_hash TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, device_id_hash)
            );"#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            encrypted_data TEXT NOT NULL,
            nonce TEXT NOT NULL,
            uid TEXT NOT NULL,
            last_updated BIGINT,
            user_id INTEGER REFERENCES users(id),
            UNIQUE(user_id, uid),
            PRIMARY KEY (user_id, uid)
        );"#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shortcuts (
            encrypted_data TEXT NOT NULL,
            nonce TEXT NOT NULL,
            uid TEXT NOT NULL,
            last_updated BIGINT,
            user_id INTEGER REFERENCES users(id),
            UNIQUE(user_id, uid),
            PRIMARY KEY (user_id, uid)
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
            INSERT INTO tasks (encrypted_data, nonce, uid, last_updated, user_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        encrypted_task.encrypted_data,
        encrypted_task.nonce,
        encrypted_task.uid,
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
            INSERT INTO shortcuts (encrypted_data, nonce, uid, last_updated, user_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        encrypted_shortcut.encrypted_data,
        encrypted_shortcut.nonce,
        encrypted_shortcut.uid,
        encrypted_shortcut.last_updated,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_task_by_uid(
    pool: &PgPool,
    uid: &str,
    user_id: i32,
) -> Result<Option<EncryptedTask>, Box<dyn Error>> {
    let record = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uid, last_updated
        FROM tasks WHERE uid = $1 AND user_id = $2
        "#,
        uid,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| EncryptedTask {
        encrypted_data: r.encrypted_data,
        nonce: r.nonce,
        uid: r.uid,
        last_updated: r.last_updated.unwrap_or_default(),
    }))
}

pub async fn get_shortcut_by_uid(
    pool: &PgPool,
    uid: &str,
    user_id: i32,
) -> Result<Option<EncryptedShortcut>, Box<dyn Error>> {
    let record = sqlx::query!(
        r#"
        SELECT encrypted_data, nonce, uid, last_updated
        FROM shortcuts WHERE uid = $1 AND user_id = $2
        "#,
        uid,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| EncryptedShortcut {
        encrypted_data: r.encrypted_data,
        nonce: r.nonce,
        uid: r.uid,
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
        WHERE uid = $4 AND user_id = $5
        "#,
        task.encrypted_data,
        task.nonce,
        task.last_updated,
        task.uid,
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
        WHERE uid = $4 AND user_id = $5
        "#,
        shortcut.encrypted_data,
        shortcut.nonce,
        shortcut.last_updated,
        shortcut.uid,
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
        SELECT encrypted_data, nonce, uid, last_updated
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
            uid: r.uid,
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
        SELECT encrypted_data, nonce, uid, last_updated
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
            uid: r.uid,
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

    let result = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id
        "#,
        email,
        password_hash,
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

pub async fn store_user_token(
    pool: &PgPool,
    user_id: i32,
    refresh_token: &str,
    device_id_hash: &str,
) -> Result<(), Box<dyn Error>> {
    sqlx::query!(
        r#"
        INSERT INTO user_tokens (user_id, refresh_token, device_id_hash)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, device_id_hash)
        DO UPDATE SET
            refresh_token = EXCLUDED.refresh_token,
            created_at = CURRENT_TIMESTAMP
        "#,
        user_id,
        refresh_token,
        device_id_hash
    )
    .execute(&*pool)
    .await?;

    Ok(())
}

pub async fn fetch_user_credentials(
    pool: &PgPool,
    email: &str,
) -> Result<Option<(i32, Option<String>)>, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT id, encryption_key_hash
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| (r.id, r.encryption_key_hash)))
}

pub async fn fetch_encryption_key(
    pool: &PgPool,
    user_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT encryption_key_hash
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await
    .map(|row| row.and_then(|r| r.encryption_key_hash))
}

pub async fn update_encryption_key(
    pool: &PgPool,
    user_id: i32,
    key_hash: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Delete existing tasks
    sqlx::query!("DELETE FROM tasks WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await?;

    // Delete existing shortcuts
    sqlx::query!("DELETE FROM shortcuts WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await?;

    // Update encryption key
    sqlx::query!(
        r#"
        UPDATE users
        SET encryption_key_hash = $1,
            encryption_key_version = encryption_key_version + 1
        WHERE id = $2
        "#,
        key_hash,
        user_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}
