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
use tracing::error;

use crate::{
    login,
    models::{EncryptedShortcut, EncryptedTask},
};

#[cfg(feature = "official")]
use crate::register::TempRegistration;

pub async fn db_init() -> Result<PgPool, Box<dyn Error>> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(e) => {
            error!("DATABASE_URL environment variable not set: {}", e);
            return Err(Box::new(e));
        }
    };
    let pool = PgPool::connect(&database_url).await?;

    #[cfg(not(feature = "official"))]
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

    #[cfg(feature = "official")]
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            encryption_key_hash VARCHAR(255),
            encryption_key_version INTEGER NOT NULL DEFAULT 0,
            stripe_customer_id VARCHAR(255),
            subscription_status VARCHAR(50),
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

    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            used BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );"#,
    )
    .execute(&pool)
    .await?;

    #[cfg(feature = "official")]
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS temporary_registrations (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            verification_token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
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
            last_updated BIGINT NOT NULL DEFAULT 0,
            is_orphaned BOOL NOT NULL DEFAULT FALSE,
            user_id INTEGER REFERENCES users(id),
            known_by_devices TEXT[] DEFAULT '{}',
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
            last_updated BIGINT NOT NULL DEFAULT 0,
            is_orphaned BOOL NOT NULL DEFAULT FALSE,
            user_id INTEGER REFERENCES users(id),
            known_by_devices TEXT[] DEFAULT '{}',
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
    task: &EncryptedTask,
    user_id: i32,
    device_refresh_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO tasks
            (encrypted_data, nonce, uid, last_updated, user_id, known_by_devices)
        VALUES ($1, $2, $3, $4, $5, ARRAY[$6])
        ON CONFLICT (user_id, uid) DO UPDATE
        SET encrypted_data =
            CASE
                WHEN tasks.is_orphaned OR $4 >= tasks.last_updated
                THEN $1
                ELSE tasks.encrypted_data
            END,
        nonce =
            CASE
                WHEN tasks.is_orphaned OR $4 >= tasks.last_updated
                THEN $2
                ELSE tasks.nonce
            END,
        last_updated =
            CASE
                WHEN tasks.is_orphaned OR $4 >= tasks.last_updated
                THEN $4
                ELSE tasks.last_updated
            END,
        known_by_devices =
            CASE
                WHEN $6 = ANY(tasks.known_by_devices)
                THEN tasks.known_by_devices
                ELSE array_append(tasks.known_by_devices, $6)
            END,
        is_orphaned = false"#,
        task.encrypted_data,
        task.nonce,
        task.uid,
        task.last_updated,
        user_id,
        device_refresh_token,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_shortcut(
    pool: &PgPool,
    shortcut: &EncryptedShortcut,
    user_id: i32,
    device_refresh_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            INSERT INTO shortcuts
                (encrypted_data, nonce, uid, last_updated, user_id, known_by_devices)
            VALUES ($1, $2, $3, $4, $5, ARRAY[$6])
            ON CONFLICT (user_id, uid) DO UPDATE
            SET encrypted_data =
                CASE
                    WHEN shortcuts.is_orphaned OR $4 >= shortcuts.last_updated
                    THEN $1
                    ELSE shortcuts.encrypted_data
                END,
            nonce =
                CASE
                    WHEN shortcuts.is_orphaned OR $4 >= shortcuts.last_updated
                    THEN $2
                    ELSE shortcuts.nonce
                END,
            last_updated =
                CASE
                    WHEN shortcuts.is_orphaned OR $4 >= shortcuts.last_updated
                    THEN $4
                    ELSE shortcuts.last_updated
                END,
            known_by_devices =
                CASE
                    WHEN $6 = ANY(shortcuts.known_by_devices)
                    THEN shortcuts.known_by_devices
                    ELSE array_append(shortcuts.known_by_devices, $6)
                END,
            is_orphaned = false"#,
        shortcut.encrypted_data,
        shortcut.nonce,
        shortcut.uid,
        shortcut.last_updated,
        user_id,
        device_refresh_token,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn fetch_orphaned_task_uids(
    pool: &PgPool,
    user_id: i32,
) -> Result<Vec<String>, Box<dyn Error>> {
    let records = sqlx::query!(
        r#"
        SELECT uid
        FROM tasks
        WHERE user_id = $1 AND is_orphaned = true
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.uid).collect())
}

pub async fn fetch_orphaned_shortcut_uids(
    pool: &PgPool,
    user_id: i32,
) -> Result<Vec<String>, Box<dyn Error>> {
    let records = sqlx::query!(
        r#"
        SELECT uid
        FROM shortcuts
        WHERE user_id = $1 AND is_orphaned = true
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.uid).collect())
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

    // Mark existing tasks as orphaned and clear known devices
    sqlx::query!(
        r#"
            UPDATE tasks
            SET is_orphaned = true,
                known_by_devices = '{}'
            WHERE user_id = $1
            "#,
        user_id
    )
    .execute(&mut *tx)
    .await?;

    // Mark existing shortcuts as orphaned and clear known devices
    sqlx::query!(
        r#"
            UPDATE shortcuts
            SET is_orphaned = true,
                known_by_devices = '{}'
            WHERE user_id = $1
            "#,
        user_id
    )
    .execute(&mut *tx)
    .await?;

    // Delete all tokens for this user
    sqlx::query!(
        r#"
            DELETE FROM user_tokens
            WHERE user_id = $1
            "#,
        user_id
    )
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

pub async fn has_any_users(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT EXISTS (SELECT 1 FROM users LIMIT 1) as "exists!"
        "#
    )
    .fetch_one(pool)
    .await?;

    Ok(record.exists)
}

pub async fn delete_user_token(
    pool: &PgPool,
    user_id: i32,
    device_id_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM user_tokens
        WHERE user_id = $1 AND device_id_hash = $2
        "#,
        user_id,
        device_id_hash
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn fetch_tasks_for_device(
    pool: &PgPool,
    user_id: i32,
    device_token: &str,
    last_sync: i64,
) -> Result<Vec<EncryptedTask>, sqlx::Error> {
    let tasks = sqlx::query_as!(
        EncryptedTask,
        r#"
        SELECT
            encrypted_data,
            nonce,
            uid,
            last_updated
        FROM tasks
        WHERE user_id = $1
        AND (
            NOT ($2 = ANY(known_by_devices))
            OR
            (last_updated > $3)
        )
        AND NOT is_orphaned"#,
        user_id,
        device_token,
        last_sync
    )
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

pub async fn fetch_shortcuts_for_device(
    pool: &PgPool,
    user_id: i32,
    device_token: &str,
    last_sync: i64,
) -> Result<Vec<EncryptedShortcut>, sqlx::Error> {
    let shortcuts = sqlx::query_as!(
        EncryptedShortcut,
        r#"
        SELECT
            encrypted_data,
            nonce,
            uid,
            last_updated
        FROM shortcuts
        WHERE user_id = $1
        AND (
            NOT ($2 = ANY(known_by_devices))
            OR
            (last_updated > $3)
        )
        AND NOT is_orphaned"#,
        user_id,
        device_token,
        last_sync
    )
    .fetch_all(pool)
    .await?;

    Ok(shortcuts)
}

pub async fn mark_tasks_known(
    pool: &PgPool,
    task_uids: &[String],
    user_id: i32,
    device_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE tasks
        SET known_by_devices =
            CASE
                WHEN $3 = ANY(known_by_devices)
                THEN known_by_devices
                ELSE array_append(known_by_devices, $3)
            END
        WHERE user_id = $1 AND uid = ANY($2)"#,
        user_id,
        task_uids,
        device_token,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn mark_shortcuts_known(
    pool: &PgPool,
    shortcut_uids: &[String],
    user_id: i32,
    device_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE shortcuts
        SET known_by_devices =
            CASE
                WHEN $3 = ANY(known_by_devices)
                THEN known_by_devices
                ELSE array_append(known_by_devices, $3)
            END
        WHERE user_id = $1 AND uid = ANY($2)"#,
        user_id,
        shortcut_uids,
        device_token,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn cleanup_device_tokens(
    pool: &PgPool,
    user_id: i32,
    expired_tokens: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE tasks
        SET known_by_devices = array_remove(known_by_devices, token)
        FROM unnest($1::text[]) AS t(token)
        WHERE user_id = $2"#,
        expired_tokens,
        user_id,
    )
    .execute(pool)
    .await?;

    sqlx::query!(
        r#"
        UPDATE shortcuts
        SET known_by_devices = array_remove(known_by_devices, token)
        FROM unnest($1::text[]) AS t(token)
        WHERE user_id = $2"#,
        expired_tokens,
        user_id,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn fetch_refresh_token(
    pool: &PgPool,
    user_id: i32,
    device_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let device_id_hash = login::hash_device_id(device_id);

    let result = sqlx::query!(
        r#"
        SELECT refresh_token
        FROM user_tokens
        WHERE user_id = $1
        AND device_id_hash = $2
        "#,
        user_id,
        device_id_hash
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.refresh_token))
}

#[cfg(feature = "official")]
pub async fn get_user_id_by_email(pool: &PgPool, email: &str) -> Result<Option<i32>, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT id
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| r.id))
}

#[cfg(feature = "official")]
pub async fn store_reset_token(
    pool: &PgPool,
    user_id: i32,
    token: &str,
    expires_at: time::OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user_id,
        token,
        expires_at,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn verify_reset_token(pool: &PgPool, token: &str) -> Result<Option<i32>, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT user_id
        FROM password_reset_tokens
        WHERE token = $1
        AND expires_at > CURRENT_TIMESTAMP
        AND used = false
        "#,
        token
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.and_then(|r| r.user_id))
}

#[cfg(feature = "official")]
pub async fn mark_reset_token_used(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE password_reset_tokens
        SET used = true
        WHERE token = $1
        "#,
        token
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn update_password(
    pool: &PgPool,
    user_id: i32,
    new_password: &str,
) -> Result<(), sqlx::Error> {
    let password_hash = bcrypt::hash(new_password.as_bytes(), bcrypt::DEFAULT_COST)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    sqlx::query!(
        r#"
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        "#,
        password_hash,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn cleanup_reset_tokens(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // Delete tokens that are:
    // 1. Expired and unused (older than 1 hour)
    // 2. Used and older than 30 days
    let result = sqlx::query!(
        r#"
        DELETE FROM password_reset_tokens
        WHERE (expires_at < CURRENT_TIMESTAMP - INTERVAL '1 hour' AND used = false)
        OR (created_at < CURRENT_TIMESTAMP - INTERVAL '30 days' AND used = true)
        RETURNING id
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(result.len() as u64)
}

#[cfg(feature = "official")]
pub async fn store_temporary_registration(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    verification_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO temporary_registrations
            (email, password_hash, verification_token, expires_at)
        VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')
        "#,
        email,
        password_hash,
        verification_token,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn get_temporary_registration(
    pool: &PgPool,
    verification_token: &str,
) -> Result<Option<TempRegistration>, sqlx::Error> {
    sqlx::query_as!(
        TempRegistration,
        r#"
        SELECT email, password_hash, verification_token
        FROM temporary_registrations
        WHERE verification_token = $1
        AND expires_at > NOW()
        AND used = false
        "#,
        verification_token
    )
    .fetch_optional(pool)
    .await
}

#[cfg(feature = "official")]
pub async fn mark_temp_registration_used(
    pool: &PgPool,
    verification_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE temporary_registrations
        SET used = true
        WHERE verification_token = $1
        "#,
        verification_token
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn create_user_with_subscription(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    stripe_customer_id: &str,
    subscription_status: &str,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO users (
            email,
            password_hash,
            stripe_customer_id,
            subscription_status
        )
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        email,
        password_hash,
        stripe_customer_id,
        subscription_status
    )
    .fetch_one(pool)
    .await?;

    Ok(result.id)
}

#[cfg(feature = "official")]
pub async fn get_stripe_customer_id(
    pool: &PgPool,
    user_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT stripe_customer_id
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.and_then(|r| r.stripe_customer_id))
}

#[cfg(feature = "official")]
pub async fn update_subscription_status(
    pool: &PgPool,
    stripe_customer_id: &str,
    status: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE users
        SET subscription_status = $1
        WHERE stripe_customer_id = $2
        "#,
        status,
        stripe_customer_id,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "official")]
pub async fn is_subscription_active(pool: &PgPool, user_id: i32) -> Result<bool, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT subscription_status
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(match record {
        Some(r) => matches!(
            r.subscription_status.as_deref(),
            Some("active") | Some("trialing")
        ),
        None => false,
    })
}
