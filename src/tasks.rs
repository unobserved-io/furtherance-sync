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

use chrono::{DateTime, Timelike, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

use crate::database;

pub async fn start_cleanup_task(pool: Arc<PgPool>) {
    tokio::spawn(async move {
        loop {
            let next_run = get_next_cleanup_time();
            let now = Utc::now();
            let duration_until_next = next_run - now;

            sleep(Duration::from_secs(duration_until_next.num_seconds() as u64)).await;

            match database::cleanup_reset_tokens(&pool).await {
                Ok(count) => {
                    info!("Cleaned up {} expired/used reset tokens", count);
                }
                Err(e) => {
                    error!("Failed to cleanup reset tokens: {}", e);
                }
            }
        }
    });
}

fn get_next_cleanup_time() -> DateTime<Utc> {
    let now = Utc::now();
    let target_hour = 6; // 6 AM UTC

    let next_run = now
        .date_naive()
        .and_hms_opt(target_hour, 0, 0)
        .and_then(|naive_dt| match naive_dt.and_local_timezone(Utc) {
            chrono::LocalResult::Single(dt) => Some(dt),
            _ => None,
        })
        .unwrap_or_else(|| {
            // Fallback: schedule for 24 hours from now
            error!("Failed to calculate next cleanup time, defaulting to 24 hours from now");
            now + chrono::Duration::days(1)
        });

    // If it's already past target_hour today, schedule for tomorrow
    if now.hour() >= target_hour as u32 {
        next_run + chrono::Duration::days(1)
    } else {
        next_run
    }
}
