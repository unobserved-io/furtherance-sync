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

use sqlx::PgPool;
use std::sync::Arc;
use time::{Duration, OffsetDateTime, Time};
use tracing::{error, info};

use crate::database;

pub async fn start_cleanup_task(pool: Arc<PgPool>) {
    tokio::spawn(async move {
        loop {
            let next_run = get_next_cleanup_time();
            let now = OffsetDateTime::now_utc();
            let duration_until_next = next_run - now;

            tokio::time::sleep(tokio::time::Duration::from_secs(
                duration_until_next.whole_seconds().max(0) as u64,
            ))
            .await;

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

fn get_next_cleanup_time() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    let target_time = Time::from_hms(6, 0, 0).unwrap();

    let mut next_run = now.replace_time(target_time);
    if now.time() >= target_time {
        next_run = next_run + Duration::days(1);
    }

    next_run
}
