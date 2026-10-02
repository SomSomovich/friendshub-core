//! Periodic cleanup of tables that would otherwise grow without bound.
//!
//! `pending_events` accumulates a row per unacked event. A consumer that
//! never acks (crashed UI, a bug, a slow implementation) leaves those rows
//! forever. The sweep drops them once they are old enough that replaying
//! would not be useful anyway.
//!
//! `identity_changes` is only interesting while the user has not seen the
//! warning. Once `notified = 1`, the row is history; it stays for a month and
//! is then dropped.

use std::time::Duration;

use sqlx::SqlitePool;

use crate::util::time::now_unix;

const PENDING_EVENT_TTL_SECS: i64 = 7 * 86_400;
const NOTIFIED_IDENTITY_TTL_SECS: i64 = 30 * 86_400;
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Runs forever. Intended to be spawned once per handle.
pub async fn run(db: SqlitePool) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.tick().await; // skip the immediate fire

    loop {
        ticker.tick().await;
        if let Err(e) = sweep(&db).await {
            tracing::warn!(error = ?e, "cleanup sweep failed");
        }
    }
}

async fn sweep(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let now = now_unix();

    let cutoff = now - PENDING_EVENT_TTL_SECS;
    let pending = sqlx::query("DELETE FROM pending_events WHERE created_at < ?")
        .bind(cutoff)
        .execute(db)
        .await?;
    if pending.rows_affected() > 0 {
        tracing::info!(count = pending.rows_affected(), "dropped stale pending events");
    }

    let cutoff = now - NOTIFIED_IDENTITY_TTL_SECS;
    let identity = sqlx::query(
        "DELETE FROM identity_changes WHERE notified = 1 AND changed_at < ?",
    )
    .bind(cutoff)
    .execute(db)
    .await?;
    if identity.rows_affected() > 0 {
        tracing::info!(count = identity.rows_affected(), "dropped old identity changes");
    }

    Ok(())
}
