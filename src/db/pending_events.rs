use sqlx::SqlitePool;

use crate::error::Result;
use crate::util::time::now_unix;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingEvent {
    pub id: i64,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

pub async fn push(db: &SqlitePool, event_type: &str, payload: &str) -> Result<i64> {
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO pending_events (event_type, payload, created_at) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(event_type)
    .bind(payload)
    .bind(now_unix())
    .fetch_one(db)
    .await?;
    Ok(id)
}

pub async fn get(db: &SqlitePool, id: i64) -> Result<Option<PendingEvent>> {
    let row = sqlx::query_as::<_, PendingEvent>(
        "SELECT id, event_type, payload, created_at FROM pending_events WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn ack(db: &SqlitePool, id: i64) -> Result<bool> {
    let res = sqlx::query("DELETE FROM pending_events WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}
