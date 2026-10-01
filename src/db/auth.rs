use sqlx::SqlitePool;

use crate::error::Result;
use crate::util::time::now_unix;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthState {
    pub account_id: Option<String>,
    pub session_id: Option<String>,
    pub session_token: Option<String>,
    pub device_number: Option<i64>,
    pub fh_number: Option<String>,
    pub expires_at: Option<i64>,
}

pub async fn load(db: &SqlitePool) -> Result<Option<AuthState>> {
    let row = sqlx::query_as::<_, AuthState>(
        "SELECT account_id, session_id, session_token, device_number, fh_number, expires_at \\
         FROM auth_state WHERE id = 1",
    )
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn store(
    db: &SqlitePool,
    account_id: &str,
    session_id: &str,
    session_token: &str,
    device_number: i64,
    fh_number: Option<&str>,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO auth_state
            (id, account_id, session_id, session_token, device_number, fh_number, expires_at, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            account_id = excluded.account_id,
            session_id = excluded.session_id,
            session_token = excluded.session_token,
            device_number = excluded.device_number,
            fh_number = excluded.fh_number,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at",
    )
    .bind(account_id)
    .bind(session_id)
    .bind(session_token)
    .bind(device_number)
    .bind(fh_number)
    .bind(expires_at)
    .bind(now_unix())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn clear(db: &SqlitePool) -> Result<()> {
    sqlx::query("DELETE FROM auth_state WHERE id = 1")
        .execute(db)
        .await?;
    Ok(())
}
