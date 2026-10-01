use sqlx::SqlitePool;

use crate::error::Result;
use crate::util::time::now_unix;

#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct AuthState {
    pub account_id: Option<String>,
    pub session_id: Option<String>,
    pub session_token: Option<String>,
    pub device_number: Option<i64>,
    pub fh_number: Option<String>,
    pub expires_at: Option<i64>,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
    pub totp_enabled: Option<i64>,
}

pub async fn load(db: &SqlitePool) -> Result<Option<AuthState>> {
    let row = sqlx::query_as::<_, AuthState>(
        "SELECT account_id, session_id, session_token, device_number, fh_number, expires_at, username, avatar_url, custom_status_text, custom_status_emoji, custom_status_expires_at, totp_enabled FROM auth_state WHERE id = 1",
    )
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn store(db: &SqlitePool, state: &AuthState) -> Result<()> {
    sqlx::query(
        "INSERT INTO auth_state (id, account_id, session_id, session_token, device_number, fh_number, expires_at, username, avatar_url, custom_status_text, custom_status_emoji, custom_status_expires_at, totp_enabled, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET account_id = excluded.account_id, session_id = excluded.session_id, session_token = excluded.session_token, device_number = excluded.device_number, fh_number = excluded.fh_number, expires_at = excluded.expires_at, username = excluded.username, avatar_url = excluded.avatar_url, custom_status_text = excluded.custom_status_text, custom_status_emoji = excluded.custom_status_emoji, custom_status_expires_at = excluded.custom_status_expires_at, totp_enabled = excluded.totp_enabled, updated_at = excluded.updated_at",
    )
    .bind(&state.account_id)
    .bind(&state.session_id)
    .bind(&state.session_token)
    .bind(state.device_number)
    .bind(&state.fh_number)
    .bind(state.expires_at)
    .bind(&state.username)
    .bind(&state.avatar_url)
    .bind(&state.custom_status_text)
    .bind(&state.custom_status_emoji)
    .bind(state.custom_status_expires_at)
    .bind(state.totp_enabled)
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
