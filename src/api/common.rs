use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

/// Loads the stored session token, or fails when the account is signed out.
pub async fn bearer(state: &ActorState) -> Result<String> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    match auth.session_token {
        Some(t) if !t.is_empty() => Ok(t),
        _ => Err(Error::NotAuthenticated),
    }
}

/// Pulls a required string out of a JSON payload.
pub fn str_field(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(String::from)
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing")))
}

/// Pulls an optional string. An empty string is treated as absent.
pub fn opt_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Pulls a required i64.
pub fn i64_field(v: &serde_json::Value, key: &str) -> Result<i64> {
    v.get(key)
        .and_then(|x| x.as_i64())
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing or not a number")))
}

/// Splits a `{ "id": "..." }` payload into the value.
pub fn id_from(v: &serde_json::Value) -> Result<String> {
    str_field(v, "id")
}
