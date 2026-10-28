use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

/// The WebSocket dispatcher accepts scheduled envelopes up to one day ahead.
pub const MAX_SCHEDULED_SEND_HORIZON_SECONDS: i64 = 24 * 60 * 60;
/// Time reserved for request transit and server-side fanout before delivery.
pub const SCHEDULED_SEND_SAFETY_MARGIN_SECONDS: i64 = 60;

/// Converts an optional scheduled delivery time into the envelope value and
/// rejects timestamps that the server would silently discard.
pub fn validate_scheduled_send_at(send_at: Option<i64>) -> Result<i64> {
    let Some(send_at) = send_at else {
        return Ok(0);
    };
    if send_at == 0 {
        return Ok(0);
    }
    let now = crate::util::time::now_unix();
    if send_at < 0 || send_at <= now {
        return Err(Error::InvalidPayload(
            "send_at must be a future Unix timestamp".to_owned(),
        ));
    }
    let max_client_horizon =
        MAX_SCHEDULED_SEND_HORIZON_SECONDS - SCHEDULED_SEND_SAFETY_MARGIN_SECONDS;
    if send_at > now.saturating_add(max_client_horizon) {
        return Err(Error::InvalidPayload(format!(
            "send_at must be no more than {max_client_horizon} seconds in the future"
        )));
    }
    Ok(send_at)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn str_field_reads_strings() {
        let v = json!({"name": "alice"});
        assert_eq!(str_field(&v, "name").unwrap(), "alice");
    }

    #[test]
    fn str_field_rejects_missing() {
        let v = json!({});
        assert!(str_field(&v, "name").is_err());
        assert!(str_field(&json!({"name": 3}), "name").is_err());
    }

    #[test]
    fn opt_str_skips_empty() {
        assert_eq!(opt_str(&json!({"x": ""}), "x"), None);
        assert_eq!(opt_str(&json!({"x": "y"}), "x").as_deref(), Some("y"));
        assert_eq!(opt_str(&json!({}), "x"), None);
    }

    #[test]
    fn i64_field_requires_number() {
        assert_eq!(i64_field(&json!({"n": 7}), "n").unwrap(), 7);
        assert!(i64_field(&json!({"n": "7"}), "n").is_err());
        assert!(i64_field(&json!({}), "n").is_err());
    }

    #[test]
    fn id_from_extracts_id() {
        assert_eq!(id_from(&json!({"id": "x"})).unwrap(), "x");
        assert!(id_from(&json!({})).is_err());
    }
}
