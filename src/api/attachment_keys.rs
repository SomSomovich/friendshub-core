//! Account-local, durable records for attachment encryption material.
//!
//! These values live only in the account's SQLCipher database. They are
//! needed to reopen attachments after a restart and are removed together with
//! the database when the account is purged.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::crypto::attachments::decode_key_and_base;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Deserialize)]
struct StoreRequest {
    attachment_id: String,
    key_hex: String,
    base_nonce_hex: String,
    #[serde(default)]
    conversation_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdRequest {
    attachment_id: String,
}

#[derive(Debug, Clone, Serialize, FromRow)]
struct AttachmentKeyRecord {
    attachment_id: String,
    key_hex: String,
    base_nonce_hex: String,
    conversation_id: Option<String>,
}

/// Save an attachment key before publishing or acknowledging the envelope
/// that carries it. Repeating the same record is safe; a conflicting record
/// never replaces the original key.
pub async fn store(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: StoreRequest = serde_json::from_slice(&payload)?;
    let attachment_id = normalize_uuid(&request.attachment_id, "attachment_id")?;
    let conversation_id = request
        .conversation_id
        .as_deref()
        .map(|value| normalize_uuid(value, "conversation_id"))
        .transpose()?;

    // Validate the material using the same decoder used by attachment crypto,
    // then canonicalize its text representation for idempotent comparisons.
    decode_key_and_base(&request.key_hex, &request.base_nonce_hex)?;
    let key_hex = request.key_hex.to_ascii_lowercase();
    let base_nonce_hex = request.base_nonce_hex.to_ascii_lowercase();

    sqlx::query(
        "INSERT INTO attachment_keys (attachment_id, key_hex, base_nonce_hex, conversation_id) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(attachment_id) DO NOTHING",
    )
    .bind(&attachment_id)
    .bind(&key_hex)
    .bind(&base_nonce_hex)
    .bind(&conversation_id)
    .execute(&state.db)
    .await?;

    let existing = load_record(&state.db, &attachment_id)
        .await?
        .ok_or_else(|| Error::Database("attachment key record disappeared after insert".into()))?;
    if existing.key_hex != key_hex
        || existing.base_nonce_hex != base_nonce_hex
        || existing.conversation_id != conversation_id
    {
        return Err(Error::InvalidPayload(
            "attachment key record already exists with different values".into(),
        ));
    }

    serde_json::to_vec(&existing).map_err(Error::from)
}

/// Load persisted key material. The JSON response is `null` when no key has
/// been stored for this attachment in the current account database.
pub async fn get(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: IdRequest = serde_json::from_slice(&payload)?;
    let attachment_id = normalize_uuid(&request.attachment_id, "attachment_id")?;
    let record = load_record(&state.db, &attachment_id).await?;
    serde_json::to_vec(&record).map_err(Error::from)
}

/// Delete a key record after its owner no longer needs local access.
pub async fn delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: IdRequest = serde_json::from_slice(&payload)?;
    let attachment_id = normalize_uuid(&request.attachment_id, "attachment_id")?;
    let result = sqlx::query("DELETE FROM attachment_keys WHERE attachment_id = ?1")
        .bind(attachment_id)
        .execute(&state.db)
        .await?;
    serde_json::to_vec(&serde_json::json!({
        "deleted": result.rows_affected() != 0
    }))
    .map_err(Error::from)
}

async fn load_record(
    db: &crate::db::Db,
    attachment_id: &str,
) -> Result<Option<AttachmentKeyRecord>> {
    sqlx::query_as::<_, AttachmentKeyRecord>(
        "SELECT attachment_id, key_hex, base_nonce_hex, conversation_id \
         FROM attachment_keys WHERE attachment_id = ?1",
    )
    .bind(attachment_id)
    .fetch_optional(db)
    .await
    .map_err(Error::from)
}

fn normalize_uuid(value: &str, field: &str) -> Result<String> {
    Uuid::parse_str(value)
        .map(|id| id.to_string())
        .map_err(|_| Error::InvalidPayload(format!("{field} must be a UUID")))
}
