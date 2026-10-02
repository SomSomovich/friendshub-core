//! Group messaging through Sender Keys.
//!
//! A group conversation has one distribution id. Every member derives their
//! own sender key for that id and sends the public half -- a
//! `SenderKeyDistributionMessage` -- to every device of every other member.
//! After that, each outgoing message is sealed once under the sender's own
//! key and broadcast to the group; each device decrypts with the copy of the
//! sender's public key it was given at distribution time.
//!
//! This is the part of Signal Protocol that makes a group message cost O(1)
//! per sender instead of O(members).

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    process_sender_key_distribution_message, DeviceId, ProtocolAddress,
    SenderKeyDistributionMessage,
};
use uuid::Uuid;

use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::stores::Store;
use crate::db::auth as db_auth;
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const SQL_GET_DIST: &str = "SELECT distribution_id FROM group_sender_keys WHERE conversation_id = ?";
const SQL_INSERT_DIST: &str = "INSERT INTO group_sender_keys (conversation_id, distribution_id, created_at) VALUES (?, ?, ?) ON CONFLICT(conversation_id) DO NOTHING";
const SQL_ROTATE_DIST: &str = "INSERT INTO group_sender_keys (conversation_id, distribution_id, created_at) VALUES (?, ?, ?) ON CONFLICT(conversation_id) DO UPDATE SET distribution_id = excluded.distribution_id, created_at = excluded.created_at";

/// Returns the distribution id this device uses for the given conversation,
/// creating one on first call.
pub async fn distribution_id_for(
    state: &ActorState,
    conversation_id: &str,
) -> CryptoResult<Uuid> {
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(SQL_GET_DIST)
        .bind(conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    if let Some((bytes,)) = existing {
        return Uuid::from_slice(&bytes)
            .map_err(|e| CryptoError::Invalid(format!("stored distribution id: {e}")));
    }

    let id = Uuid::new_v4();
    sqlx::query(SQL_INSERT_DIST)
        .bind(conversation_id)
        .bind(id.as_bytes().to_vec())
        .bind(now_unix())
        .execute(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    Ok(id)
}

/// Forces a new distribution id for a conversation. Used after a member is
/// removed, so the remaining members rekey and the removed device cannot
/// read anything sent afterwards.
pub async fn rotate_distribution(
    state: &ActorState,
    conversation_id: &str,
) -> CryptoResult<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(SQL_ROTATE_DIST)
        .bind(conversation_id)
        .bind(id.as_bytes().to_vec())
        .bind(now_unix())
        .execute(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;
    Ok(id)
}

async fn local_address(state: &ActorState) -> CryptoResult<ProtocolAddress> {
    let auth = db_auth::load(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?
        .ok_or(CryptoError::NoIdentity)?;

    let account_id = auth.account_id.ok_or(CryptoError::NoIdentity)?;
    let device_number = auth.device_number.unwrap_or(1) as u32;
    let device = DeviceId::try_from(device_number)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;

    Ok(ProtocolAddress::new(account_id, device))
}

/// Produces the distribution message for a conversation, generating the
/// local sender key on first call. The returned bytes go out over the wire
/// inside a SENDER_KEY envelope; the recipient feeds them to
/// [`process_distribution`].
pub async fn create_distribution(
    state: &ActorState,
    conversation_id: &str,
) -> CryptoResult<Vec<u8>> {
    let dist_id = distribution_id_for(state, conversation_id).await?;
    let local = local_address(state).await?;
    let mut store = Store::new(state.db.clone());
    let mut rng = rand::rng();

    let skdm = create_sender_key_distribution_message(&local, dist_id, &mut store, &mut rng)
        .await
        .map_err(|e| CryptoError::Signal(e.to_string()))?;

    Ok(skdm.serialized().to_vec())
}

/// Handles an incoming distribution message from another device. Stores the
/// sender's public key so future group messages from that device can be
/// decrypted.
pub async fn process_distribution(
    state: &ActorState,
    sender_account_id: &str,
    sender_device_number: i64,
    skdm_bytes: &[u8],
) -> CryptoResult<()> {
    let device = DeviceId::try_from(sender_device_number as u32)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;
    let sender = ProtocolAddress::new(sender_account_id.to_string(), device);

    let skdm = SenderKeyDistributionMessage::try_from(skdm_bytes)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;

    let mut store = Store::new(state.db.clone());
    process_sender_key_distribution_message(&sender, &skdm, &mut store)
        .await
        .map_err(|e| CryptoError::Signal(e.to_string()))?;

    Ok(())
}

/// Encrypts a plaintext once for the whole group. The returned bytes are
/// the `SenderKeyMessage`; the caller wraps them in a per-device envelope
/// and sends the same bytes to every member device.
pub async fn encrypt_for_group(
    state: &ActorState,
    conversation_id: &str,
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let dist_id = distribution_id_for(state, conversation_id).await?;
    let local = local_address(state).await?;
    let mut store = Store::new(state.db.clone());
    let mut rng = rand::rng();

    let skm = group_encrypt(&mut store, &local, dist_id, plaintext, &mut rng)
        .await
        .map_err(|e| CryptoError::Signal(e.to_string()))?;

    Ok(skm.serialized().to_vec())
}

/// Decrypts a group message from another device.
pub async fn decrypt_from_group(
    state: &ActorState,
    sender_account_id: &str,
    sender_device_number: i64,
    skm_bytes: &[u8],
) -> CryptoResult<Vec<u8>> {
    let device = DeviceId::try_from(sender_device_number as u32)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;
    let sender = ProtocolAddress::new(sender_account_id.to_string(), device);

    let mut store = Store::new(state.db.clone());
    group_decrypt(skm_bytes, &mut store, &sender)
        .await
        .map_err(|e| CryptoError::Signal(e.to_string()))
}

/// True when the bytes look like a SenderKeyMessage rather than a JSON
/// payload. Used by the websocket dispatcher to tell group ciphertext
/// apart from ordinary text before handing it to the group path.
pub fn looks_like_sender_key_message(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // SenderKeyMessage begins with a version byte (currently 3). JSON, hex,
    // and every other text payload this library produces begin with an
    // ASCII printable character, never with 0x03.
    bytes[0] == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sender_key_version_byte() {
        assert!(looks_like_sender_key_message(&[3]));
        assert!(looks_like_sender_key_message(&[3, 0, 0, 0]));
    }

    #[test]
    fn json_payloads_are_not_sender_key_messages() {
        assert!(!looks_like_sender_key_message(b"{\"k\":1}"));
        assert!(!looks_like_sender_key_message(b"68656c6c6f"));
        assert!(!looks_like_sender_key_message(b""));
    }
}
