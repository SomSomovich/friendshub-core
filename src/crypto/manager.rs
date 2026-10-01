//! High-level Signal Protocol operations: session establishment, envelope
//! encryption, and envelope decryption.
//!
//! The protocol entry points take several `&mut dyn Trait` arguments at
//! once, and Rust will not let us borrow the same value twice. Each call
//! therefore gets its own `Store` clone: cloning a `SqlitePool` is
//! reference-counting, not connection duplication.

use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, DeviceId,
    IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, PreKeySignalMessage, ProtocolAddress,
    PublicKey, SignalMessage, SignedPreKeyId,
};

use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::stores::Store;
use crate::db::auth as db_auth;
use crate::runtime::ActorState;

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

fn bundle_from_json(v: &serde_json::Value) -> CryptoResult<PreKeyBundle> {
    let registration_id = v
        .get("registration_id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CryptoError::Invalid("registration_id missing".into()))? as u32;

    let device_number = v
        .get("device_number")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CryptoError::Invalid("device_number missing".into()))? as u32;
    let device_id = DeviceId::try_from(device_number)
        .map_err(|e| CryptoError::Invalid(format!("device_id: {e}")))?;

    let identity_key_hex = v
        .get("identity_key_pub")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("identity_key_pub missing".into()))?;
    let identity_key_bytes = hex::decode(identity_key_hex)
        .map_err(|e| CryptoError::Invalid(format!("identity_key_pub hex: {e}")))?;
    let identity_key = IdentityKey::decode(&identity_key_bytes)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;

    let signed = v
        .get("signed_prekey")
        .ok_or_else(|| CryptoError::Invalid("signed_prekey missing".into()))?;
    let signed_id = signed
        .get("id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CryptoError::Invalid("signed_prekey.id missing".into()))? as u32;
    let signed_pub_hex = signed
        .get("pub")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("signed_prekey.pub missing".into()))?;
    let signed_pub_bytes = hex::decode(signed_pub_hex)
        .map_err(|e| CryptoError::Invalid(format!("signed_prekey.pub hex: {e}")))?;
    let signed_pub = PublicKey::deserialize(&signed_pub_bytes)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;
    let signed_sig_hex = signed
        .get("sig")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("signed_prekey.sig missing".into()))?;
    let signed_sig = hex::decode(signed_sig_hex)
        .map_err(|e| CryptoError::Invalid(format!("signed_prekey.sig hex: {e}")))?;

    let kyber = v
        .get("kyber_last_resort")
        .ok_or_else(|| CryptoError::Invalid("kyber_last_resort missing".into()))?;
    let kyber_id = kyber
        .get("id")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CryptoError::Invalid("kyber.id missing".into()))? as u32;
    let kyber_pub_hex = kyber
        .get("pub")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("kyber.pub missing".into()))?;
    let kyber_pub_bytes = hex::decode(kyber_pub_hex)
        .map_err(|e| CryptoError::Invalid(format!("kyber.pub hex: {e}")))?;
    let kyber_pub = libsignal_protocol::kem::PublicKey::deserialize(&kyber_pub_bytes)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;
    let kyber_sig_hex = kyber
        .get("sig")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("kyber.sig missing".into()))?;
    let kyber_sig = hex::decode(kyber_sig_hex)
        .map_err(|e| CryptoError::Invalid(format!("kyber.sig hex: {e}")))?;

    let otk = v.get("one_time_prekey").and_then(|o| {
        let id = o.get("id").and_then(|x| x.as_u64())? as u32;
        let pub_hex = o.get("pub").and_then(|x| x.as_str())?;
        let pub_bytes = hex::decode(pub_hex).ok()?;
        let pubkey = PublicKey::deserialize(&pub_bytes).ok()?;
        Some((PreKeyId::from(id), pubkey))
    });

    PreKeyBundle::new(
        registration_id,
        device_id,
        otk,
        SignedPreKeyId::from(signed_id),
        signed_pub,
        signed_sig,
        KyberPreKeyId::from(kyber_id),
        kyber_pub,
        kyber_sig,
        identity_key,
    )
    .map_err(|e| CryptoError::Signal(e.to_string()))
}

/// Establishes an outbound session with one device of a peer.
pub async fn establish_outbound_session(
    state: &ActorState,
    recipient_account_id: &str,
    device_number: i64,
    bundle_json: &serde_json::Value,
) -> CryptoResult<()> {
    let local = local_address(state).await?;
    let device = DeviceId::try_from(device_number as u32)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;
    let remote = ProtocolAddress::new(recipient_account_id.to_string(), device);

    let bundle = bundle_from_json(bundle_json)?;

    // Each parameter slot gets its own Store: process_prekey_bundle takes
    // session_store and identity_store as separate mutable references, and
    // Rust will not allow two mutable borrows of the same value in one call.
    let mut session_store = Store::new(state.db.clone());
    let mut identity_store = Store::new(state.db.clone());
    let mut rng = rand::rng();

    process_prekey_bundle(
        &remote,
        &local,
        &mut session_store,
        &mut identity_store,
        &bundle,
        SystemTime::now(),
        &mut rng,
    )
    .await
    .map_err(|e| CryptoError::Signal(e.to_string()))?;

    Ok(())
}

/// Encrypts `plaintext` for a single device and returns the serialized
/// `CiphertextMessage` plus a flag for whether it is a prekey message.
pub async fn encrypt_for_device(
    state: &ActorState,
    recipient_account_id: &str,
    device_number: i64,
    plaintext: &[u8],
) -> CryptoResult<(Vec<u8>, bool)> {
    let local = local_address(state).await?;
    let device = DeviceId::try_from(device_number as u32)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;
    let remote = ProtocolAddress::new(recipient_account_id.to_string(), device);

    let mut session_store = Store::new(state.db.clone());
    let mut identity_store = Store::new(state.db.clone());
    let mut rng = rand::rng();

    let msg = message_encrypt(
        plaintext,
        &remote,
        &local,
        &mut session_store,
        &mut identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .await
    .map_err(|e| CryptoError::Signal(e.to_string()))?;

    let is_prekey = matches!(msg, CiphertextMessage::PreKeySignalMessage(_));
    let bytes = msg.serialize().to_vec();
    Ok((bytes, is_prekey))
}

/// Decrypts an incoming envelope.
///
/// The envelope JSON carries `is_prekey_message`, which selects between the
/// prekey and the ordinary ciphertext constructor: libsignal does not expose a
/// `TryFrom<&[u8]>` on `CiphertextMessage`, so the branch is explicit.
pub async fn decrypt_envelope(
    state: &ActorState,
    envelope: &serde_json::Value,
) -> CryptoResult<Vec<u8>> {
    let sender_account_id = envelope
        .get("sender_account_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("sender_account_id missing".into()))?;
    let sender_device = envelope
        .get("sender_device_number")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| CryptoError::Invalid("sender_device_number missing".into()))? as u32;
    let is_prekey = envelope
        .get("is_prekey_message")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let ciphertext_hex = envelope
        .get("ciphertext")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CryptoError::Invalid("ciphertext missing".into()))?;
    let ciphertext_bytes = hex::decode(ciphertext_hex)
        .map_err(|e| CryptoError::Invalid(format!("ciphertext hex: {e}")))?;

    let ciphertext = if is_prekey {
        let msg = PreKeySignalMessage::try_from(&ciphertext_bytes[..])
            .map_err(|e| CryptoError::Signal(e.to_string()))?;
        CiphertextMessage::PreKeySignalMessage(msg)
    } else {
        let msg = SignalMessage::try_from(&ciphertext_bytes[..])
            .map_err(|e| CryptoError::Signal(e.to_string()))?;
        CiphertextMessage::SignalMessage(msg)
    };

    let local = local_address(state).await?;
    let device = DeviceId::try_from(sender_device)
        .map_err(|e| CryptoError::Invalid(format!("device id: {e}")))?;
    let remote = ProtocolAddress::new(sender_account_id.to_string(), device);

    let mut session_store = Store::new(state.db.clone());
    let mut identity_store = Store::new(state.db.clone());
    let mut pre_key_store = Store::new(state.db.clone());
    let signed_pre_key_store = Store::new(state.db.clone());
    let mut kyber_store = Store::new(state.db.clone());
    let mut rng = rand::rng();

    let plaintext = message_decrypt(
        &ciphertext,
        &remote,
        &local,
        &mut session_store,
        &mut identity_store,
        &mut pre_key_store,
        &signed_pre_key_store,
        &mut kyber_store,
        &mut rng,
    )
    .await
    .map_err(|e| CryptoError::Signal(e.to_string()))?;

    Ok(plaintext)
}
