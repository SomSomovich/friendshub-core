//! Device initialization: identity key, registration, prekey provisioning.
//!
//! Called once after login on a fresh device. Generates the local identity,
//! tells the server about the device (name, registration id, public identity
//! key), then generates and uploads the initial prekey material.

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyId,
    PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};
use rand::Rng;

use crate::api::common::bearer;
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::stores::Store;
use crate::runtime::ActorState;

/// Number of one-time prekeys generated on first setup.
pub const INITIAL_OTK_COUNT: usize = 100;

/// Minimum pool size below which `ensure_prekeys` tops up.
pub const MIN_OTK_THRESHOLD: usize = 10;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InitResult {
    pub device_id: String,
    pub device_number: i64,
    pub registration_id: i64,
    pub one_time_prekeys: usize,
    pub kyber_one_time_prekeys: usize,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn is_initialized(state: &ActorState) -> CryptoResult<bool> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_state WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;
    Ok(count > 0)
}

async fn load_identity(state: &ActorState) -> CryptoResult<IdentityKeyPair> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT key_pair FROM identity_state WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| CryptoError::Database(e.to_string()))?;

    let blob = row.ok_or(CryptoError::NoIdentity)?.0;
    crate::crypto::stores::decode_identity_key_pair(&blob)
        .map_err(|e| CryptoError::Signal(e.to_string()))
}

/// Full first-run setup: identity, device registration, initial prekeys.
pub async fn initialize(state: &ActorState, name: &str) -> CryptoResult<InitResult> {
    if is_initialized(state).await? {
        return Err(CryptoError::Invalid("device is already initialized".into()));
    }

    let mut rng = rand::rng();

    // 1. Identity key pair.
    let identity = IdentityKeyPair::generate(&mut rng);

    // 2. Registration id. The server accepts the full 14-bit range; picking a
    //    random value here means two devices of the same account will almost
    //    never collide, and re-registration of the same device gets a fresh id.
    let registration_id: u32 = rng.random_range(0..16384);

    // 3. Store identity locally before anything else: the server call below
    //    can fail, and re-running setup must be able to see that state.
    let identity_blob = identity.serialize().to_vec();
    sqlx::query(
        "INSERT INTO identity_state (id, key_pair, registration_id, next_prekey_id) VALUES (1, ?, ?, 1)",
    )
    .bind(&identity_blob)
    .bind(registration_id as i64)
    .execute(&state.db)
    .await
    .map_err(|e| CryptoError::Database(e.to_string()))?;

    // 4. Register the device with the server.
    let identity_pub_hex = hex::encode(identity.identity_key().serialize());
    let token = bearer(state).await.map_err(|e| CryptoError::Database(e.to_string()))?;

    let body = serde_json::json!({
        "name": name,
        "registration_id": registration_id as i64,
        "identity_key_pub": identity_pub_hex,
    });

    let resp: serde_json::Value = state
        .http
        .post("/api/v1/devices", &body, Some(&token))
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    let device_id = resp
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CryptoError::Invalid("server response missing device id".into()))?
        .to_string();

    let device_number = resp
        .get("device_number")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CryptoError::Invalid("server response missing device_number".into()))?;

    // 5. Persist device_number so subsequent sessions are bound to it.
    sqlx::query("UPDATE auth_state SET device_number = ? WHERE id = 1")
        .bind(device_number)
        .execute(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    // 6. Generate and upload the initial prekey material.
    let (otk, kyber_otk) = generate_and_upload_prekeys(state, &identity, INITIAL_OTK_COUNT).await?;

    Ok(InitResult {
        device_id,
        device_number,
        registration_id: registration_id as i64,
        one_time_prekeys: otk,
        kyber_one_time_prekeys: kyber_otk,
    })
}

/// Ensures the local one-time prekey pool has at least `MIN_OTK_THRESHOLD`
/// unused keys. Generates and uploads the shortfall. Safe to call repeatedly:
/// a pool above the threshold is left alone.
pub async fn ensure_prekeys(state: &ActorState) -> CryptoResult<usize> {
    let identity = load_identity(state).await?;

    let available: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pre_keys")
        .fetch_one(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    let have = available as usize;
    if have >= MIN_OTK_THRESHOLD {
        return Ok(0);
    }

    let needed = INITIAL_OTK_COUNT.saturating_sub(have);
    if needed == 0 {
        return Ok(0);
    }

    let (otk, _kyber) = generate_and_upload_prekeys(state, &identity, needed).await?;
    Ok(otk)
}

/// Generates `count` one-time prekeys on both curves, plus a fresh signed
/// prekey and kyber last-resort, stores them locally, and uploads the public
/// halves to the server.
async fn generate_and_upload_prekeys(
    state: &ActorState,
    identity: &IdentityKeyPair,
    count: usize,
) -> CryptoResult<(usize, usize)> {
    let mut rng = rand::rng();

    let mut next_id: i64 = sqlx::query_scalar(
        "SELECT next_prekey_id FROM identity_state WHERE id = 1",
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| CryptoError::Database(e.to_string()))?;

    let signed_prekey_id = next_id;
    next_id += 1;
    let kyber_last_resort_id = next_id;
    next_id += 1;

    // ---- signed prekey ----
    let signed_id = SignedPreKeyId::from(signed_prekey_id as u32);
    let signed_kp = KeyPair::generate(&mut rng);
    let signed_pub_bytes = signed_kp.public_key.serialize();
    let signed_sig = identity
        .private_key()
        .calculate_signature(&signed_pub_bytes, &mut rng)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;
    let signed_record = SignedPreKeyRecord::new(
        signed_id,
        Timestamp::from_epoch_millis(now_millis()),
        &signed_kp,
        &signed_sig,
    );
    {
        let mut store = Store::new(state.db.clone());
        libsignal_protocol::SignedPreKeyStore::save_signed_pre_key(&mut store, signed_id, &signed_record)
            .await
            .map_err(|e| CryptoError::Signal(e.to_string()))?;
    }

    // ---- kyber last-resort ----
    let kyber_lr_id = KyberPreKeyId::from(kyber_last_resort_id as u32);
    let kyber_lr_record = KyberPreKeyRecord::generate(
        libsignal_protocol::kem::KeyType::Kyber1024,
        kyber_lr_id,
        identity.private_key(),
    )
    .map_err(|e| CryptoError::Signal(e.to_string()))?;
    let kyber_lr_pub_bytes = {
        let pk = kyber_lr_record
            .public_key()
            .map_err(|e| CryptoError::Signal(e.to_string()))?;
        pk.serialize()
    };
    let kyber_lr_sig = GenericSignedPreKey::signature(&kyber_lr_record)
        .map_err(|e| CryptoError::Signal(e.to_string()))?;
    {
        let mut store = Store::new(state.db.clone());
        libsignal_protocol::KyberPreKeyStore::save_kyber_pre_key(&mut store, kyber_lr_id, &kyber_lr_record)
            .await
            .map_err(|e| CryptoError::Signal(e.to_string()))?;
    }

    // ---- one-time prekeys (X25519) ----
    let mut otk_pairs: Vec<(i64, String)> = Vec::with_capacity(count);
    for _ in 0..count {
        let kp = KeyPair::generate(&mut rng);
        let id = PreKeyId::from(next_id as u32);
        let record = PreKeyRecord::new(id, &kp);
        {
            let mut store = Store::new(state.db.clone());
            libsignal_protocol::PreKeyStore::save_pre_key(&mut store, id, &record)
                .await
                .map_err(|e| CryptoError::Signal(e.to_string()))?;
        }
        otk_pairs.push((next_id, hex::encode(kp.public_key.serialize())));
        next_id += 1;
    }

    // ---- one-time prekeys (Kyber) ----
    let mut kyber_otk_pairs: Vec<(i64, String)> = Vec::with_capacity(count);
    for _ in 0..count {
        let id = KyberPreKeyId::from(next_id as u32);
        let record = KyberPreKeyRecord::generate(
            libsignal_protocol::kem::KeyType::Kyber1024,
            id,
            identity.private_key(),
        )
        .map_err(|e| CryptoError::Signal(e.to_string()))?;
        let pub_bytes = {
            let pk = record.public_key().map_err(|e| CryptoError::Signal(e.to_string()))?;
            pk.serialize()
        };
        {
            let mut store = Store::new(state.db.clone());
            libsignal_protocol::KyberPreKeyStore::save_kyber_pre_key(&mut store, id, &record)
                .await
                .map_err(|e| CryptoError::Signal(e.to_string()))?;
        }
        kyber_otk_pairs.push((next_id, hex::encode(&pub_bytes)));
        next_id += 1;
    }

    // ---- persist the id cursor ----
    sqlx::query("UPDATE identity_state SET next_prekey_id = ? WHERE id = 1")
        .bind(next_id)
        .execute(&state.db)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    // ---- upload public halves ----
    let signed_pub_hex = hex::encode(&signed_pub_bytes);
    let signed_sig_hex = hex::encode(&signed_sig);
    let kyber_lr_pub_hex = hex::encode(&kyber_lr_pub_bytes);
    let kyber_lr_sig_hex = hex::encode(&kyber_lr_sig);

    let otk_json: Vec<serde_json::Value> = otk_pairs
        .iter()
        .map(|(id, pub_hex)| serde_json::json!({ "id": id, "pub": pub_hex }))
        .collect();
    let kyber_otk_json: Vec<serde_json::Value> = kyber_otk_pairs
        .iter()
        .map(|(id, pub_hex)| serde_json::json!({ "id": id, "pub": pub_hex }))
        .collect();

    let body = serde_json::json!({
        "signed_prekey": {
            "id": signed_prekey_id,
            "pub": signed_pub_hex,
            "sig": signed_sig_hex,
        },
        "kyber_last_resort": {
            "id": kyber_last_resort_id,
            "pub": kyber_lr_pub_hex,
            "sig": kyber_lr_sig_hex,
        },
        "one_time_prekeys": otk_json,
        "kyber_one_time_prekeys": kyber_otk_json,
    });

    let token = bearer(state).await.map_err(|e| CryptoError::Database(e.to_string()))?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/devices/me/prekeys", &body, Some(&token))
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

    Ok((otk_pairs.len(), kyber_otk_pairs.len()))
}
