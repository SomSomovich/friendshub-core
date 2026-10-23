//! Device initialization: identity key, registration, prekey provisioning.
//!
//! Initialization progress and unacknowledged prekey uploads are durable so a
//! transient network failure can be retried without changing the local
//! identity or publishing keys that no longer match the private records.

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyId,
    PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::api::common::bearer;
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::runtime::ActorState;

/// Number of one-time prekeys generated on first setup.
pub const INITIAL_OTK_COUNT: usize = 100;

/// Minimum pool size below which `ensure_prekeys` tops up.
pub const MIN_OTK_THRESHOLD: usize = 10;

// Actor requests are spawned concurrently. A process-wide lock keeps identity
// creation and the entire reserve/generate/persist/upload sequence serialized,
// so key ID ranges cannot overlap even when multiple Client handles share the
// same SQLite database.
static DEVICE_INIT_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Debug, Clone, Serialize)]
pub struct InitResult {
    pub device_id: String,
    pub device_number: i64,
    pub registration_id: i64,
    pub one_time_prekeys: usize,
    pub kyber_one_time_prekeys: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyReconciliation {
    /// The old local identity has no corresponding server device yet.
    RegistrationPending,
    /// A matching server device exists, but its published prekey state needs repair.
    PrekeysPending,
    /// The matching server device already has a complete published prekey state.
    Complete,
}

#[derive(Debug)]
struct DeviceInitState {
    stage: String,
    device_name: String,
    device_id: Option<String>,
    device_number: Option<i64>,
    initial_otk_count: usize,
    initial_kyber_otk_count: usize,
}

#[derive(Debug, Clone)]
struct PendingPrekeyUpload {
    payload: Value,
    one_time_count: usize,
    kyber_one_time_count: usize,
    purpose: String,
}

#[derive(Serialize, Deserialize)]
struct PublicPreKey {
    id: i64,
    #[serde(rename = "pub")]
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct SignedPublicPreKey {
    id: i64,
    #[serde(rename = "pub")]
    public_key: String,
    sig: String,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn crypto_db_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::Database(error.to_string())
}

fn signal_key_id(id: i64) -> CryptoResult<u32> {
    u32::try_from(id).map_err(|_| CryptoError::Invalid(format!("prekey id out of range: {id}")))
}

async fn load_init_state(state: &ActorState) -> CryptoResult<Option<DeviceInitState>> {
    let row: Option<(String, String, Option<String>, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT stage, device_name, device_id, device_number,
                initial_otk_count, initial_kyber_otk_count
           FROM device_init_state WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crypto_db_error)?;
    Ok(row.map(
        |(stage, device_name, device_id, device_number, initial_otk, initial_kyber)| {
            DeviceInitState {
                stage,
                device_name,
                device_id,
                device_number,
                initial_otk_count: initial_otk as usize,
                initial_kyber_otk_count: initial_kyber as usize,
            }
        },
    ))
}

async fn has_local_identity(state: &ActorState) -> CryptoResult<bool> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_state WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .map_err(crypto_db_error)?;
    Ok(count > 0)
}

pub async fn is_initialized(state: &ActorState) -> CryptoResult<bool> {
    let _guard = DEVICE_INIT_LOCK.lock().await;
    is_initialized_unlocked(state).await
}

async fn is_initialized_unlocked(state: &ActorState) -> CryptoResult<bool> {
    if !has_local_identity(state).await? {
        return Ok(false);
    }

    if let Some(progress) = load_init_state(state).await? {
        return Ok(progress.stage == "complete");
    }

    Ok(reconcile_legacy_identity(state, None).await? == LegacyReconciliation::Complete)
}

/// Reconciles identity rows written by the old initializer, which persisted
/// identity and prekeys before the server had acknowledged either operation.
/// Local prekey records cannot prove publication, so only the authenticated
/// server's device list and prekey status decide whether the old install is
/// complete.
async fn reconcile_legacy_identity(
    state: &ActorState,
    retry_device_name: Option<&str>,
) -> CryptoResult<LegacyReconciliation> {
    let identity = load_identity(state).await?;
    let registration_id: i64 =
        sqlx::query_scalar("SELECT registration_id FROM identity_state WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .map_err(crypto_db_error)?;
    let identity_key_pub = hex::encode(identity.identity_key().serialize());
    let token = bearer(state)
        .await
        .map_err(|error| CryptoError::Database(error.to_string()))?;
    let devices: Vec<crate::api::devices::DeviceItem> = state
        .http
        .get("/api/v1/devices", Some(&token))
        .await
        .map_err(|error| CryptoError::Database(error.to_string()))?;
    let active_device_count = devices.len();
    let registered = devices.into_iter().find(|device| {
        device.registration_id == registration_id
            && device
                .identity_key_pub
                .eq_ignore_ascii_case(&identity_key_pub)
    });

    let Some(device) = registered else {
        if let Some(name) = retry_device_name {
            let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
            sqlx::query(
                "INSERT INTO device_init_state
                     (id, stage, device_name, initial_otk_count, initial_kyber_otk_count)
                 VALUES (1, 'registration_pending', ?, ?, ?)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(name)
            .bind(INITIAL_OTK_COUNT as i64)
            .bind(INITIAL_OTK_COUNT as i64)
            .execute(&mut *tx)
            .await
            .map_err(crypto_db_error)?;
            tx.commit().await.map_err(crypto_db_error)?;
            return Ok(LegacyReconciliation::RegistrationPending);
        }
        return Ok(LegacyReconciliation::RegistrationPending);
    };

    let session_device_number: Option<i64> =
        sqlx::query_scalar("SELECT device_number FROM auth_state WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .map_err(crypto_db_error)?
            .flatten();
    // Normally login persisted the session's selected device number. Older
    // logins can leave it NULL, including after device registration committed
    // but its response was lost. Recovering from the unique identity+reg-id
    // match is safe only when it is also the account's sole active device:
    // the backend's `/devices/me/prekeys/status` endpoint is bound to the
    // immutable session device, and the device allocator only falls back to a
    // different number when another active device already occupies the
    // session's preferred number. With multiple active devices there is no
    // API contract that identifies which one owns this bearer session.
    let can_recover_missing_number = session_device_number.is_none() && active_device_count == 1;
    if session_device_number != Some(device.device_number) && !can_recover_missing_number {
        return Err(CryptoError::Invalid(format!(
            "legacy device {} does not match the authenticated session device {:?} and cannot be safely recovered from {} active devices; refusing to reconcile another device's prekeys",
            device.device_number, session_device_number, active_device_count
        )));
    }

    let prekeys: crate::api::prekeys::PrekeyStatusResponse = state
        .http
        .get("/api/v1/devices/me/prekeys/status", Some(&token))
        .await
        .map_err(|error| CryptoError::Database(error.to_string()))?;
    let one_time_available = usize::try_from(prekeys.one_time_available.max(0)).unwrap_or(0);
    let kyber_one_time_available =
        usize::try_from(prekeys.kyber_one_time_available.max(0)).unwrap_or(0);
    let one_time_to_publish = if one_time_available < MIN_OTK_THRESHOLD {
        INITIAL_OTK_COUNT.saturating_sub(one_time_available)
    } else {
        0
    };
    let kyber_to_publish = if kyber_one_time_available < MIN_OTK_THRESHOLD {
        INITIAL_OTK_COUNT.saturating_sub(kyber_one_time_available)
    } else {
        0
    };
    let complete = one_time_to_publish == 0
        && kyber_to_publish == 0
        && prekeys.has_signed_prekey
        && prekeys.has_kyber_last_resort;
    let stage = if complete {
        "complete"
    } else {
        "prekeys_pending"
    };

    let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
    sqlx::query(
        "INSERT INTO device_init_state
             (id, stage, device_name, device_id, device_number,
              initial_otk_count, initial_kyber_otk_count)
         VALUES (1, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(stage)
    .bind(device.name)
    .bind(device.id)
    .bind(device.device_number)
    .bind(one_time_to_publish as i64)
    .bind(kyber_to_publish as i64)
    .execute(&mut *tx)
    .await
    .map_err(crypto_db_error)?;
    sqlx::query("UPDATE auth_state SET device_number = ? WHERE id = 1")
        .bind(device.device_number)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    tx.commit().await.map_err(crypto_db_error)?;

    Ok(if complete {
        LegacyReconciliation::Complete
    } else {
        LegacyReconciliation::PrekeysPending
    })
}

async fn load_identity(state: &ActorState) -> CryptoResult<IdentityKeyPair> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT key_pair FROM identity_state WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .map_err(crypto_db_error)?;

    let blob = row.ok_or(CryptoError::NoIdentity)?.0;
    crate::crypto::stores::decode_identity_key_pair(&blob)
        .map_err(|e| CryptoError::Signal(e.to_string()))
}

/// Starts device setup or resumes its last durable stage after a failed call.
pub async fn initialize(state: &ActorState, name: &str) -> CryptoResult<InitResult> {
    let _guard = DEVICE_INIT_LOCK.lock().await;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(CryptoError::Invalid(
            "device name must contain 1-64 characters".into(),
        ));
    }

    if has_local_identity(state).await? {
        let Some(progress) = load_init_state(state).await? else {
            return match reconcile_legacy_identity(state, Some(name)).await? {
                LegacyReconciliation::Complete => {
                    Err(CryptoError::Invalid("device is already initialized".into()))
                }
                LegacyReconciliation::RegistrationPending => {
                    finish_initialization_with_registration_lookup(state, false).await
                }
                LegacyReconciliation::PrekeysPending => finish_initialization(state).await,
            };
        };
        if progress.stage == "complete" {
            return Err(CryptoError::Invalid("device is already initialized".into()));
        }
        return finish_initialization(state).await;
    }

    let mut signal_rng = signal_rand::rng();
    let identity = IdentityKeyPair::generate(&mut signal_rng);
    let registration_id: u32 = rand::rng().random_range(0..16384);
    let identity_blob = identity.serialize().to_vec();

    // The identity and its retry stage are committed together. Every network
    // failure from here onward can resume with these same credentials.
    let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
    sqlx::query(
        "INSERT INTO identity_state (id, key_pair, registration_id, next_prekey_id) VALUES (1, ?, ?, 1)",
    )
    .bind(&identity_blob)
    .bind(registration_id as i64)
    .execute(&mut *tx)
    .await
    .map_err(crypto_db_error)?;
    sqlx::query(
        "INSERT INTO device_init_state
             (id, stage, device_name, initial_otk_count, initial_kyber_otk_count)
         VALUES (1, 'registration_pending', ?, ?, ?)",
    )
    .bind(name)
    .bind(INITIAL_OTK_COUNT as i64)
    .bind(INITIAL_OTK_COUNT as i64)
    .execute(&mut *tx)
    .await
    .map_err(crypto_db_error)?;
    tx.commit().await.map_err(crypto_db_error)?;

    finish_initialization(state).await
}

async fn finish_initialization(state: &ActorState) -> CryptoResult<InitResult> {
    finish_initialization_with_registration_lookup(state, true).await
}

async fn finish_initialization_with_registration_lookup(
    state: &ActorState,
    check_registration: bool,
) -> CryptoResult<InitResult> {
    let mut progress = load_init_state(state)
        .await?
        .ok_or_else(|| CryptoError::Invalid("missing device initialization state".into()))?;
    let identity = load_identity(state).await?;

    if progress.stage == "registration_pending" {
        let registration_id: i64 =
            sqlx::query_scalar("SELECT registration_id FROM identity_state WHERE id = 1")
                .fetch_one(&state.db)
                .await
                .map_err(crypto_db_error)?;
        let identity_key_pub = hex::encode(identity.identity_key().serialize());
        let token = bearer(state)
            .await
            .map_err(|error| CryptoError::Database(error.to_string()))?;

        // A prior POST may have succeeded while its response was lost. Query
        // the authenticated device list first, matching the stable identity
        // key and registration ID, before attempting another registration.
        let registered = if check_registration {
            let devices: Vec<crate::api::devices::DeviceItem> = state
                .http
                .get("/api/v1/devices", Some(&token))
                .await
                .map_err(|error| CryptoError::Database(error.to_string()))?;
            devices.into_iter().find(|device| {
                device.registration_id == registration_id
                    && device
                        .identity_key_pub
                        .eq_ignore_ascii_case(&identity_key_pub)
            })
        } else {
            None
        };
        let (device_id, device_number) = if let Some(device) = registered {
            (device.id, device.device_number)
        } else {
            let body = serde_json::json!({
                "name": progress.device_name,
                "registration_id": registration_id,
                "identity_key_pub": identity_key_pub,
            });
            let response: crate::api::devices::DeviceItem = state
                .http
                .post("/api/v1/devices", &body, Some(&token))
                .await
                .map_err(|error| CryptoError::Database(error.to_string()))?;
            (response.id, response.device_number)
        };

        let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
        sqlx::query(
            "UPDATE device_init_state
                SET stage = 'prekeys_pending', device_id = ?, device_number = ?
              WHERE id = 1 AND stage = 'registration_pending'",
        )
        .bind(&device_id)
        .bind(device_number)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
        sqlx::query("UPDATE auth_state SET device_number = ? WHERE id = 1")
            .bind(device_number)
            .execute(&mut *tx)
            .await
            .map_err(crypto_db_error)?;
        tx.commit().await.map_err(crypto_db_error)?;
        progress.stage = "prekeys_pending".into();
        progress.device_id = Some(device_id);
        progress.device_number = Some(device_number);
    }

    if progress.stage == "prekeys_pending" {
        if load_pending_prekey_upload(state).await?.is_none() {
            persist_new_prekey_batch(
                state,
                &identity,
                progress.initial_otk_count,
                progress.initial_kyber_otk_count,
                "initial",
            )
            .await?;
        }
        upload_pending_prekey_batch(state).await?;
        progress = load_init_state(state)
            .await?
            .ok_or_else(|| CryptoError::Invalid("missing device initialization state".into()))?;
    }

    if progress.stage != "complete" {
        return Err(CryptoError::Invalid(format!(
            "unexpected device initialization stage: {}",
            progress.stage
        )));
    }

    let registration_id: i64 =
        sqlx::query_scalar("SELECT registration_id FROM identity_state WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .map_err(crypto_db_error)?;
    Ok(InitResult {
        device_id: progress
            .device_id
            .ok_or_else(|| CryptoError::Invalid("registered device id is missing".into()))?,
        device_number: progress
            .device_number
            .ok_or_else(|| CryptoError::Invalid("registered device number is missing".into()))?,
        registration_id,
        one_time_prekeys: progress.initial_otk_count,
        kyber_one_time_prekeys: progress.initial_kyber_otk_count,
    })
}

/// Ensures both independent one-time-prekey pools have a healthy reserve.
/// Any durable upload left by an earlier failed call is retried first.
pub async fn ensure_prekeys(state: &ActorState) -> CryptoResult<usize> {
    let _guard = DEVICE_INIT_LOCK.lock().await;
    if !has_local_identity(state).await? {
        return Err(CryptoError::NoIdentity);
    }

    if !is_initialized_unlocked(state).await? {
        let result = finish_initialization(state).await?;
        return Ok(result.one_time_prekeys);
    }

    let identity = load_identity(state).await?;
    let mut generated = 0;
    if let Some(pending) = load_pending_prekey_upload(state).await? {
        generated += pending.one_time_count;
        upload_pending_prekey_batch(state).await?;
    }

    let available_otk: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pre_keys")
        .fetch_one(&state.db)
        .await
        .map_err(crypto_db_error)?;
    let available_kyber: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kyber_pre_keys
          WHERE key_kind = 'one_time' AND used = 0",
    )
    .fetch_one(&state.db)
    .await
    .map_err(crypto_db_error)?;

    let have_otk = usize::try_from(available_otk).unwrap_or(0);
    let have_kyber = usize::try_from(available_kyber).unwrap_or(0);
    let needed_otk = if have_otk < MIN_OTK_THRESHOLD {
        INITIAL_OTK_COUNT.saturating_sub(have_otk)
    } else {
        0
    };
    let needed_kyber = if have_kyber < MIN_OTK_THRESHOLD {
        INITIAL_OTK_COUNT.saturating_sub(have_kyber)
    } else {
        0
    };

    if needed_otk > 0 || needed_kyber > 0 {
        persist_new_prekey_batch(state, &identity, needed_otk, needed_kyber, "replenish").await?;
        let pending = load_pending_prekey_upload(state)
            .await?
            .ok_or_else(|| CryptoError::Invalid("prekey upload was not persisted".into()))?;
        generated += pending.one_time_count;
        upload_pending_prekey_batch(state).await?;
    }

    Ok(generated)
}

async fn load_pending_prekey_upload(
    state: &ActorState,
) -> CryptoResult<Option<PendingPrekeyUpload>> {
    let row: Option<(String, i64, i64, String)> = sqlx::query_as(
        "SELECT payload, one_time_count, kyber_one_time_count, purpose
           FROM device_init_pending_prekeys WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crypto_db_error)?;
    let Some((payload, one_time_count, kyber_count, purpose)) = row else {
        return Ok(None);
    };
    let payload: Value = serde_json::from_str(&payload)
        .map_err(|error| CryptoError::Invalid(format!("stored prekey upload: {error}")))?;
    let one_time_count = usize::try_from(one_time_count)
        .map_err(|_| CryptoError::Invalid("stored one-time prekey count is negative".into()))?;
    let kyber_one_time_count = usize::try_from(kyber_count)
        .map_err(|_| CryptoError::Invalid("stored Kyber prekey count is negative".into()))?;
    let payload_one_time_count = payload
        .get("one_time_prekeys")
        .and_then(Value::as_array)
        .map(Vec::len);
    let payload_kyber_count = payload
        .get("kyber_one_time_prekeys")
        .and_then(Value::as_array)
        .map(Vec::len);
    if payload_one_time_count != Some(one_time_count)
        || payload_kyber_count != Some(kyber_one_time_count)
    {
        return Err(CryptoError::Invalid(
            "stored prekey upload does not match its committed counts".into(),
        ));
    }
    Ok(Some(PendingPrekeyUpload {
        payload,
        one_time_count,
        kyber_one_time_count,
        purpose,
    }))
}

async fn persist_new_prekey_batch(
    state: &ActorState,
    identity: &IdentityKeyPair,
    one_time_count: usize,
    kyber_one_time_count: usize,
    purpose: &str,
) -> CryptoResult<()> {
    let mut next_id: i64 =
        sqlx::query_scalar("SELECT next_prekey_id FROM identity_state WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .map_err(crypto_db_error)?;
    let signed_prekey_id = next_id;
    next_id = next_id
        .checked_add(1)
        .ok_or_else(|| CryptoError::Invalid("prekey ID space exhausted".into()))?;
    let kyber_last_resort_id = next_id;
    next_id = next_id
        .checked_add(1)
        .ok_or_else(|| CryptoError::Invalid("prekey ID space exhausted".into()))?;

    let mut rng = signal_rand::rng();
    let signed_id = SignedPreKeyId::from(signal_key_id(signed_prekey_id)?);
    let signed_key_pair = KeyPair::generate(&mut rng);
    let signed_pub = signed_key_pair.public_key.serialize();
    let signed_sig = identity
        .private_key()
        .calculate_signature(&signed_pub, &mut rng)
        .map_err(|error| CryptoError::Signal(error.to_string()))?;
    let signed_record = SignedPreKeyRecord::new(
        signed_id,
        Timestamp::from_epoch_millis(now_millis()),
        &signed_key_pair,
        &signed_sig,
    );
    let signed_record_blob = signed_record
        .serialize()
        .map_err(|error| CryptoError::Signal(error.to_string()))?;

    let kyber_lr_id = KyberPreKeyId::from(signal_key_id(kyber_last_resort_id)?);
    let kyber_lr_record = KyberPreKeyRecord::generate(
        libsignal_protocol::kem::KeyType::Kyber1024,
        kyber_lr_id,
        identity.private_key(),
    )
    .map_err(|error| CryptoError::Signal(error.to_string()))?;
    let kyber_lr_pub = kyber_lr_record
        .public_key()
        .map_err(|error| CryptoError::Signal(error.to_string()))?
        .serialize();
    let kyber_lr_sig = GenericSignedPreKey::signature(&kyber_lr_record)
        .map_err(|error| CryptoError::Signal(error.to_string()))?;
    let kyber_lr_blob = GenericSignedPreKey::serialize(&kyber_lr_record)
        .map_err(|error| CryptoError::Signal(error.to_string()))?;

    let mut otk_records = Vec::with_capacity(one_time_count);
    let mut otk_public = Vec::with_capacity(one_time_count);
    for _ in 0..one_time_count {
        let id = PreKeyId::from(signal_key_id(next_id)?);
        let key_pair = KeyPair::generate(&mut rng);
        let record = PreKeyRecord::new(id, &key_pair);
        let blob = record
            .serialize()
            .map_err(|error| CryptoError::Signal(error.to_string()))?;
        otk_records.push((next_id, blob));
        otk_public.push(PublicPreKey {
            id: next_id,
            public_key: hex::encode(key_pair.public_key.serialize()),
        });
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| CryptoError::Invalid("prekey ID space exhausted".into()))?;
    }

    let mut kyber_records = Vec::with_capacity(kyber_one_time_count);
    let mut kyber_public = Vec::with_capacity(kyber_one_time_count);
    for _ in 0..kyber_one_time_count {
        let id = KyberPreKeyId::from(signal_key_id(next_id)?);
        let record = KyberPreKeyRecord::generate(
            libsignal_protocol::kem::KeyType::Kyber1024,
            id,
            identity.private_key(),
        )
        .map_err(|error| CryptoError::Signal(error.to_string()))?;
        let public_key = record
            .public_key()
            .map_err(|error| CryptoError::Signal(error.to_string()))?
            .serialize();
        let blob = GenericSignedPreKey::serialize(&record)
            .map_err(|error| CryptoError::Signal(error.to_string()))?;
        kyber_records.push((next_id, blob));
        kyber_public.push(PublicPreKey {
            id: next_id,
            public_key: hex::encode(public_key),
        });
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| CryptoError::Invalid("prekey ID space exhausted".into()))?;
    }

    let payload = serde_json::json!({
        "signed_prekey": SignedPublicPreKey {
            id: signed_prekey_id,
            public_key: hex::encode(signed_pub),
            sig: hex::encode(signed_sig),
        },
        "kyber_last_resort": SignedPublicPreKey {
            id: kyber_last_resort_id,
            public_key: hex::encode(kyber_lr_pub),
            sig: hex::encode(kyber_lr_sig),
        },
        "one_time_prekeys": otk_public,
        "kyber_one_time_prekeys": kyber_public,
    });
    let payload_json =
        serde_json::to_string(&payload).map_err(|error| CryptoError::Invalid(error.to_string()))?;

    // All local private records, their publication payload, and the next ID
    // cursor commit atomically before the first network upload.
    let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
    sqlx::query("INSERT INTO signed_pre_keys (prekey_id, record) VALUES (?, ?)")
        .bind(signed_prekey_id)
        .bind(signed_record_blob)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    sqlx::query("INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (?, ?, 0, 'last_resort')")
        .bind(kyber_last_resort_id)
        .bind(kyber_lr_blob)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    for (id, blob) in otk_records {
        sqlx::query("INSERT INTO pre_keys (prekey_id, record) VALUES (?, ?)")
            .bind(id)
            .bind(blob)
            .execute(&mut *tx)
            .await
            .map_err(crypto_db_error)?;
    }
    for (id, blob) in kyber_records {
        sqlx::query("INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (?, ?, 0, 'one_time')")
            .bind(id)
            .bind(blob)
            .execute(&mut *tx)
            .await
            .map_err(crypto_db_error)?;
    }
    sqlx::query("UPDATE identity_state SET next_prekey_id = ? WHERE id = 1")
        .bind(next_id)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    sqlx::query(
        "INSERT INTO device_init_pending_prekeys
             (id, payload, one_time_count, kyber_one_time_count, purpose)
         VALUES (1, ?, ?, ?, ?)",
    )
    .bind(payload_json)
    .bind(one_time_count as i64)
    .bind(kyber_one_time_count as i64)
    .bind(purpose)
    .execute(&mut *tx)
    .await
    .map_err(crypto_db_error)?;
    if purpose == "initial" {
        sqlx::query(
            "UPDATE device_init_state
                SET stage = 'prekeys_pending', initial_otk_count = ?,
                    initial_kyber_otk_count = ? WHERE id = 1",
        )
        .bind(one_time_count as i64)
        .bind(kyber_one_time_count as i64)
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    }
    tx.commit().await.map_err(crypto_db_error)
}

async fn upload_pending_prekey_batch(state: &ActorState) -> CryptoResult<()> {
    let Some(pending) = load_pending_prekey_upload(state).await? else {
        return Ok(());
    };
    tracing::debug!(
        purpose = %pending.purpose,
        one_time_count = pending.one_time_count,
        kyber_one_time_count = pending.kyber_one_time_count,
        "retrying durable prekey upload"
    );
    let token = bearer(state)
        .await
        .map_err(|error| CryptoError::Database(error.to_string()))?;
    let _: Value = state
        .http
        .post("/api/v1/devices/me/prekeys", &pending.payload, Some(&token))
        .await
        .map_err(|error| CryptoError::Database(error.to_string()))?;

    let mut tx = state.db.begin().await.map_err(crypto_db_error)?;
    sqlx::query("DELETE FROM device_init_pending_prekeys WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(crypto_db_error)?;
    if pending.purpose == "initial" {
        sqlx::query("UPDATE device_init_state SET stage = 'complete' WHERE id = 1")
            .execute(&mut *tx)
            .await
            .map_err(crypto_db_error)?;
    }
    tx.commit().await.map_err(crypto_db_error)
}
