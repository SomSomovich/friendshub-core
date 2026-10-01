//! SQLite-backed implementations of the six Signal Protocol store traits.
//!
//! The protocol entry points take several `&mut dyn Trait` arguments at
//! once, which Rust will not allow when they are all references to the same
//! value. Every store is therefore a small wrapper around a cloned
//! [`SqlitePool`]; cloning the pool is reference-counting, not connection
//! duplication, so it costs nothing to hand out one Store per parameter slot.

use async_trait::async_trait;
use sqlx::SqlitePool;

use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, KyberPreKeyId,
    KyberPreKeyRecord, PreKeyId, PreKeyRecord, PrivateKey, ProtocolAddress, PublicKey,
    SessionRecord, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
};
use libsignal_protocol::{
    IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore,
};

use crate::util::time::now_unix;

#[derive(Clone)]
pub struct Store {
    pub db: SqlitePool,
}

impl Store {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }
}

fn store_err<E: std::fmt::Display>(e: E) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("store: {e}"))
}

fn addr_name(addr: &ProtocolAddress) -> &str {
    addr.name()
}

fn addr_dev(addr: &ProtocolAddress) -> i64 {
    u32::from(addr.device_id()) as i64
}

fn prekey_u32(id: PreKeyId) -> u32 {
    u32::from(id)
}

fn signed_u32(id: SignedPreKeyId) -> u32 {
    u32::from(id)
}

fn kyber_u32(id: KyberPreKeyId) -> u32 {
    u32::from(id)
}

/// Rebuilds an `IdentityKeyPair` from the byte layout `serialize` produces:
/// a 33-byte public key followed by a 32-byte private key.
pub fn decode_identity_key_pair(
    blob: &[u8],
) -> std::result::Result<IdentityKeyPair, SignalProtocolError> {
    if blob.len() != 65 {
        return Err(SignalProtocolError::InvalidArgument(format!(
            "identity key pair blob is {} bytes, expected 65",
            blob.len()
        )));
    }

    let public = PublicKey::deserialize(&blob[..33]).map_err(store_err)?;
    let private = PrivateKey::deserialize(&blob[33..]).map_err(store_err)?;
    Ok(IdentityKeyPair::new(IdentityKey::new(public), private))
}

// ---------------------------------------------------------------
// IdentityKeyStore
// ---------------------------------------------------------------

#[async_trait(?Send)]
impl IdentityKeyStore for Store {
    async fn get_identity_key_pair(&self) -> std::result::Result<IdentityKeyPair, SignalProtocolError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT key_pair FROM identity_state WHERE id = 1")
                .fetch_optional(&self.db)
                .await
                .map_err(store_err)?;
        let blob = row
            .ok_or_else(|| SignalProtocolError::InvalidArgument("no identity configured".into()))?
            .0;
        decode_identity_key_pair(&blob)
    }

    async fn get_local_registration_id(&self) -> std::result::Result<u32, SignalProtocolError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT registration_id FROM identity_state WHERE id = 1")
                .fetch_optional(&self.db)
                .await
                .map_err(store_err)?;
        let n = row
            .ok_or_else(|| SignalProtocolError::InvalidArgument("no identity configured".into()))?
            .0;
        Ok(n as u32)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> std::result::Result<IdentityChange, SignalProtocolError> {
        let account_id = addr_name(address).to_string();
        let device_number = addr_dev(address);
        let blob = identity.serialize().to_vec();
        let now = now_unix();

        let existing: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT identity_key FROM peer_identities WHERE account_id = ? AND device_number = ?",
        )
        .bind(&account_id)
        .bind(device_number)
        .fetch_optional(&self.db)
        .await
        .map_err(store_err)?;

        let changed = match &existing {
            Some((old,)) => old.as_slice() != blob.as_slice(),
            None => true,
        };

        sqlx::query(
            "INSERT INTO peer_identities (account_id, device_number, identity_key, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(account_id, device_number) DO UPDATE SET
                identity_key = excluded.identity_key,
                updated_at = excluded.updated_at",
        )
        .bind(&account_id)
        .bind(device_number)
        .bind(&blob)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(store_err)?;

        Ok(if changed {
            IdentityChange::ReplacedExisting
        } else {
            IdentityChange::NewOrUnchanged
        })
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> std::result::Result<bool, SignalProtocolError> {
        // Trust on first use. A future version could pin the first key seen
        // for a peer and surface a warning on change, but the server here
        // already stores the identity key per device and never rotates it.
        Ok(true)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> std::result::Result<Option<IdentityKey>, SignalProtocolError> {
        let account_id = addr_name(address).to_string();
        let device_number = addr_dev(address);
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT identity_key FROM peer_identities WHERE account_id = ? AND device_number = ?",
        )
        .bind(&account_id)
        .bind(device_number)
        .fetch_optional(&self.db)
        .await
        .map_err(store_err)?;

        match row {
            Some((blob,)) => Ok(Some(IdentityKey::decode(&blob).map_err(store_err)?)),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------
// PreKeyStore
// ---------------------------------------------------------------

#[async_trait(?Send)]
impl PreKeyStore for Store {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> std::result::Result<PreKeyRecord, SignalProtocolError> {
        let id = prekey_u32(prekey_id) as i64;
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT record FROM pre_keys WHERE prekey_id = ?")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(store_err)?;
        let blob = row
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("prekey {id} not found"))
            })?
            .0;
        PreKeyRecord::deserialize(&blob)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        let id = prekey_u32(prekey_id) as i64;
        let blob = record.serialize().map_err(store_err)?;
        sqlx::query(
            "INSERT INTO pre_keys (prekey_id, record) VALUES (?, ?)
             ON CONFLICT(prekey_id) DO UPDATE SET record = excluded.record",
        )
        .bind(id)
        .bind(&blob)
        .execute(&self.db)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> std::result::Result<(), SignalProtocolError> {
        let id = prekey_u32(prekey_id) as i64;
        sqlx::query("DELETE FROM pre_keys WHERE prekey_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(store_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------
// SignedPreKeyStore
// ---------------------------------------------------------------

#[async_trait(?Send)]
impl SignedPreKeyStore for Store {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> std::result::Result<SignedPreKeyRecord, SignalProtocolError> {
        let id = signed_u32(signed_prekey_id) as i64;
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT record FROM signed_pre_keys WHERE prekey_id = ?")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(store_err)?;
        let blob = row
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("signed prekey {id} not found"))
            })?
            .0;
        <SignedPreKeyRecord as GenericSignedPreKey>::deserialize(&blob)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        let id = signed_u32(signed_prekey_id) as i64;
        let blob = GenericSignedPreKey::serialize(record).map_err(store_err)?;
        sqlx::query(
            "INSERT INTO signed_pre_keys (prekey_id, record) VALUES (?, ?)
             ON CONFLICT(prekey_id) DO UPDATE SET record = excluded.record",
        )
        .bind(id)
        .bind(&blob)
        .execute(&self.db)
        .await
        .map_err(store_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------
// KyberPreKeyStore
// ---------------------------------------------------------------

#[async_trait(?Send)]
impl KyberPreKeyStore for Store {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> std::result::Result<KyberPreKeyRecord, SignalProtocolError> {
        let id = kyber_u32(kyber_prekey_id) as i64;
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT record FROM kyber_pre_keys WHERE prekey_id = ?")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(store_err)?;
        let blob = row
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("kyber prekey {id} not found"))
            })?
            .0;
        <KyberPreKeyRecord as GenericSignedPreKey>::deserialize(&blob)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        let id = kyber_u32(kyber_prekey_id) as i64;
        let blob = GenericSignedPreKey::serialize(record).map_err(store_err)?;
        sqlx::query(
            "INSERT INTO kyber_pre_keys (prekey_id, record, used) VALUES (?, ?, 0)
             ON CONFLICT(prekey_id) DO UPDATE SET record = excluded.record",
        )
        .bind(id)
        .bind(&blob)
        .execute(&self.db)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> std::result::Result<(), SignalProtocolError> {
        let id = kyber_u32(kyber_prekey_id) as i64;
        sqlx::query("UPDATE kyber_pre_keys SET used = 1 WHERE prekey_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(store_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------

#[async_trait(?Send)]
impl SessionStore for Store {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> std::result::Result<Option<SessionRecord>, SignalProtocolError> {
        let account_id = addr_name(address).to_string();
        let device_number = addr_dev(address);
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT record FROM sessions WHERE account_id = ? AND device_number = ?",
        )
        .bind(&account_id)
        .bind(device_number)
        .fetch_optional(&self.db)
        .await
        .map_err(store_err)?;

        match row {
            Some((blob,)) => SessionRecord::deserialize(&blob).map(Some),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        let account_id = addr_name(address).to_string();
        let device_number = addr_dev(address);
        let blob = record.serialize().map_err(store_err)?;
        let now = now_unix();
        sqlx::query(
            "INSERT INTO sessions (account_id, device_number, record, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(account_id, device_number) DO UPDATE SET
                record = excluded.record,
                updated_at = excluded.updated_at",
        )
        .bind(&account_id)
        .bind(device_number)
        .bind(&blob)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(store_err)?;
        Ok(())
    }
}
