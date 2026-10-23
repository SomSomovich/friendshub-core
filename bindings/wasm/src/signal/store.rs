//! In-memory implementations of libsignal's stores and the WEB-compatible
//! snapshot format. IndexedDB remains outside this crate.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use async_trait::async_trait;
use libsignal_protocol::error::Result as SignalResult;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, PublicKey, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::JsValue;

use super::js_err;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IdentityChangeEntry {
    pub account_id: String,
    pub device_number: u32,
    pub old_key_hex: String,
    pub new_key_hex: String,
    pub changed_at: i64,
}

#[derive(Default)]
pub(crate) struct StoreInner {
    pub identity: Option<IdentityKeyPair>,
    pub registration_id: u32,
    pub peer_identities: HashMap<(String, u32), IdentityKey>,
    pub pre_keys: HashMap<u32, PreKeyRecord>,
    pub signed_pre_keys: HashMap<u32, SignedPreKeyRecord>,
    pub kyber_pre_keys: HashMap<u32, KyberPreKeyRecord>,
    pub sessions: HashMap<(String, u32), SessionRecord>,
    pub sender_keys: HashMap<(String, u32, Uuid), SenderKeyRecord>,
    pub group_sender_keys: HashMap<String, Uuid>,
    pub identity_changes: Vec<IdentityChangeEntry>,
}

#[derive(Clone, Default)]
pub(crate) struct Store {
    pub inner: Rc<RefCell<StoreInner>>,
}

thread_local! {
    static STORES: RefCell<HashMap<String, Store>> = RefCell::new(HashMap::new());
}

pub(crate) fn with_store<F, R>(account_id: &str, f: F) -> R
where
    F: FnOnce(&Store) -> R,
{
    STORES.with(|stores| {
        let store = {
            let mut stores = stores.borrow_mut();
            stores.entry(account_id.to_owned()).or_default().clone()
        };
        f(&store)
    })
}

pub(crate) fn drop_store(account_id: &str) {
    STORES.with(|stores| {
        stores.borrow_mut().remove(account_id);
    });
}

fn addr_key(address: &ProtocolAddress) -> (String, u32) {
    (address.name().to_owned(), u32::from(address.device_id()))
}

#[async_trait(?Send)]
impl IdentityKeyStore for Store {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        self.inner
            .borrow()
            .identity
            .clone()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("no local identity".into()))
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        Ok(self.inner.borrow().registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let key = addr_key(address);
        let mut inner = self.inner.borrow_mut();
        let changed = inner
            .peer_identities
            .get(&key)
            .is_none_or(|existing| existing != identity);

        if changed && let Some(previous) = inner.peer_identities.get(&key).cloned() {
            inner.identity_changes.push(IdentityChangeEntry {
                account_id: key.0.clone(),
                device_number: key.1,
                old_key_hex: hex::encode(previous.serialize()),
                new_key_hex: hex::encode(identity.serialize()),
                changed_at: super::now_unix(),
            });
        }

        inner.peer_identities.insert(key, identity.clone());
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
    ) -> SignalResult<bool> {
        // WEB presents recorded key changes to the user after decrypting.
        Ok(true)
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        Ok(self
            .inner
            .borrow()
            .peer_identities
            .get(&addr_key(address))
            .cloned())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for Store {
    async fn get_pre_key(&self, id: PreKeyId) -> SignalResult<PreKeyRecord> {
        let id = u32::from(id);
        self.inner
            .borrow()
            .pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| SignalProtocolError::InvalidArgument(format!("prekey {id} not found")))
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SignalResult<()> {
        self.inner
            .borrow_mut()
            .pre_keys
            .insert(u32::from(id), record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> SignalResult<()> {
        self.inner.borrow_mut().pre_keys.remove(&u32::from(id));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for Store {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SignalResult<SignedPreKeyRecord> {
        let id = u32::from(id);
        self.inner
            .borrow()
            .signed_pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("signed prekey {id} not found"))
            })
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        self.inner
            .borrow_mut()
            .signed_pre_keys
            .insert(u32::from(id), record.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for Store {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SignalResult<KyberPreKeyRecord> {
        let id = u32::from(id);
        self.inner
            .borrow()
            .kyber_pre_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("Kyber prekey {id} not found"))
            })
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        self.inner
            .borrow_mut()
            .kyber_pre_keys
            .insert(u32::from(id), record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _id: KyberPreKeyId,
        _ec: SignedPreKeyId,
        _base: &PublicKey,
    ) -> SignalResult<()> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for Store {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        Ok(self
            .inner
            .borrow()
            .sessions
            .get(&addr_key(address))
            .cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        self.inner
            .borrow_mut()
            .sessions
            .insert(addr_key(address), record.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for Store {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> SignalResult<()> {
        let (account_id, device_number) = addr_key(sender);
        self.inner
            .borrow_mut()
            .sender_keys
            .insert((account_id, device_number, distribution_id), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> SignalResult<Option<SenderKeyRecord>> {
        let (account_id, device_number) = addr_key(sender);
        Ok(self
            .inner
            .borrow()
            .sender_keys
            .get(&(account_id, device_number, distribution_id))
            .cloned())
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot {
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub registration_id: u32,
    #[serde(default)]
    pub peer_identities: Vec<(String, u32, String)>,
    #[serde(default)]
    pub pre_keys: Vec<(u32, String)>,
    #[serde(default)]
    pub signed_pre_keys: Vec<(u32, String)>,
    #[serde(default)]
    pub kyber_pre_keys: Vec<(u32, String)>,
    #[serde(default)]
    pub sessions: Vec<(String, u32, String)>,
    #[serde(default)]
    pub sender_keys: Vec<(String, u32, String, String)>,
    #[serde(default)]
    pub group_sender_keys: Vec<(String, String)>,
    #[serde(default)]
    pub identity_changes: Vec<IdentityChangeEntry>,
}

pub(crate) fn snapshot_inner(store: &Store) -> Result<String, JsValue> {
    let inner = store.inner.borrow();
    let snapshot = Snapshot {
        identity: inner
            .identity
            .as_ref()
            .map(|identity| hex::encode(identity.serialize())),
        registration_id: inner.registration_id,
        peer_identities: inner
            .peer_identities
            .iter()
            .map(|((account_id, device_number), identity)| {
                (
                    account_id.clone(),
                    *device_number,
                    hex::encode(identity.serialize()),
                )
            })
            .collect(),
        pre_keys: inner
            .pre_keys
            .iter()
            .map(|(id, record)| {
                record
                    .serialize()
                    .map(|bytes| (*id, hex::encode(bytes)))
                    .map_err(js_err)
            })
            .collect::<Result<_, _>>()?,
        signed_pre_keys: inner
            .signed_pre_keys
            .iter()
            .map(|(id, record)| {
                GenericSignedPreKey::serialize(record)
                    .map(|bytes| (*id, hex::encode(bytes)))
                    .map_err(js_err)
            })
            .collect::<Result<_, _>>()?,
        kyber_pre_keys: inner
            .kyber_pre_keys
            .iter()
            .map(|(id, record)| {
                GenericSignedPreKey::serialize(record)
                    .map(|bytes| (*id, hex::encode(bytes)))
                    .map_err(js_err)
            })
            .collect::<Result<_, _>>()?,
        sessions: inner
            .sessions
            .iter()
            .map(|((account_id, device_number), record)| {
                record
                    .serialize()
                    .map(|bytes| (account_id.clone(), *device_number, hex::encode(bytes)))
                    .map_err(js_err)
            })
            .collect::<Result<_, _>>()?,
        sender_keys: inner
            .sender_keys
            .iter()
            .map(|((account_id, device_number, distribution_id), record)| {
                record
                    .serialize()
                    .map(|bytes| {
                        (
                            account_id.clone(),
                            *device_number,
                            distribution_id.to_string(),
                            hex::encode(bytes),
                        )
                    })
                    .map_err(js_err)
            })
            .collect::<Result<_, _>>()?,
        group_sender_keys: inner
            .group_sender_keys
            .iter()
            .map(|(conversation_id, distribution_id)| {
                (conversation_id.clone(), distribution_id.to_string())
            })
            .collect(),
        identity_changes: inner.identity_changes.clone(),
    };

    serde_json::to_string(&snapshot).map_err(js_err)
}

pub(crate) fn restore_inner(store: &Store, json: &str) -> Result<(), JsValue> {
    let snapshot: Snapshot = serde_json::from_str(json).map_err(js_err)?;
    let mut restored = StoreInner {
        registration_id: snapshot.registration_id,
        identity_changes: snapshot.identity_changes,
        ..StoreInner::default()
    };

    if let Some(identity_hex) = snapshot.identity {
        let bytes = hex::decode(identity_hex).map_err(js_err)?;
        restored.identity = Some(decode_identity_key_pair(&bytes).map_err(js_err)?);
    }
    for (account_id, device_number, identity_hex) in snapshot.peer_identities {
        let bytes = hex::decode(identity_hex).map_err(js_err)?;
        restored.peer_identities.insert(
            (account_id, device_number),
            IdentityKey::decode(&bytes).map_err(js_err)?,
        );
    }
    for (id, value) in snapshot.pre_keys {
        let bytes = hex::decode(value).map_err(js_err)?;
        restored
            .pre_keys
            .insert(id, PreKeyRecord::deserialize(&bytes).map_err(js_err)?);
    }
    for (id, value) in snapshot.signed_pre_keys {
        let bytes = hex::decode(value).map_err(js_err)?;
        restored.signed_pre_keys.insert(
            id,
            <SignedPreKeyRecord as GenericSignedPreKey>::deserialize(&bytes).map_err(js_err)?,
        );
    }
    for (id, value) in snapshot.kyber_pre_keys {
        let bytes = hex::decode(value).map_err(js_err)?;
        restored.kyber_pre_keys.insert(
            id,
            <KyberPreKeyRecord as GenericSignedPreKey>::deserialize(&bytes).map_err(js_err)?,
        );
    }
    for (account_id, device_number, value) in snapshot.sessions {
        let bytes = hex::decode(value).map_err(js_err)?;
        restored.sessions.insert(
            (account_id, device_number),
            SessionRecord::deserialize(&bytes).map_err(js_err)?,
        );
    }
    for (account_id, device_number, distribution_id, value) in snapshot.sender_keys {
        let bytes = hex::decode(value).map_err(js_err)?;
        let distribution_id = Uuid::parse_str(&distribution_id).map_err(js_err)?;
        restored.sender_keys.insert(
            (account_id, device_number, distribution_id),
            SenderKeyRecord::deserialize(&bytes).map_err(js_err)?,
        );
    }
    for (conversation_id, distribution_id) in snapshot.group_sender_keys {
        restored.group_sender_keys.insert(
            conversation_id,
            Uuid::parse_str(&distribution_id).map_err(js_err)?,
        );
    }

    *store.inner.borrow_mut() = restored;
    Ok(())
}

pub(crate) fn decode_identity_key_pair(bytes: &[u8]) -> SignalResult<IdentityKeyPair> {
    // v0.103.1's serialized keypair is protobuf encoded (69 bytes); it is not
    // the old hand-sliced 65-byte public+private representation.
    IdentityKeyPair::try_from(bytes).map_err(|error| {
        SignalProtocolError::InvalidArgument(format!("identity key pair: {error}"))
    })
}
