//! Signal operations exported to the browser. The names and JSON payloads
//! preserve `friendshubWEB/src/wasm`'s current bridge contract.

use libsignal_protocol::{
    CiphertextMessage, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage,
    ProtocolAddress, PublicKey, SenderKeyDistributionMessage, SignalMessage, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, Timestamp, create_sender_key_distribution_message,
    group_decrypt as signal_group_decrypt, group_encrypt as signal_group_encrypt, message_decrypt,
    message_encrypt, process_prekey_bundle, process_sender_key_distribution_message,
};
use rand::RngCore;
use serde_json::{Value, json};
use std::future::Future;
use wasm_bindgen::prelude::*;

use super::store::{
    Store, decode_identity_key_pair, drop_store, restore_inner, snapshot_inner, with_store,
};
use super::{block_on, js_err, now, now_millis};

type JsResult<T> = Result<T, JsValue>;

const MAX_REGISTRATION_ID: u32 = 16_383;

fn require_account_id(account_id: &str) -> JsResult<()> {
    if account_id.trim().is_empty() {
        return Err(js_err("account_id must not be empty"));
    }
    Ok(())
}

fn validate_registration_id(registration_id: u32) -> JsResult<()> {
    if registration_id > MAX_REGISTRATION_ID {
        return Err(js_err(format!(
            "registration_id must be in 0..={MAX_REGISTRATION_ID}"
        )));
    }
    Ok(())
}

fn device_id(value: u32, label: &str) -> JsResult<DeviceId> {
    DeviceId::try_from(value).map_err(|error| js_err(format!("{label}: {error}")))
}

fn run_signal<F, T, E>(future: F) -> JsResult<T>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    block_on(future)?.map_err(js_err)
}

fn next_prekey_id(store: &Store) -> JsResult<u32> {
    let inner = store.inner.borrow();
    inner
        .pre_keys
        .keys()
        .chain(inner.signed_pre_keys.keys())
        .chain(inner.kyber_pre_keys.keys())
        .max()
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| js_err("prekey id space is exhausted"))
}

fn checked_next_id(start: u32, count: usize) -> JsResult<u32> {
    let count = u32::try_from(count).map_err(js_err)?;
    start
        .checked_add(2)
        .and_then(|value| value.checked_add(count.checked_mul(2)?))
        .ok_or_else(|| js_err("prekey id space is exhausted"))
}

fn random_uuid_v4() -> uuid::Uuid {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

/// Returns `pong`; also useful to check that the binding was instantiated.
#[wasm_bindgen]
pub fn ping() -> String {
    "pong".to_owned()
}

/// Generates and stores the local identity, returning libsignal's serialized
/// keypair as hex. Use `local_identity_public` for the public value to register.
#[wasm_bindgen]
pub fn generate_identity(account_id: &str, registration_id: u32) -> JsResult<String> {
    require_account_id(account_id)?;
    validate_registration_id(registration_id)?;
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let serialized = identity.serialize();
    with_store(account_id, |store| {
        let mut inner = store.inner.borrow_mut();
        inner.identity = Some(identity);
        inner.registration_id = registration_id;
    });
    Ok(hex::encode(serialized))
}

/// Loads an identity previously returned by `generate_identity` or included
/// in a snapshot. The serialized representation is validated by libsignal.
#[wasm_bindgen]
pub fn load_identity(account_id: &str, identity_hex: &str, registration_id: u32) -> JsResult<()> {
    require_account_id(account_id)?;
    validate_registration_id(registration_id)?;
    let bytes = hex::decode(identity_hex).map_err(js_err)?;
    let identity = decode_identity_key_pair(&bytes).map_err(js_err)?;
    with_store(account_id, |store| {
        let mut inner = store.inner.borrow_mut();
        inner.identity = Some(identity);
        inner.registration_id = registration_id;
    });
    Ok(())
}

/// Returns the registered public identity key as hex.
#[wasm_bindgen]
pub fn local_identity_public(account_id: &str) -> JsResult<String> {
    require_account_id(account_id)?;
    with_store(account_id, |store| {
        let inner = store.inner.borrow();
        let identity = inner
            .identity
            .as_ref()
            .ok_or_else(|| js_err("no local identity"))?;
        Ok(hex::encode(identity.identity_key().serialize()))
    })
}

/// Serializes the account state in the snapshot schema already stored by WEB.
#[wasm_bindgen]
pub fn snapshot(account_id: &str) -> JsResult<String> {
    require_account_id(account_id)?;
    with_store(account_id, snapshot_inner)
}

/// Restores an opaque snapshot produced by this API or the existing WEB WASM.
#[wasm_bindgen]
pub fn restore(account_id: &str, snapshot_json: &str) -> JsResult<()> {
    require_account_id(account_id)?;
    with_store(account_id, |store| restore_inner(store, snapshot_json))
}

/// Drops and frees all state held for one account.
#[wasm_bindgen]
pub fn reset(account_id: &str) {
    drop_store(account_id);
}

/// Generates an EC and Kyber one-time prekey pool, a signed EC prekey, and the
/// Kyber last-resort prekey. The JSON response is accepted by WEB's existing
/// prekey upload adapter.
#[wasm_bindgen]
pub fn generate_prekeys(account_id: &str, count: usize) -> JsResult<String> {
    require_account_id(account_id)?;
    if count == 0 {
        return Err(js_err("prekey count must be positive"));
    }

    with_store(account_id, |store| {
        let identity = store
            .inner
            .borrow()
            .identity
            .clone()
            .ok_or_else(|| js_err("no local identity"))?;
        let first_id = next_prekey_id(store)?;
        let after_id = checked_next_id(first_id, count)?;
        let mut next_id = first_id;
        let mut rng = rand::rng();

        let signed_id = next_id;
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| js_err("prekey id space is exhausted"))?;
        let signed_key_pair = KeyPair::generate(&mut rng);
        let signed_public = signed_key_pair.public_key.serialize();
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_public, &mut rng)
            .map_err(js_err)?;
        let signed_record = SignedPreKeyRecord::new(
            SignedPreKeyId::from(signed_id),
            Timestamp::from_epoch_millis(now_millis()),
            &signed_key_pair,
            &signed_signature,
        );

        // KyberPreKeyRecord::generate calls SystemTime::now(), which panics
        // for wasm32-unknown-unknown. Construct it with the browser clock.
        let kyber_last_resort_id = next_id;
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| js_err("prekey id space is exhausted"))?;
        let kyber_last_resort_key_pair = libsignal_protocol::kem::KeyPair::generate(
            libsignal_protocol::kem::KeyType::Kyber1024,
            &mut rng,
        );
        let kyber_last_resort_public = kyber_last_resort_key_pair.public_key.serialize();
        let kyber_last_resort_signature = identity
            .private_key()
            .calculate_signature(&kyber_last_resort_public, &mut rng)
            .map_err(js_err)?
            .into_vec();
        let kyber_last_resort_record = KyberPreKeyRecord::new(
            KyberPreKeyId::from(kyber_last_resort_id),
            Timestamp::from_epoch_millis(now_millis()),
            &kyber_last_resort_key_pair,
            &kyber_last_resort_signature,
        );

        let mut one_time_prekeys = Vec::with_capacity(count);
        let mut prekey_records = Vec::with_capacity(count);
        for _ in 0..count {
            let key_pair = KeyPair::generate(&mut rng);
            let id = next_id;
            next_id = next_id
                .checked_add(1)
                .ok_or_else(|| js_err("prekey id space is exhausted"))?;
            one_time_prekeys.push(json!({
                "id": id,
                "pub": hex::encode(key_pair.public_key.serialize()),
            }));
            prekey_records.push((id, PreKeyRecord::new(PreKeyId::from(id), &key_pair)));
        }

        let mut kyber_one_time_prekeys = Vec::with_capacity(count);
        let mut kyber_records = Vec::with_capacity(count + 1);
        kyber_records.push((kyber_last_resort_id, kyber_last_resort_record));
        for _ in 0..count {
            let id = next_id;
            next_id = next_id
                .checked_add(1)
                .ok_or_else(|| js_err("prekey id space is exhausted"))?;
            let key_pair = libsignal_protocol::kem::KeyPair::generate(
                libsignal_protocol::kem::KeyType::Kyber1024,
                &mut rng,
            );
            let public = key_pair.public_key.serialize();
            let signature = identity
                .private_key()
                .calculate_signature(&public, &mut rng)
                .map_err(js_err)?
                .into_vec();
            let record = KyberPreKeyRecord::new(
                KyberPreKeyId::from(id),
                Timestamp::from_epoch_millis(now_millis()),
                &key_pair,
                &signature,
            );
            kyber_one_time_prekeys.push(json!({
                "id": id,
                "pub": hex::encode(public),
            }));
            kyber_records.push((id, record));
        }

        if next_id != after_id {
            return Err(js_err("internal prekey id accounting error"));
        }

        let result = json!({
            "signed_prekey": {
                "id": signed_id,
                "pub": hex::encode(signed_public),
                "sig": hex::encode(signed_signature),
            },
            "kyber_last_resort": {
                "id": kyber_last_resort_id,
                "pub": hex::encode(kyber_last_resort_public),
                "sig": hex::encode(kyber_last_resort_signature),
            },
            "one_time_prekeys": one_time_prekeys,
            "kyber_one_time_prekeys": kyber_one_time_prekeys,
        });
        let json = serde_json::to_string(&result).map_err(js_err)?;

        // Keep the update atomic: a generation/serialization error above does
        // not leave a partially advanced private prekey pool.
        let mut inner = store.inner.borrow_mut();
        inner.signed_pre_keys.insert(signed_id, signed_record);
        for (id, record) in prekey_records {
            inner.pre_keys.insert(id, record);
        }
        for (id, record) in kyber_records {
            inner.kyber_pre_keys.insert(id, record);
        }
        Ok(json)
    })
}

/// Returns locally-held prekey counts using the WEB facade's response fields.
#[wasm_bindgen]
pub fn prekey_counts(account_id: &str) -> JsResult<String> {
    require_account_id(account_id)?;
    with_store(account_id, |store| {
        let inner = store.inner.borrow();
        serde_json::to_string(&json!({
            "one_time_available": inner.pre_keys.len(),
            "kyber_one_time_available": inner.kyber_pre_keys.len(),
            "has_signed_prekey": !inner.signed_pre_keys.is_empty(),
            "has_kyber_last_resort": !inner.kyber_pre_keys.is_empty(),
        }))
        .map_err(js_err)
    })
}

/// Establishes an outbound Signal session using the WEB prekey bundle response.
#[wasm_bindgen]
pub fn establish_session(
    account_id: &str,
    peer_account_id: &str,
    peer_device_number: u32,
    local_device_number: u32,
    bundle_json: &str,
) -> JsResult<()> {
    require_account_id(account_id)?;
    if peer_account_id.is_empty() {
        return Err(js_err("peer_account_id must not be empty"));
    }
    let bundle_value: Value = serde_json::from_str(bundle_json).map_err(js_err)?;
    let bundle = parse_bundle(&bundle_value).map_err(js_err)?;
    let remote = ProtocolAddress::new(
        peer_account_id.to_owned(),
        device_id(peer_device_number, "peer device number")?,
    );
    let local = ProtocolAddress::new(
        account_id.to_owned(),
        device_id(local_device_number, "local device number")?,
    );

    with_store(account_id, |store| {
        let mut session_store = store.clone();
        let mut identity_store = store.clone();
        let mut rng = rand::rng();
        run_signal(process_prekey_bundle(
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            &bundle,
            now(),
            &mut rng,
        ))
    })
}

/// Returns whether the account store has an outbound Signal session record for
/// one peer device. The browser API uses this only to decide whether the
/// server's single-use prekey bundle must be fetched before encryption.
#[wasm_bindgen]
pub fn has_session(
    account_id: &str,
    peer_account_id: &str,
    peer_device_number: u32,
) -> JsResult<bool> {
    require_account_id(account_id)?;
    if peer_account_id.trim().is_empty() {
        return Err(js_err("peer_account_id must not be empty"));
    }
    device_id(peer_device_number, "peer device number")?;
    Ok(with_store(account_id, |store| {
        store
            .inner
            .borrow()
            .sessions
            .contains_key(&(peer_account_id.to_owned(), peer_device_number))
    }))
}

/// Encrypts bytes (encoded as hex) for one peer device. The result JSON matches
/// `src/wasm/types.ts` after the existing facade maps snake_case to camelCase.
#[wasm_bindgen]
pub fn encrypt(
    account_id: &str,
    peer_account_id: &str,
    peer_device_number: u32,
    local_device_number: u32,
    plaintext_hex: &str,
) -> JsResult<String> {
    require_account_id(account_id)?;
    if peer_account_id.is_empty() {
        return Err(js_err("peer_account_id must not be empty"));
    }
    let plaintext = hex::decode(plaintext_hex).map_err(js_err)?;
    let remote = ProtocolAddress::new(
        peer_account_id.to_owned(),
        device_id(peer_device_number, "peer device number")?,
    );
    let local = ProtocolAddress::new(
        account_id.to_owned(),
        device_id(local_device_number, "local device number")?,
    );

    with_store(account_id, |store| {
        let mut session_store = store.clone();
        let mut identity_store = store.clone();
        let mut rng = rand::rng();
        let message = run_signal(message_encrypt(
            &plaintext,
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            now(),
            &mut rng,
        ))?;
        let is_prekey = matches!(message, CiphertextMessage::PreKeySignalMessage(_));
        serde_json::to_string(&json!({
            "ciphertext_hex": hex::encode(message.serialize()),
            "is_prekey_message": is_prekey,
        }))
        .map_err(js_err)
    })
}

/// Decrypts a pairwise envelope and returns plaintext bytes encoded as hex.
#[wasm_bindgen]
pub fn decrypt(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    local_device_number: u32,
    ciphertext_hex: &str,
    is_prekey_message: bool,
) -> JsResult<String> {
    require_account_id(account_id)?;
    if sender_account_id.is_empty() {
        return Err(js_err("sender_account_id must not be empty"));
    }
    let bytes = hex::decode(ciphertext_hex).map_err(js_err)?;
    let ciphertext = if is_prekey_message {
        CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(bytes.as_slice()).map_err(js_err)?,
        )
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::try_from(bytes.as_slice()).map_err(js_err)?)
    };
    let remote = ProtocolAddress::new(
        sender_account_id.to_owned(),
        device_id(sender_device_number, "sender device number")?,
    );
    let local = ProtocolAddress::new(
        account_id.to_owned(),
        device_id(local_device_number, "local device number")?,
    );

    with_store(account_id, |store| {
        let mut session_store = store.clone();
        let mut identity_store = store.clone();
        let mut prekey_store = store.clone();
        let signed_prekey_store = store.clone();
        let mut kyber_store = store.clone();
        let mut rng = rand::rng();
        let plaintext = run_signal(message_decrypt(
            &ciphertext,
            &remote,
            &local,
            &mut session_store,
            &mut identity_store,
            &mut prekey_store,
            &signed_prekey_store,
            &mut kyber_store,
            &mut rng,
        ))?;
        Ok(hex::encode(plaintext))
    })
}

/// Creates or reuses this device's sender-key distribution for a conversation.
#[wasm_bindgen]
pub fn create_sender_key_distribution(
    account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
) -> JsResult<String> {
    require_account_id(account_id)?;
    if conversation_id.is_empty() {
        return Err(js_err("conversation_id must not be empty"));
    }
    let local = ProtocolAddress::new(
        account_id.to_owned(),
        device_id(local_device_number, "local device number")?,
    );
    with_store(account_id, |store| {
        let distribution_id = {
            let mut inner = store.inner.borrow_mut();
            *inner
                .group_sender_keys
                .entry(conversation_id.to_owned())
                .or_insert_with(random_uuid_v4)
        };
        let mut sender_key_store = store.clone();
        let mut rng = rand::rng();
        let distribution = run_signal(create_sender_key_distribution_message(
            &local,
            distribution_id,
            &mut sender_key_store,
            &mut rng,
        ))?;
        Ok(hex::encode(distribution.serialized()))
    })
}

/// Processes a pairwise-decrypted sender-key distribution envelope.
#[wasm_bindgen]
pub fn process_sender_key_distribution(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    distribution_hex: &str,
) -> JsResult<()> {
    require_account_id(account_id)?;
    if sender_account_id.is_empty() {
        return Err(js_err("sender_account_id must not be empty"));
    }
    let bytes = hex::decode(distribution_hex).map_err(js_err)?;
    let distribution = SenderKeyDistributionMessage::try_from(bytes.as_slice()).map_err(js_err)?;
    let sender = ProtocolAddress::new(
        sender_account_id.to_owned(),
        device_id(sender_device_number, "sender device number")?,
    );
    with_store(account_id, |store| {
        let mut sender_key_store = store.clone();
        run_signal(process_sender_key_distribution_message(
            &sender,
            &distribution,
            &mut sender_key_store,
        ))
    })
}

/// Encrypts a group payload under the sender key previously distributed for
/// this conversation.
#[wasm_bindgen]
pub fn group_encrypt(
    account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
    plaintext_hex: &str,
) -> JsResult<String> {
    require_account_id(account_id)?;
    let plaintext = hex::decode(plaintext_hex).map_err(js_err)?;
    let local = ProtocolAddress::new(
        account_id.to_owned(),
        device_id(local_device_number, "local device number")?,
    );
    with_store(account_id, |store| {
        let distribution_id = store
            .inner
            .borrow()
            .group_sender_keys
            .get(conversation_id)
            .copied()
            .ok_or_else(|| js_err("no sender key distribution for this conversation"))?;
        let mut sender_key_store = store.clone();
        let mut rng = rand::rng();
        let message = run_signal(signal_group_encrypt(
            &mut sender_key_store,
            &local,
            distribution_id,
            &plaintext,
            &mut rng,
        ))?;
        Ok(hex::encode(message.serialized()))
    })
}

/// Decrypts a group message using the sender key received earlier.
#[wasm_bindgen]
pub fn group_decrypt(
    account_id: &str,
    sender_account_id: &str,
    sender_device_number: u32,
    ciphertext_hex: &str,
) -> JsResult<String> {
    require_account_id(account_id)?;
    let bytes = hex::decode(ciphertext_hex).map_err(js_err)?;
    let sender = ProtocolAddress::new(
        sender_account_id.to_owned(),
        device_id(sender_device_number, "sender device number")?,
    );
    with_store(account_id, |store| {
        let mut sender_key_store = store.clone();
        let plaintext = run_signal(signal_group_decrypt(&bytes, &mut sender_key_store, &sender))?;
        Ok(hex::encode(plaintext))
    })
}

/// Returns identity-key changes awaiting user acknowledgement.
#[wasm_bindgen]
pub fn identity_changes(account_id: &str) -> JsResult<String> {
    require_account_id(account_id)?;
    with_store(account_id, |store| {
        serde_json::to_string(&store.inner.borrow().identity_changes).map_err(js_err)
    })
}

/// Clears the identity-change journal after WEB has presented the warning.
#[wasm_bindgen]
pub fn clear_identity_changes(account_id: &str) {
    with_store(account_id, |store| {
        store.inner.borrow_mut().identity_changes.clear();
    });
}

fn parse_bundle(value: &Value) -> Result<PreKeyBundle, SignalProtocolError> {
    let required_u32 = |object: &Value, key: &str| -> Result<u32, SignalProtocolError> {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!("{key} missing or invalid"))
            })
    };
    let required_hex = |object: &Value, key: &str| -> Result<Vec<u8>, SignalProtocolError> {
        let value = object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| SignalProtocolError::InvalidArgument(format!("{key} missing")))?;
        hex::decode(value).map_err(|error| SignalProtocolError::InvalidArgument(error.to_string()))
    };

    let registration_id = required_u32(value, "registration_id")?;
    let device_id = DeviceId::try_from(required_u32(value, "device_number")?)
        .map_err(|error| SignalProtocolError::InvalidArgument(error.to_string()))?;
    let identity_key = IdentityKey::decode(&required_hex(value, "identity_key_pub")?)?;

    let signed = value
        .get("signed_prekey")
        .ok_or_else(|| SignalProtocolError::InvalidArgument("signed_prekey missing".into()))?;
    let signed_id = SignedPreKeyId::from(required_u32(signed, "id")?);
    let signed_public = PublicKey::deserialize(&required_hex(signed, "pub")?)?;
    let signed_signature = required_hex(signed, "sig")?;

    let kyber = value
        .get("kyber_last_resort")
        .ok_or_else(|| SignalProtocolError::InvalidArgument("kyber_last_resort missing".into()))?;
    let kyber_id = KyberPreKeyId::from(required_u32(kyber, "id")?);
    let kyber_public =
        libsignal_protocol::kem::PublicKey::deserialize(&required_hex(kyber, "pub")?)?;
    let kyber_signature = required_hex(kyber, "sig")?;

    let one_time_prekey = match value.get("one_time_prekey") {
        None | Some(Value::Null) => None,
        Some(prekey) => {
            let id = PreKeyId::from(required_u32(prekey, "id")?);
            let public = PublicKey::deserialize(&required_hex(prekey, "pub")?)?;
            Some((id, public))
        }
    };

    PreKeyBundle::new(
        registration_id,
        device_id,
        one_time_prekey,
        signed_id,
        signed_public,
        signed_signature,
        kyber_id,
        kyber_public,
        kyber_signature,
        identity_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str) -> String {
        format!("signal-test-{name}-{}", now_millis())
    }

    fn parsed_json(value: &str) -> Value {
        serde_json::from_str(value).expect("valid JSON returned by Signal API")
    }

    #[test]
    fn browser_store_matches_web_snapshot_shape_and_roundtrips_identity_and_prekeys() {
        let id = account("snapshot");
        let identity = generate_identity(&id, 77).expect("identity generation");
        let generated = parsed_json(&generate_prekeys(&id, 2).expect("prekey generation"));
        assert_eq!(generated["one_time_prekeys"].as_array().unwrap().len(), 2);
        let snapshot = parsed_json(&snapshot(&id).expect("snapshot"));
        for key in [
            "identity",
            "registration_id",
            "peer_identities",
            "pre_keys",
            "signed_pre_keys",
            "kyber_pre_keys",
            "sessions",
            "sender_keys",
            "group_sender_keys",
            "identity_changes",
        ] {
            assert!(snapshot.get(key).is_some(), "snapshot omitted {key}");
        }
        assert!(snapshot["identity"].as_str().unwrap().len() > 130);

        reset(&id);
        restore(&id, &snapshot.to_string()).expect("restore WEB snapshot");
        assert_eq!(
            local_identity_public(&id).expect("restored identity"),
            hex::encode(
                IdentityKeyPair::try_from(hex::decode(identity).unwrap().as_slice())
                    .unwrap()
                    .identity_key()
                    .serialize()
            )
        );
        let counts = parsed_json(&prekey_counts(&id).expect("prekey counts"));
        assert_eq!(counts["one_time_available"], 2);
        assert_eq!(counts["kyber_one_time_available"], 3);
        reset(&id);
    }

    #[test]
    fn pairwise_ciphertext_interoperates_and_session_survives_snapshot_restore() {
        let alice = account("alice");
        let bob = account("bob");
        generate_identity(&alice, 41).expect("Alice identity");
        generate_identity(&bob, 42).expect("Bob identity");
        let bob_prekeys = parsed_json(&generate_prekeys(&bob, 2).expect("Bob prekeys"));
        let bundle = json!({
            "registration_id": 42,
            "device_number": 1,
            "identity_key_pub": local_identity_public(&bob).unwrap(),
            "signed_prekey": bob_prekeys["signed_prekey"],
            "kyber_last_resort": bob_prekeys["kyber_last_resort"],
            "one_time_prekey": bob_prekeys["one_time_prekeys"][0],
        });

        establish_session(&alice, &bob, 1, 1, &bundle.to_string()).expect("session establishment");
        assert!(has_session(&alice, &bob, 1).expect("session lookup"));
        let first = parsed_json(&encrypt(&alice, &bob, 1, 1, &hex::encode("привет")).unwrap());
        assert_eq!(first["is_prekey_message"], true);
        let opened = decrypt(
            &bob,
            &alice,
            1,
            1,
            first["ciphertext_hex"].as_str().unwrap(),
            true,
        )
        .expect("first message decrypt");
        assert_eq!(hex::decode(opened).unwrap(), "привет".as_bytes());

        let reply = parsed_json(&encrypt(&bob, &alice, 1, 1, &hex::encode("ответ")).unwrap());
        assert_eq!(reply["is_prekey_message"], false);
        let reply_plain = decrypt(
            &alice,
            &bob,
            1,
            1,
            reply["ciphertext_hex"].as_str().unwrap(),
            false,
        )
        .expect("reply decrypt");
        assert_eq!(hex::decode(reply_plain).unwrap(), "ответ".as_bytes());

        let alice_snapshot = snapshot(&alice).expect("Alice snapshot");
        reset(&alice);
        restore(&alice, &alice_snapshot).expect("Alice restore");
        let followup = parsed_json(&encrypt(&alice, &bob, 1, 1, &hex::encode("дальше")).unwrap());
        assert_eq!(followup["is_prekey_message"], false);
        let followup_plain = decrypt(
            &bob,
            &alice,
            1,
            1,
            followup["ciphertext_hex"].as_str().unwrap(),
            false,
        )
        .expect("followup decrypt");
        assert_eq!(hex::decode(followup_plain).unwrap(), "дальше".as_bytes());

        reset(&alice);
        reset(&bob);
    }

    #[test]
    fn sender_key_distribution_and_group_message_roundtrip() {
        let alice = account("group-alice");
        let bob = account("group-bob");
        let conversation = "group-conversation";
        generate_identity(&alice, 51).expect("Alice identity");
        generate_identity(&bob, 52).expect("Bob identity");

        let distribution = create_sender_key_distribution(&alice, 1, conversation)
            .expect("create sender-key distribution");
        process_sender_key_distribution(&bob, &alice, 1, &distribution)
            .expect("process sender-key distribution");
        let encrypted = group_encrypt(&alice, 1, conversation, &hex::encode("group payload"))
            .expect("group encryption");
        let plaintext = group_decrypt(&bob, &alice, 1, &encrypted).expect("group decryption");
        assert_eq!(hex::decode(plaintext).unwrap(), b"group payload");

        reset(&alice);
        reset(&bob);
    }
}
