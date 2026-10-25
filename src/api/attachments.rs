use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::api::common::{bearer, id_from};
use crate::crypto::attachments::{
    BASE_NONCE_LEN, KEY_LEN, TAG_LEN, decode_key_and_base, new_key_and_base, open_chunk, seal_chunk,
};
use crate::error::{Error, Result};
use crate::proto::{ClientFrame, Envelope, EnvelopeUpload, client_frame};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

#[derive(Debug, Serialize, Deserialize)]
pub struct RecommendRequest {
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendResponse {
    pub chunk_size: u64,
    pub chunk_sizes: Vec<u64>,
    pub chunk_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    pub chunk_sizes: Vec<u64>,
    pub conversation_id: String,
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_kind() -> String {
    "attachment".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedPut {
    pub chunk_index: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitResponse {
    pub attachment_id: String,
    pub chunk_count: i64,
    pub total_size: i64,
    pub uploads: Vec<PresignedPut>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedGet {
    pub chunk_index: i64,
    pub size_bytes: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub attachment_id: String,
    pub total_size: i64,
    pub chunk_count: i64,
    pub chunks: Vec<PresignedGet>,
}

// ---------------------------------------------------------------
// Encrypted upload
// ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadParams {
    pub file_path: String,
    pub conversation_id: String,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadResult {
    pub attachment_id: String,
    /// 32-byte symmetric key, hex. Send this to the recipient through an
    /// attachment-key envelope; never store it on the server.
    pub key_hex: String,
    /// 4-byte base nonce, hex. Travels alongside the key.
    pub base_nonce_hex: String,
    /// Plaintext size, as the caller handed it in.
    pub plaintext_size: u64,
    /// Total bytes stored in S3: plaintext plus 16 bytes per chunk.
    pub encrypted_size: u64,
    pub chunk_count: usize,
}

/// Reads a file, seals every chunk under a fresh symmetric key, uploads the
/// sealed bytes, and returns the key so the caller can forward it.
///
/// The server never sees the plaintext or the key. Sizes reported at `init`
/// are the sealed sizes, which is what `finalize` on the server verifies.
pub async fn upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: UploadParams = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;

    let path = PathBuf::from(&params.file_path);
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot stat {}: {e}", params.file_path)))?;
    if !metadata.is_file() {
        return Err(Error::InvalidPayload(format!(
            "{} is not a regular file",
            params.file_path
        )));
    }
    let plaintext_size = metadata.len();

    // Server-chosen chunk size, but on the plaintext side we leave room for
    // the tag so a sealed chunk is at most the size the server recommended.
    let rec: RecommendResponse = state
        .http
        .post(
            "/api/v1/attachments/recommend",
            &RecommendRequest {
                total_size: plaintext_size,
            },
            Some(&token),
        )
        .await?;
    let recommended = rec.chunk_size.max(1);
    let raw_chunk_size = recommended.saturating_sub(TAG_LEN as u64).max(1);

    // Read and seal chunk by chunk. The sealed chunks and their sizes are
    // collected before `init`, because `init` needs the sealed sizes and there
    // is no way to know them without actually sealing.
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot open {}: {e}", params.file_path)))?;

    let (key, base) = new_key_and_base();
    let mut sealed_chunks: Vec<Vec<u8>> = Vec::new();
    let mut sealed_sizes: Vec<u64> = Vec::new();
    let mut index: u64 = 0;
    let mut remaining = plaintext_size;

    while remaining > 0 {
        let take = remaining.min(raw_chunk_size) as usize;
        let mut buf = vec![0u8; take];
        file.read_exact(&mut buf)
            .await
            .map_err(|e| Error::Internal(format!("short read on chunk {index}: {e}")))?;

        let sealed = seal_chunk(&key, &base, index, &buf)?;
        sealed_sizes.push(sealed.len() as u64);
        sealed_chunks.push(sealed);

        remaining -= take as u64;
        index += 1;
    }

    if sealed_chunks.is_empty() {
        // Zero-byte file: one empty chunk, sealed.
        let sealed = seal_chunk(&key, &base, 0, &[])?;
        sealed_sizes.push(sealed.len() as u64);
        sealed_chunks.push(sealed);
    }

    let encrypted_size: u64 = sealed_sizes.iter().sum();

    let init: InitResponse = state
        .http
        .post(
            "/api/v1/attachments/init",
            &InitRequest {
                chunk_sizes: sealed_sizes.clone(),
                conversation_id: params.conversation_id.clone(),
                kind: params.kind.clone(),
            },
            Some(&token),
        )
        .await?;

    let mut uploads = init.uploads.clone();
    uploads.sort_by_key(|u| u.chunk_index);

    if uploads.len() != sealed_chunks.len() {
        return Err(Error::Internal(format!(
            "server allocated {} chunks but {} were sealed",
            uploads.len(),
            sealed_chunks.len()
        )));
    }

    for (upload, sealed) in uploads.iter().zip(sealed_chunks) {
        state.http.put_absolute(&upload.url, sealed).await?;
    }

    let finalize_path = format!("/api/v1/attachments/{}/finalize", init.attachment_id);
    let _: serde_json::Value = state
        .http
        .post(&finalize_path, &serde_json::json!({}), Some(&token))
        .await?;

    Ok(serde_json::to_vec(&UploadResult {
        attachment_id: init.attachment_id,
        key_hex: hex::encode(key),
        base_nonce_hex: hex::encode(base),
        plaintext_size,
        encrypted_size,
        chunk_count: sealed_sizes.len(),
    })?)
}

// ---------------------------------------------------------------
// Encrypted download
// ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadParams {
    pub attachment_id: String,
    pub output_path: String,
    pub key_hex: String,
    pub base_nonce_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadResult {
    pub output_path: String,
    pub plaintext_size: u64,
    pub chunk_count: usize,
}

/// Fetches every sealed chunk, opens it, and writes the plaintext in order.
pub async fn download(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: DownloadParams = serde_json::from_slice(&payload)?;
    let (key, base) = decode_key_and_base(&params.key_hex, &params.base_nonce_hex)?;
    let token = bearer(state).await?;

    let path = format!("/api/v1/attachments/{}", params.attachment_id);
    let resp: DownloadResponse = state.http.get(&path, Some(&token)).await?;

    let mut chunks = resp.chunks.clone();
    chunks.sort_by_key(|c| c.chunk_index);

    let out_path = PathBuf::from(&params.output_path);
    let mut out = tokio::fs::File::create(&out_path)
        .await
        .map_err(|e| Error::Internal(format!("cannot create {}: {e}", params.output_path)))?;

    let mut plaintext_total: u64 = 0;

    for c in &chunks {
        let sealed = state.http.get_absolute(&c.url).await?;

        // The size recorded by the server is the sealed size, since that is
        // what was uploaded. Anything smaller than the tag length is not a
        // valid sealed chunk.
        if sealed.len() as i64 != c.size_bytes {
            return Err(Error::Internal(format!(
                "chunk {} size mismatch: expected {}, got {}",
                c.chunk_index,
                c.size_bytes,
                sealed.len()
            )));
        }

        let plaintext = open_chunk(&key, &base, c.chunk_index as u64, &sealed)?;
        out.write_all(&plaintext)
            .await
            .map_err(|e| Error::Internal(format!("write failed: {e}")))?;
        plaintext_total += plaintext.len() as u64;
    }

    out.flush()
        .await
        .map_err(|e| Error::Internal(format!("flush failed: {e}")))?;

    Ok(serde_json::to_vec(&DownloadResult {
        output_path: params.output_path,
        plaintext_size: plaintext_total,
        chunk_count: chunks.len(),
    })?)
}

// ---------------------------------------------------------------
// Claim / release / recommend (unchanged from before)
// ---------------------------------------------------------------

pub async fn claim(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/attachments/{id}/claim");
    let _: serde_json::Value = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
    Ok(br#"{"claimed":true}"#.to_vec())
}

pub async fn release(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/attachments/{id}/release");
    let _: serde_json::Value = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
    Ok(br#"{"released":true}"#.to_vec())
}

pub async fn recommend(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: RecommendRequest = serde_json::from_slice(&payload)?;
    let resp: RecommendResponse = state
        .http
        .post("/api/v1/attachments/recommend", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

// ---------------------------------------------------------------
// Forward the key to the recipient via an attachment-key envelope
// ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SendKeyRequest {
    pub recipient_account_id: String,
    pub attachment_id: String,
    pub key_hex: String,
    pub base_nonce_hex: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
}

/// ENVELOPE_TYPE_ATTACHMENT_KEY from friendshub.proto.
const ENVELOPE_TYPE_ATTACHMENT_KEY: i32 = 9;

/// Delivers the symmetric key to every device of the recipient. The
/// attachment id is included so the recipient knows which object to fetch;
/// the key and base nonce are what turn that object back into a file.
pub async fn send_key(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: SendKeyRequest = serde_json::from_slice(&payload)?;

    // Validate the key material locally before spending a network round trip.
    let _ = decode_key_and_base(&req.key_hex, &req.base_nonce_hex)?;
    let _attachment_id = uuid_bytes(&req.attachment_id, "attachment_id")?;
    let recipient_id = uuid_bytes(&req.recipient_account_id, "recipient_account_id")?;
    let conversation_id = req
        .conversation_id
        .as_deref()
        .map(|id| uuid_bytes(id, "conversation_id"))
        .transpose()?
        .unwrap_or_default();

    let inner = serde_json::json!({
        "kind": "attachment_key",
        "attachment_id": req.attachment_id,
        "key_hex": req.key_hex,
        "base_nonce_hex": req.base_nonce_hex,
        "conversation_id": req.conversation_id,
    });
    let inner_bytes = serde_json::to_vec(&inner)?;

    let auth = crate::db::auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.clone().ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let sender_id = uuid_bytes(&sender_account_id, "sender_account_id")?;
    let sender_device_number_proto = protobuf_device_number(sender_device_number, "sender")?;
    let token = bearer(state).await?;

    let devices = crate::crypto::device_cache::get(state, &req.recipient_account_id).await?;
    for device in &devices {
        protobuf_device_number(device.device_number, "recipient")?;
    }

    let encrypt_state = Arc::clone(state);
    let upload_state = Arc::clone(state);
    let token = token.clone();
    let recipient_account_id = req.recipient_account_id.clone();
    let plaintext = inner_bytes;
    let crypto_snapshot = crate::crypto::history_stage::load_snapshot(&state.db)
        .await
        .map_err(|error| Error::Database(format!("failed to snapshot crypto state: {error}")))?;
    let rollback_state = Arc::clone(&state);
    let prepared = encrypt_then_upload(
        &devices,
        move |device_number| {
            let state = Arc::clone(&encrypt_state);
            let token = token.clone();
            let recipient_account_id = recipient_account_id.clone();
            let recipient_id = recipient_id.clone();
            let sender_id = sender_id.clone();
            let conversation_id = conversation_id.clone();
            let plaintext = plaintext.clone();
            async move {
                let recipient_device_number = protobuf_device_number(device_number, "recipient")?;
                if !crate::crypto::manager::has_session(
                    &state,
                    &recipient_account_id,
                    device_number,
                )
                .await
                .map_err(Error::from)?
                {
                    let path = format!(
                        "/api/v1/accounts/{recipient_account_id}/devices/{device_number}/bundle"
                    );
                    let bundle: serde_json::Value = state.http.get(&path, Some(&token)).await?;
                    crate::crypto::manager::establish_outbound_session(
                        &state,
                        &recipient_account_id,
                        device_number,
                        &bundle,
                    )
                    .await
                    .map_err(Error::from)?;
                }

                let (ciphertext, is_prekey_message) = crate::crypto::manager::encrypt_for_device(
                    &state,
                    &recipient_account_id,
                    device_number,
                    &plaintext,
                )
                .await
                .map_err(Error::from)?;
                let envelope_id = uuid::Uuid::now_v7();
                let sent = crate::crypto::send::SentEnvelope {
                    device_number,
                    envelope_id: envelope_id.to_string(),
                    is_prekey_message,
                    ciphertext_len: ciphertext.len(),
                };
                let envelope = Envelope {
                    envelope_id: envelope_id.as_bytes().to_vec(),
                    sender_account_id: sender_id,
                    sender_device_number: sender_device_number_proto,
                    recipient_account_id: recipient_id,
                    recipient_device_number,
                    conversation_id,
                    ciphertext,
                    is_prekey_message,
                    envelope_type: ENVELOPE_TYPE_ATTACHMENT_KEY,
                    client_timestamp: now_unix(),
                    sender_is_bot: false,
                    send_at: 0,
                };
                Ok(PreparedKeyEnvelope { envelope, sent })
            }
        },
        move || {
            let state = Arc::clone(&rollback_state);
            let snapshot = crypto_snapshot.clone();
            async move {
                crate::crypto::history_stage::replace_snapshot(&state.db, &snapshot)
                    .await
                    .map_err(|error| {
                        Error::Database(format!("failed to restore crypto state: {error}"))
                    })
            }
        },
        move |prepared| async move {
            let envelopes = prepared
                .into_iter()
                .map(|prepared| prepared.envelope)
                .collect();
            upload_state
                .ws
                .send_frame(ClientFrame {
                    kind: Some(client_frame::Kind::Upload(EnvelopeUpload { envelopes })),
                })
                .await
        },
    )
    .await?;

    let sent = prepared
        .into_iter()
        .map(|prepared| prepared.sent)
        .collect::<Vec<_>>();

    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes": sent,
        "device_errors": [],
    }))?)
}

#[derive(Clone)]
struct PreparedKeyEnvelope {
    envelope: Envelope,
    sent: crate::crypto::send::SentEnvelope,
}

/// Encrypt every target first, then upload all resulting envelopes in a single
/// frame. An encryption failure therefore never uploads a partial fanout.
async fn encrypt_then_upload<
    T,
    EncryptOne,
    EncryptFuture,
    Rollback,
    RollbackFuture,
    Upload,
    UploadFuture,
>(
    devices: &[crate::crypto::device_cache::CachedDevice],
    mut encrypt_one: EncryptOne,
    rollback_crypto: Rollback,
    upload_batch: Upload,
) -> Result<Vec<T>>
where
    T: Clone,
    EncryptOne: FnMut(i64) -> EncryptFuture,
    EncryptFuture: Future<Output = Result<T>>,
    Rollback: FnOnce() -> RollbackFuture,
    RollbackFuture: Future<Output = Result<()>>,
    Upload: FnOnce(Vec<T>) -> UploadFuture,
    UploadFuture: Future<Output = Result<()>>,
{
    if devices.is_empty() {
        return Err(Error::InvalidPayload(
            "recipient has no active devices".into(),
        ));
    }

    let mut prepared = Vec::with_capacity(devices.len());
    for device in devices {
        match encrypt_one(device.device_number).await {
            Ok(envelope) => prepared.push(envelope),
            Err(error) => {
                if let Err(rollback_error) = rollback_crypto().await {
                    return Err(Error::Database(format!(
                        "{error}; failed to restore crypto state after fanout preparation: {rollback_error}"
                    )));
                }
                return Err(error);
            }
        }
    }

    upload_batch(prepared.clone()).await?;
    Ok(prepared)
}

fn uuid_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    uuid::Uuid::parse_str(value)
        .map(|id| id.as_bytes().to_vec())
        .map_err(|error| Error::InvalidPayload(format!("{field}: {error}")))
}

fn protobuf_device_number(device_number: i64, field: &str) -> Result<u32> {
    let number = u32::try_from(device_number)
        .map_err(|_| Error::InvalidPayload(format!("{field} device number is invalid")))?;
    libsignal_protocol::DeviceId::try_from(number)
        .map_err(|_| Error::InvalidPayload(format!("{field} device number is invalid")))?;
    Ok(number)
}

#[allow(dead_code)]
fn _consts(_: [usize; 3]) -> [usize; 3] {
    [KEY_LEN, BASE_NONCE_LEN, TAG_LEN]
}

#[cfg(test)]
mod send_key_batch_tests {
    use super::encrypt_then_upload;
    use crate::crypto::device_cache::CachedDevice;
    use crate::error::Error;
    use std::sync::{Arc, Mutex};

    fn devices(numbers: &[i64]) -> Vec<CachedDevice> {
        numbers
            .iter()
            .map(|number| CachedDevice {
                device_number: *number,
                registration_id: 1,
                identity_key_pub: String::new(),
            })
            .collect()
    }

    #[tokio::test]
    async fn send_key_encrypts_all_devices_before_one_batch_upload() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let uploaded = Arc::new(Mutex::new(Vec::new()));
        let encrypt_order = order.clone();
        let upload_order = order.clone();
        let uploaded_batches = uploaded.clone();

        let prepared = encrypt_then_upload(
            &devices(&[2, 4, 9]),
            move |device_number| {
                let order = encrypt_order.clone();
                async move {
                    order.lock().unwrap().push(device_number);
                    Ok(device_number * 10)
                }
            },
            || async { Ok(()) },
            move |batch| {
                let order = upload_order.clone();
                let uploaded = uploaded_batches.clone();
                async move {
                    assert_eq!(*order.lock().unwrap(), vec![2, 4, 9]);
                    uploaded.lock().unwrap().push(batch);
                    Ok(())
                }
            },
        )
        .await
        .expect("complete fanout should upload");

        assert_eq!(prepared, vec![20, 40, 90]);
        assert_eq!(*uploaded.lock().unwrap(), vec![vec![20, 40, 90]]);
    }

    #[tokio::test]
    async fn send_key_stops_at_first_encryption_error_without_uploading_partial_batch() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let upload_count = Arc::new(Mutex::new(0));
        let ratchet_updates = Arc::new(Mutex::new(Vec::new()));
        let encrypt_order = order.clone();
        let upload_calls = upload_count.clone();
        let encrypted_devices = ratchet_updates.clone();
        let rollback_devices = ratchet_updates.clone();

        let result = encrypt_then_upload(
            &devices(&[2, 4, 9]),
            move |device_number| {
                let order = encrypt_order.clone();
                let ratchets = encrypted_devices.clone();
                async move {
                    order.lock().unwrap().push(device_number);
                    ratchets.lock().unwrap().push(device_number);
                    if device_number == 4 {
                        Err(Error::Network("device encryption failed".into()))
                    } else {
                        Ok(device_number)
                    }
                }
            },
            move || {
                let ratchets = rollback_devices.clone();
                async move {
                    ratchets.lock().unwrap().clear();
                    Ok(())
                }
            },
            move |_batch| {
                let count = upload_calls.clone();
                async move {
                    *count.lock().unwrap() += 1;
                    Ok(())
                }
            },
        )
        .await;

        assert!(
            matches!(result, Err(Error::Network(message)) if message == "device encryption failed")
        );
        assert_eq!(*order.lock().unwrap(), vec![2, 4]);
        assert_eq!(*upload_count.lock().unwrap(), 0);
        assert!(
            ratchet_updates.lock().unwrap().is_empty(),
            "failed batch preparation must restore every earlier ratchet update"
        );
    }

    #[tokio::test]
    async fn send_key_rejects_a_recipient_with_no_active_devices() {
        let upload_count = Arc::new(Mutex::new(0));
        let upload_calls = upload_count.clone();
        let result = encrypt_then_upload(
            &[],
            |_device_number| async { Ok(1_i32) },
            || async { Ok(()) },
            move |_batch| {
                let count = upload_calls.clone();
                async move {
                    *count.lock().unwrap() += 1;
                    Ok(())
                }
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(Error::InvalidPayload(message)) if message == "recipient has no active devices"
        ));
        assert_eq!(*upload_count.lock().unwrap(), 0);
    }
}
