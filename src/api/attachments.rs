use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::api::common::{bearer, id_from};
use crate::crypto::attachments::{
    decode_key_and_base, new_key_and_base, open_chunk, seal_chunk, BASE_NONCE_LEN, KEY_LEN,
    TAG_LEN,
};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

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
            &RecommendRequest { total_size: plaintext_size },
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

    for (upload, sealed) in uploads.iter().zip(sealed_chunks.into_iter()) {
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

    out.flush().await.map_err(|e| Error::Internal(format!("flush failed: {e}")))?;

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
    let token = bearer(state).await?;

    let devices = crate::crypto::device_cache::get(state, &req.recipient_account_id).await?;
    if devices.is_empty() {
        return Err(Error::InvalidPayload(format!(
            "recipient {} has no active devices",
            req.recipient_account_id
        )));
    }

    let mut sent = Vec::new();
    let mut errors = Vec::new();
    for d in &devices {
        match crate::crypto::send::send_one(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            &req.recipient_account_id,
            d.device_number,
            &inner_bytes,
            ENVELOPE_TYPE_ATTACHMENT_KEY,
            req.conversation_id.as_deref(),
)
        .await
        {
            Ok(info) => sent.push(info),
            Err(e) => errors.push(serde_json::json!({
                "device_number": d.device_number,
                "error": e.to_string(),
            })),
        }
    }

    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes": sent,
        "device_errors": errors,
    }))?)
}

#[allow(dead_code)]
fn _consts(_: [usize; 3]) -> [usize; 3] {
    [KEY_LEN, BASE_NONCE_LEN, TAG_LEN]
}
