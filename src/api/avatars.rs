use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct AvatarUploadResponse {
    pub avatar_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadParams {
    /// Absolute path to a WebP file on disk. The library reads it, validates
    /// the magic bytes, and posts it as-is.
    pub file_path: String,
}

/// Uploads a new avatar. The file must already be WebP: the server rejects
/// anything whose magic bytes are not "RIFF...WEBP", and re-encoding is a
/// job for the client, not for this library.
pub async fn upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: UploadParams = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;

    let path = PathBuf::from(&params.file_path);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot read {}: {e}", params.file_path)))?;

    // Cheap local check: a 12-byte header is enough to reject the obvious
    // mistakes before spending a round trip on the server.
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err(Error::InvalidPayload(
            "file does not look like a WebP image".into(),
        ));
    }

    let resp: AvatarUploadResponse = state
        .http
        .post_raw("/api/v1/avatars/me", bytes, "image/webp", Some(&token))
        .await?;

    Ok(serde_json::to_vec(&resp)?)
}

pub async fn delete(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .delete("/api/v1/avatars/me", Some(&token))
        .await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServeParams {
    pub account_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServeResult {
    pub account_id: String,
    pub content_type: String,
    pub data_base64: String,
}

/// Public avatar fetch, with no authentication. The bytes come back base64
/// in the JSON payload rather than through the transport as raw data, so the
/// FFI response stays uniform across all methods.
pub async fn serve(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: ServeParams = serde_json::from_slice(&payload)?;

    let path = format!("/api/v1/avatars/{}", params.account_id);
    let bytes = state.http.get_absolute_relative(&path).await?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(serde_json::to_vec(&ServeResult {
        account_id: params.account_id,
        content_type: "image/webp".into(),
        data_base64: encoded,
    })?)
}
