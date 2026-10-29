use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::api::common::bearer;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const MAX_AVATAR_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvatarUploadResponse {
    pub avatar_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadParams {
    /// Absolute path to a WebP file on disk. The library reads it, validates
    /// the size and magic bytes, then owns all upload buffers.
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvatarUploadInitParams {
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvatarUploadSession {
    pub upload_id: String,
    pub size_bytes: u64,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvatarUploadFinalizeParams {
    pub upload_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationAvatarParams {
    /// Group or channel conversation ID.
    pub conversation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationAvatarUploadParams {
    /// Group or channel conversation ID.
    pub conversation_id: String,
    /// Absolute path to a WebP file on disk.
    pub file_path: String,
}

/// Uploads an account avatar using the same direct-to-storage flow as WEB:
/// initialize a session, PUT to its presigned URL without FriendsHub auth,
/// then publish the immutable avatar URL by finalizing the session.
///
/// A finalization timeout is retried once with the same upload ID because that
/// operation is idempotent. A finalization 404 restarts the complete upload
/// once, matching the browser's expired-session recovery behavior.
pub async fn upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: UploadParams = serde_json::from_slice(&payload)?;
    let bytes = read_avatar_file(&params.file_path).await?;
    validate_avatar_bytes(&bytes)?;
    let token = bearer(state).await?;
    let response = upload_account_bytes(state, &token, &bytes, true).await?;
    Ok(serde_json::to_vec(&response)?)
}

/// Creates an account avatar upload session. The returned URL is a storage
/// capability and must be used without the FriendsHub bearer token.
pub async fn init_upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: AvatarUploadInitParams = serde_json::from_slice(&payload)?;
    validate_avatar_size(params.size_bytes)?;
    let token = bearer(state).await?;
    let response = init_upload_with_token(state, &token, params.size_bytes).await?;
    Ok(serde_json::to_vec(&response)?)
}

/// Finalizes an account avatar upload session returned by [`init_upload`].
pub async fn finalize_upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: AvatarUploadFinalizeParams = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;
    let response = finalize_upload_with_token(state, &token, &params.upload_id).await?;
    Ok(serde_json::to_vec(&response)?)
}

/// Deletes the signed-in account's avatar. The server clears the account URL
/// first and treats object-store cleanup as best effort.
pub async fn delete(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .delete("/api/v1/avatars/me", Some(&token))
        .await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

pub async fn upload_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    upload_conversation(state, payload, "groups").await
}

pub async fn delete_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    delete_conversation(state, payload, "groups").await
}

pub async fn upload_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    upload_conversation(state, payload, "channels").await
}

pub async fn delete_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    delete_conversation(state, payload, "channels").await
}

/// Fetches a group's public avatar through the shared conversation-avatar
/// route. Bytes are base64-wrapped so the response remains JSON over FFI.
pub async fn get_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    serve_conversation(state, payload).await
}

/// Fetches a channel's public avatar through the shared conversation-avatar
/// route. Bytes are base64-wrapped so the response remains JSON over FFI.
pub async fn get_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    serve_conversation(state, payload).await
}

async fn serve_conversation(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: ConversationAvatarParams = serde_json::from_slice(&payload)?;
    let conversation_id = path_segment(&params.conversation_id, "conversation_id")?;
    let path = format!("/api/v1/conversations/{conversation_id}/avatar");
    let bytes = state.http.get_absolute_relative(&path).await?;
    validate_avatar_bytes(&bytes)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(serde_json::to_vec(&ConversationAvatarResult {
        conversation_id: params.conversation_id,
        content_type: "image/webp".into(),
        data_base64: encoded,
    })?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationAvatarResult {
    pub conversation_id: String,
    pub content_type: String,
    pub data_base64: String,
}

async fn upload_conversation(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
    collection: &'static str,
) -> Result<Vec<u8>> {
    let params: ConversationAvatarUploadParams = serde_json::from_slice(&payload)?;
    let conversation_id = path_segment(&params.conversation_id, "conversation_id")?;
    let bytes = read_avatar_file(&params.file_path).await?;
    validate_avatar_bytes(&bytes)?;
    let token = bearer(state).await?;
    let path = conversation_avatar_path(collection, &conversation_id);
    let response: AvatarUploadResponse = state
        .http
        .post_raw(&path, bytes, "image/webp", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&response)?)
}

async fn delete_conversation(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
    collection: &'static str,
) -> Result<Vec<u8>> {
    let params: ConversationAvatarParams = serde_json::from_slice(&payload)?;
    let conversation_id = path_segment(&params.conversation_id, "conversation_id")?;
    let token = bearer(state).await?;
    let path = conversation_avatar_path(collection, &conversation_id);
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

fn conversation_avatar_path(collection: &str, conversation_id: &str) -> String {
    format!("/api/v1/{collection}/{conversation_id}/avatar")
}

async fn upload_account_bytes(
    state: &Arc<ActorState>,
    token: &str,
    bytes: &[u8],
    restart_after_not_found: bool,
) -> Result<AvatarUploadResponse> {
    let mut may_restart = restart_after_not_found;
    loop {
        let session = init_upload_with_token(state, token, bytes.len() as u64).await?;
        state
            .http
            .put_absolute(&session.url, bytes.to_vec())
            .await?;

        match finalize_upload_with_token(state, token, &session.upload_id).await {
            Ok(response) => return Ok(response),
            Err(Error::Server { status: 404, .. }) if may_restart => {
                // A 404 means this upload ID cannot be finalized. Start one
                // new session and send the same bytes once, never indefinitely.
                may_restart = false;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn init_upload_with_token(
    state: &Arc<ActorState>,
    token: &str,
    size_bytes: u64,
) -> Result<AvatarUploadSession> {
    validate_avatar_size(size_bytes)?;
    let session: AvatarUploadSession = state
        .http
        .post(
            "/api/v1/avatars/me/uploads",
            &AvatarUploadInitParams { size_bytes },
            Some(token),
        )
        .await?;
    if session.size_bytes != size_bytes {
        return Err(Error::InvalidPayload(
            "avatar upload session returned a different byte length".into(),
        ));
    }
    if session.upload_id.is_empty() || session.url.is_empty() {
        return Err(Error::InvalidPayload(
            "avatar upload session is missing its ID or URL".into(),
        ));
    }
    Ok(session)
}

async fn finalize_upload_with_token(
    state: &Arc<ActorState>,
    token: &str,
    upload_id: &str,
) -> Result<AvatarUploadResponse> {
    let upload_id = path_segment(upload_id, "upload_id")?;
    let path = format!("/api/v1/avatars/me/uploads/{upload_id}/finalize");
    let empty = serde_json::json!({});

    match state
        .http
        .post::<serde_json::Value, AvatarUploadResponse>(&path, &empty, Some(token))
        .await
    {
        // The first response may be lost after the server commits. Finalize is
        // idempotent for an upload ID, so one retry matches WEB's behavior.
        Err(error) if is_ambiguous_finalize_error(&error) => {
            state.http.post(&path, &empty, Some(token)).await
        }
        result => result,
    }
}

async fn read_avatar_file(file_path: &str) -> Result<Vec<u8>> {
    let path = PathBuf::from(file_path);
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot stat {file_path}: {e}")))?;
    if !metadata.is_file() {
        return Err(Error::InvalidPayload(format!(
            "{file_path} is not a regular file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > MAX_AVATAR_BYTES as u64 {
        return Err(Error::InvalidPayload(format!(
            "avatar size must be between 1 byte and {MAX_AVATAR_BYTES} bytes"
        )));
    }

    // Limit the read itself too, so a file that grows after metadata() cannot
    // force the library to allocate an unbounded buffer.
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot open {file_path}: {e}")))?;
    let mut reader = file.take((MAX_AVATAR_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| Error::Internal(format!("cannot read {file_path}: {e}")))?;
    validate_avatar_bytes(&bytes)?;
    Ok(bytes)
}

fn validate_avatar_size(size_bytes: u64) -> Result<()> {
    if size_bytes == 0 || size_bytes > MAX_AVATAR_BYTES as u64 {
        return Err(Error::InvalidPayload(format!(
            "avatar size must be between 1 byte and {MAX_AVATAR_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_avatar_bytes(bytes: &[u8]) -> Result<()> {
    validate_avatar_size(bytes.len() as u64)?;
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err(Error::InvalidPayload(
            "file does not look like a WebP image".into(),
        ));
    }
    Ok(())
}

/// Percent-encodes one path component like `encodeURIComponent`, after
/// rejecting empty IDs and control characters. This prevents IDs from
/// introducing extra route segments while preserving WEB/backend routing.
fn path_segment(value: &str, field: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::InvalidPayload(format!("{field} is invalid")));
    }
    Ok(encode_path_segment(value))
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn is_ambiguous_finalize_error(error: &Error) -> bool {
    matches!(error, Error::Network(_) | Error::Server { status: 504, .. })
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

/// Public account-avatar fetch, with no authentication. The bytes come back
/// base64 in JSON so the FFI response stays uniform across methods.
pub async fn serve(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: ServeParams = serde_json::from_slice(&payload)?;
    let account_id = path_segment(&params.account_id, "account_id")?;
    let path = format!("/api/v1/avatars/{account_id}");
    let bytes = state.http.get_absolute_relative(&path).await?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(serde_json::to_vec(&ServeResult {
        account_id: params.account_id,
        content_type: "image/webp".into(),
        data_base64: encoded,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_webp() -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes[0..4].copy_from_slice(b"RIFF");
        bytes[8..12].copy_from_slice(b"WEBP");
        bytes
    }

    #[test]
    fn avatar_size_matches_web_limit() {
        assert!(validate_avatar_size(1).is_ok());
        assert!(validate_avatar_size(MAX_AVATAR_BYTES as u64).is_ok());
        assert!(validate_avatar_size(0).is_err());
        assert!(validate_avatar_size(MAX_AVATAR_BYTES as u64 + 1).is_err());
    }

    #[test]
    fn avatar_bytes_require_webp_signature_and_allowed_size() {
        assert!(validate_avatar_bytes(&valid_webp()).is_ok());
        assert!(validate_avatar_bytes(&[]).is_err());
        assert!(validate_avatar_bytes(b"not a webp image").is_err());

        let mut too_large = valid_webp();
        too_large.resize(MAX_AVATAR_BYTES + 1, 0);
        assert!(validate_avatar_bytes(&too_large).is_err());
    }

    #[test]
    fn path_segments_match_encode_uri_component_and_reject_controls() {
        assert_eq!(
            path_segment("id/part?x=1", "id").unwrap(),
            "id%2Fpart%3Fx%3D1"
        );
        assert_eq!(path_segment("дом", "id").unwrap(), "%D0%B4%D0%BE%D0%BC");
        assert_eq!(path_segment("a-b_c.d", "id").unwrap(), "a-b_c.d");
        assert!(path_segment("", "id").is_err());
        assert!(path_segment("bad\nid", "id").is_err());
    }

    #[test]
    fn group_and_channel_avatar_routes_are_distinct() {
        assert_eq!(
            conversation_avatar_path("groups", "group-id"),
            "/api/v1/groups/group-id/avatar"
        );
        assert_eq!(
            conversation_avatar_path("channels", "channel-id"),
            "/api/v1/channels/channel-id/avatar"
        );
    }

    #[test]
    fn only_ambiguous_finalize_failures_are_retried() {
        assert!(is_ambiguous_finalize_error(&Error::Network(
            "timeout".into()
        )));
        assert!(is_ambiguous_finalize_error(&Error::Server {
            status: 504,
            body: String::new(),
        }));
        assert!(!is_ambiguous_finalize_error(&Error::Server {
            status: 404,
            body: String::new(),
        }));
        assert!(!is_ambiguous_finalize_error(&Error::Server {
            status: 503,
            body: String::new(),
        }));
    }
}
