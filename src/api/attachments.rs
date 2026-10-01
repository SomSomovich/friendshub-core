use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::api::common::{bearer, id_from};
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
    pub total_size: i64,
    pub chunk_count: i64,
}

/// Full upload flow: read the file from disk, ask the server for a chunk
/// layout, allocate the attachment, PUT each chunk to its presigned URL,
/// finalize.
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
    let total_size = metadata.len();

    let rec: RecommendResponse = state
        .http
        .post(
            "/api/v1/attachments/recommend",
            &RecommendRequest { total_size },
            Some(&token),
        )
        .await?;

    let init: InitResponse = state
        .http
        .post(
            "/api/v1/attachments/init",
            &InitRequest {
                chunk_sizes: rec.chunk_sizes.clone(),
                conversation_id: params.conversation_id.clone(),
                kind: params.kind.clone(),
            },
            Some(&token),
        )
        .await?;

    let mut uploads = init.uploads.clone();
    uploads.sort_by_key(|u| u.chunk_index);

    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| Error::Internal(format!("cannot open {}: {e}", params.file_path)))?;

    for (i, upload) in uploads.iter().enumerate() {
        let size = match rec.chunk_sizes.get(i) {
            Some(s) => *s as usize,
            None => {
                return Err(Error::Internal(format!(
                    "server returned chunk {} but the recommendation had only {} entries",
                    upload.chunk_index,
                    rec.chunk_sizes.len()
                )));
            }
        };

        let mut buf = vec![0u8; size];
        file.read_exact(&mut buf)
            .await
            .map_err(|e| Error::Internal(format!("short read on chunk {i}: {e}")))?;

        state.http.put_absolute(&upload.url, buf).await?;
    }

    let finalize_path = format!("/api/v1/attachments/{}/finalize", init.attachment_id);
    let _: serde_json::Value = state
        .http
        .post(&finalize_path, &serde_json::json!({}), Some(&token))
        .await?;

    Ok(serde_json::to_vec(&UploadResult {
        attachment_id: init.attachment_id,
        total_size: init.total_size,
        chunk_count: init.chunk_count,
    })?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadParams {
    pub attachment_id: String,
    pub output_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadResult {
    pub output_path: String,
    pub total_size: i64,
    pub chunk_count: i64,
}

/// Full download flow: fetch presigned GET URLs, download each chunk, write
/// them in order to disk.
pub async fn download(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let params: DownloadParams = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;

    let path = format!("/api/v1/attachments/{}", params.attachment_id);
    let resp: DownloadResponse = state.http.get(&path, Some(&token)).await?;

    let mut chunks = resp.chunks.clone();
    chunks.sort_by_key(|c| c.chunk_index);

    let out_path = PathBuf::from(&params.output_path);
    let mut out = tokio::fs::File::create(&out_path)
        .await
        .map_err(|e| Error::Internal(format!("cannot create {}: {e}", params.output_path)))?;

    for c in &chunks {
        let bytes = state.http.get_absolute(&c.url).await?;

        if bytes.len() as i64 != c.size_bytes {
            return Err(Error::Internal(format!(
                "chunk {} size mismatch: expected {}, got {}",
                c.chunk_index,
                c.size_bytes,
                bytes.len()
            )));
        }

        out.write_all(&bytes)
            .await
            .map_err(|e| Error::Internal(format!("write failed: {e}")))?;
    }

    out.flush().await.map_err(|e| Error::Internal(format!("flush failed: {e}")))?;

    Ok(serde_json::to_vec(&DownloadResult {
        output_path: params.output_path,
        total_size: resp.total_size,
        chunk_count: resp.chunk_count,
    })?)
}

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
