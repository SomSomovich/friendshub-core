use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordRequest {
    pub peer_account_id: String,
    pub direction: String,
    pub status: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecordItem {
    pub id: String,
    pub peer_account_id: String,
    pub direction: String,
    pub status: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

pub async fn record(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: RecordRequest = serde_json::from_slice(&payload)?;
    let rec: CallRecordItem = state.http.post("/api/v1/calls", &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&rec)?)
}

pub async fn list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(serde_json::json!({}));
    let peer = v.get("peer_account_id").and_then(|x| x.as_str());
    let limit = v.get("limit").and_then(|x| x.as_i64()).unwrap_or(50);
    let path = match peer {
        Some(p) => format!("/api/v1/calls?peer_account_id={p}&limit={limit}"),
        None => format!("/api/v1/calls?limit={limit}"),
    };
    let rows: Vec<CallRecordItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn delete_one(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/calls/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

pub async fn clear(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/calls/clear", &serde_json::json!({}), Some(&token))
        .await?;
    Ok(br#"{"cleared":true}"#.to_vec())
}

#[allow(dead_code)]
fn _unused(_: CallRecordItem) {}
