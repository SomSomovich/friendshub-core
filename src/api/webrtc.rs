use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServersResponse {
    pub ice_servers: Vec<IceServer>,
    pub ttl_seconds: u64,
}

pub async fn ice_servers(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: IceServersResponse = state
        .http
        .get("/api/v1/webrtc/ice-servers", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

async fn fetch_ice(state: &Arc<ActorState>) -> Result<Vec<serde_json::Value>> {
    let token = bearer(state).await?;
    let resp: IceServersResponse = state
        .http
        .get("/api/v1/webrtc/ice-servers", Some(&token))
        .await?;
    Ok(resp
        .ice_servers
        .into_iter()
        .map(|s| serde_json::to_value(&s).unwrap_or(serde_json::Value::Null))
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct CreateCallRequest {
    pub call_id: String,
}

#[derive(Debug, Serialize)]
pub struct SdpResponse {
    pub call_id: String,
    pub sdp: String,
}

/// Creates a peer connection and returns an SDP offer.
pub async fn create_offer(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: CreateCallRequest = serde_json::from_slice(&payload)?;
    let ice = fetch_ice(state).await?;
    let sdp = state.webrtc.create_offer(&req.call_id, ice).await?;
    Ok(serde_json::to_vec(&SdpResponse {
        call_id: req.call_id,
        sdp,
    })?)
}

#[derive(Debug, Deserialize)]
pub struct AcceptCallRequest {
    pub call_id: String,
    pub remote_sdp: String,
}

/// Accepts a remote SDP offer and returns an SDP answer.
pub async fn accept_offer(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: AcceptCallRequest = serde_json::from_slice(&payload)?;
    let ice = fetch_ice(state).await?;
    let sdp = state
        .webrtc
        .accept_offer(&req.call_id, &req.remote_sdp, ice)
        .await?;
    Ok(serde_json::to_vec(&SdpResponse {
        call_id: req.call_id,
        sdp,
    })?)
}

#[derive(Debug, Deserialize)]
pub struct ApplyAnswerRequest {
    pub call_id: String,
    pub remote_sdp: String,
}

pub async fn apply_answer(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: ApplyAnswerRequest = serde_json::from_slice(&payload)?;
    state
        .webrtc
        .apply_answer(&req.call_id, &req.remote_sdp)
        .await?;
    Ok(br#"{"ok":true}"#.to_vec())
}

#[derive(Debug, Deserialize)]
pub struct AddIceRequest {
    pub call_id: String,
    pub candidate: serde_json::Value,
}

pub async fn add_ice(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: AddIceRequest = serde_json::from_slice(&payload)?;
    state
        .webrtc
        .add_ice_candidate(&req.call_id, req.candidate)
        .await?;
    Ok(br#"{"ok":true}"#.to_vec())
}

#[derive(Debug, Deserialize)]
pub struct CreateDataChannelRequest {
    pub call_id: String,
    pub label: String,
}

pub async fn create_data_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: CreateDataChannelRequest = serde_json::from_slice(&payload)?;
    state
        .webrtc
        .create_data_channel(&req.call_id, &req.label)
        .await?;
    Ok(br#"{"ok":true}"#.to_vec())
}

#[derive(Debug, Deserialize)]
pub struct CloseCallRequest {
    pub call_id: String,
}

pub async fn close_call(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: CloseCallRequest = serde_json::from_slice(&payload)?;
    state.webrtc.close(&req.call_id).await?;
    Ok(br#"{"ok":true}"#.to_vec())
}

pub async fn list_active(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let rows = state.webrtc.list_active().await;
    Ok(serde_json::to_vec(&rows)?)
}

#[allow(dead_code)]
fn _unused(_: Error, _: SdpResponse) {}
