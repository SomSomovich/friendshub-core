use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitiateResponse {
    pub confirm_after: i64,
    pub confirm_until: i64,
    pub confirm_after_seconds: i64,
    pub confirm_window_seconds: i64,
}

pub async fn initiate(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: InitiateResponse = state
        .http
        .post("/api/v1/account/delete/initiate", &serde_json::json!({}), Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub password: Option<String>,
    pub code: Option<String>,
}

pub async fn confirm(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: ConfirmRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/account/delete/confirm", &req, Some(&token))
        .await?;
    Ok(br#"{"confirmed":true}"#.to_vec())
}

pub async fn cancel(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/account/delete/cancel", &serde_json::json!({}), Some(&token))
        .await?;
    Ok(br#"{"cancelled":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub pending: bool,
    pub account_id: Option<String>,
    pub initiated_at: Option<i64>,
    pub confirm_after: Option<i64>,
    pub confirm_until: Option<i64>,
}

pub async fn status(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: StatusResponse = state
        .http
        .get("/api/v1/account/delete/status", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: InitiateResponse, _: ConfirmRequest, _: StatusResponse) {}
