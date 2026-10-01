use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::Result;
use crate::runtime::ActorState;

/// Begins enrollment. The response carries `secret_base32` and `otpauth_uri`;
/// the user scans the URI with their authenticator and then calls
/// `enroll_verify` with the first code it produces.
pub async fn enroll(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: serde_json::Value = state
        .http
        .post("/api/v1/2fa/enroll", &serde_json::json!({}), Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollVerifyRequest {
    pub code: String,
}

/// Confirms enrollment and returns the one-time backup codes.
///
/// These codes are shown once and never again; the library does not store
/// them. The response passes straight through to the caller, whose job it is
/// to make the user write them down.
pub async fn enroll_verify(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: EnrollVerifyRequest = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;
    let resp: serde_json::Value = state
        .http
        .post("/api/v1/2fa/enroll/verify", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisableRequest {
    pub password: String,
    pub code: String,
}

pub async fn disable(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: DisableRequest = serde_json::from_slice(&payload)?;
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/2fa/disable", &req, Some(&token))
        .await?;
    Ok(br#"{"disabled":true}"#.to_vec())
}
