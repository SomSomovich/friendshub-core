use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, i64_field, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyRef {
    pub id: i64,
    #[serde(rename = "pub")]
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekeyRef {
    pub id: i64,
    #[serde(rename = "pub")]
    pub public_key: String,
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPrekeysRequest {
    pub signed_prekey: Option<SignedPrekeyRef>,
    pub kyber_last_resort: Option<SignedPrekeyRef>,
    #[serde(default)]
    pub one_time_prekeys: Vec<PrekeyRef>,
    #[serde(default)]
    pub kyber_one_time_prekeys: Vec<PrekeyRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPrekeysResponse {
    pub one_time_inserted: u64,
    pub kyber_one_time_inserted: u64,
}

pub async fn upload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: UploadPrekeysRequest = serde_json::from_slice(&payload)?;
    let resp: UploadPrekeysResponse = state
        .http
        .post("/api/v1/devices/me/prekeys", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyStatusResponse {
    pub one_time_available: i64,
    pub kyber_one_time_available: i64,
    pub has_signed_prekey: bool,
    pub has_kyber_last_resort: bool,
}

pub async fn status(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: PrekeyStatusResponse = state
        .http
        .get("/api/v1/devices/me/prekeys/status", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundleResponse {
    pub account_id: String,
    pub device_number: i64,
    pub registration_id: i64,
    pub identity_key_pub: String,
    pub signed_prekey: SignedPrekeyRef,
    pub kyber_last_resort: SignedPrekeyRef,
    pub one_time_prekey: Option<PrekeyRef>,
    pub kyber_one_time_prekey: Option<PrekeyRef>,
}

pub async fn fetch_bundle(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let account_id = str_field(&v, "account_id")?;
    let device_number = i64_field(&v, "device_number")?;
    let path = format!("/api/v1/accounts/{account_id}/devices/{device_number}/bundle");
    let resp: PrekeyBundleResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: PrekeyRef, _: PrekeyStatusResponse, _: UploadPrekeysResponse) {}
