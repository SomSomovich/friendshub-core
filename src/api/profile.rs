use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::api::profile_extras::ProfileField;
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUsernameRequest {
    pub username: String,
}

pub async fn update_username(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: UpdateUsernameRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .put("/api/v1/profile/username", &req, Some(&token))
        .await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateStatusRequest {
    pub text: Option<String>,
    pub emoji: Option<String>,
    pub ttl_seconds: Option<i64>,
}

pub async fn update_custom_status(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: UpdateStatusRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .put("/api/v1/profile/status", &req, Some(&token))
        .await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

pub async fn clear_custom_status(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state
        .http
        .delete("/api/v1/profile/status", Some(&token))
        .await?;
    Ok(br#"{"cleared":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvisibleModeRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvisibleModeResponse {
    pub enabled: bool,
}

pub async fn set_invisible_mode(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: InvisibleModeRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .put("/api/v1/profile/invisible", &req, Some(&token))
        .await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

/// Reads the stored invisibility setting, as used by the web settings screen.
pub async fn get_invisible_mode(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: InvisibleModeResponse = state
        .http
        .get("/api/v1/profile/invisible", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&response)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionItem {
    pub target_account_id: String,
    pub kind: String,
    pub created_at: i64,
}

pub async fn list_exceptions(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<ExceptionItem> = state
        .http
        .get("/api/v1/profile/presence-exceptions", Some(&token))
        .await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExceptionRequest {
    pub target_account_id: String,
    pub kind: String,
}

pub async fn add_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: ExceptionRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .post("/api/v1/profile/presence-exceptions", &req, Some(&token))
        .await?;
    Ok(br#"{"added":true}"#.to_vec())
}

pub async fn remove_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: ExceptionRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state
        .http
        .post(
            "/api/v1/profile/presence-exceptions/remove",
            &req,
            Some(&token),
        )
        .await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicProfile {
    pub id: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
    pub is_blocked_by_me: bool,
    pub is_contact: bool,
    #[serde(default)]
    pub profile_fields: Vec<ProfileField>,
}

pub async fn get_public_profile(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/accounts/{id}/profile");
    let profile: PublicProfile = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&profile)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceResponse {
    pub account_id: String,
    pub is_online: bool,
    pub last_seen: Option<i64>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
    pub visible: bool,
}

pub async fn get_presence(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "account_id")?;
    let path = format!("/api/v1/accounts/{id}/presence");
    let presence: PresenceResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&presence)?)
}

#[allow(dead_code)]
fn _unused(_: PublicProfile, _: PresenceResponse, _: UpdateStatusRequest, _: InvisibleModeRequest) {
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invisible_mode_response_matches_web_contract() {
        let response = InvisibleModeResponse { enabled: true };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({"enabled": true})
        );
        assert_eq!(
            serde_json::from_value::<InvisibleModeResponse>(json!({"enabled": false})).unwrap(),
            InvisibleModeResponse { enabled: false }
        );
    }

    #[test]
    fn public_profile_keeps_profile_fields_and_defaults_legacy_responses() {
        let profile: PublicProfile = serde_json::from_value(json!({
            "id": "account-id",
            "user_id": 7,
            "fh_number": "FH-000007",
            "username": "alice",
            "avatar_url": null,
            "custom_status_text": null,
            "custom_status_emoji": null,
            "custom_status_expires_at": null,
            "is_blocked_by_me": false,
            "is_contact": true,
            "profile_fields": [{"label": "Website", "value": "example.test"}]
        }))
        .unwrap();
        assert_eq!(
            profile.profile_fields,
            [ProfileField {
                label: "Website".into(),
                value: "example.test".into(),
            }]
        );
        assert_eq!(
            serde_json::to_value(profile).unwrap()["profile_fields"],
            json!([{"label": "Website", "value": "example.test"}])
        );

        let legacy: PublicProfile = serde_json::from_value(json!({
            "id": "account-id",
            "user_id": 7,
            "fh_number": "FH-000007",
            "username": "alice",
            "avatar_url": null,
            "custom_status_text": null,
            "custom_status_emoji": null,
            "custom_status_expires_at": null,
            "is_blocked_by_me": false,
            "is_contact": true
        }))
        .unwrap();
        assert!(legacy.profile_fields.is_empty());
    }
}
