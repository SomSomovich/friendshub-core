use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
}

pub async fn register(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: RegisterRequest = serde_json::from_slice(&payload)?;
    let resp: RegisterResponse = state.http.post("/api/v1/register", &req, None).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub fh_number: String,
    pub password: String,
    pub device_number: i64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginResponse {
    Session { session_token: String, expires_at: i64 },
    TotpRequired { challenge_token: String, expires_in_seconds: u64 },
}

#[derive(Debug, Serialize)]
pub struct LoginResult {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<MeResponse>,
}

pub async fn login(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: LoginRequest = serde_json::from_slice(&payload)?;
    let resp: LoginResponse = state.http.post("/api/v1/login", &req, None).await?;

    match resp {
        LoginResponse::Session { session_token, expires_at } => {
            let me: MeResponse = state.http.get("/api/v1/me", Some(&session_token)).await?;
            persist_session(state, &me, &session_token, req.device_number, expires_at).await?;

            Ok(serde_json::to_vec(&LoginResult {
                kind: "session".into(),
                session_token: Some(session_token),
                expires_at: Some(expires_at),
                challenge_token: None,
                expires_in_seconds: None,
                account: Some(me),
            })?)
        }
        LoginResponse::TotpRequired { challenge_token, expires_in_seconds } => {
            Ok(serde_json::to_vec(&LoginResult {
                kind: "totp_required".into(),
                session_token: None,
                expires_at: None,
                challenge_token: Some(challenge_token),
                expires_in_seconds: Some(expires_in_seconds),
                account: None,
            })?)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Login2faRequest {
    pub challenge_token: String,
    pub code: String,
    pub device_number: i64,
}

pub async fn login_2fa(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: Login2faRequest = serde_json::from_slice(&payload)?;
    let resp: LoginResponse = state.http.post("/api/v1/login/2fa", &req, None).await?;

    let LoginResponse::Session { session_token, expires_at } = resp else {
        return Err(Error::Internal("2fa endpoint returned a challenge".into()));
    };

    let me: MeResponse = state.http.get("/api/v1/me", Some(&session_token)).await?;
    persist_session(state, &me, &session_token, req.device_number, expires_at).await?;

    Ok(serde_json::to_vec(&LoginResult {
        kind: "session".into(),
        session_token: Some(session_token),
        expires_at: Some(expires_at),
        challenge_token: None,
        expires_in_seconds: None,
        account: Some(me),
    })?)
}

pub async fn logout(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    let token = auth.session_token.clone().ok_or(Error::NotAuthenticated)?;

    // A 401 means the session is already gone on the server; the local
    // state is cleared regardless. Only genuine transport failures surface.
    if let Err(Error::Server { status, .. }) = state
        .http
        .post_void("/api/v1/logout", &serde_json::json!({}), Some(&token))
        .await
    {
        if status != 401 {
            return Err(Error::Server { status, body: "logout failed".into() });
        }
    }

    db_auth::clear(&state.db).await?;
    Ok(br#"{"ok":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub id: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub totp_enabled: bool,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
}

pub async fn me(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let me: MeResponse = state.http.get("/api/v1/me", Some(&token)).await?;
    persist_profile_fields(state, &me).await?;
    Ok(serde_json::to_vec(&me)?)
}

/// Stores the session and everything the profile response carries, so a UI
/// that opens the database can show the account's own name and avatar
/// without a second call to `/me`.
async fn persist_session(
    state: &Arc<ActorState>,
    me: &MeResponse,
    token: &str,
    device_number: i64,
    expires_at: i64,
) -> Result<()> {
    let mut auth = db_auth::load(&state.db).await?.unwrap_or_default();
    auth.account_id = Some(me.id.clone());
    auth.session_token = Some(token.to_string());
    auth.device_number = Some(device_number);
    auth.fh_number = Some(me.fh_number.clone());
    auth.expires_at = Some(expires_at);
    auth.username = Some(me.username.clone());
    auth.avatar_url = me.avatar_url.clone();
    auth.custom_status_text = me.custom_status_text.clone();
    auth.custom_status_emoji = me.custom_status_emoji.clone();
    auth.custom_status_expires_at = me.custom_status_expires_at;
    auth.totp_enabled = Some(if me.totp_enabled { 1 } else { 0 });
    db_auth::store(&state.db, &auth).await?;
    Ok(())
}

/// Refreshes just the profile fields, leaving the session untouched.
async fn persist_profile_fields(state: &Arc<ActorState>, me: &MeResponse) -> Result<()> {
    let Some(mut auth) = db_auth::load(&state.db).await? else {
        return Ok(());
    };
    auth.username = Some(me.username.clone());
    auth.avatar_url = me.avatar_url.clone();
    auth.custom_status_text = me.custom_status_text.clone();
    auth.custom_status_emoji = me.custom_status_emoji.clone();
    auth.custom_status_expires_at = me.custom_status_expires_at;
    auth.totp_enabled = Some(if me.totp_enabled { 1 } else { 0 });
    db_auth::store(&state.db, &auth).await?;
    Ok(())
}

async fn bearer(state: &Arc<ActorState>) -> Result<String> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    match auth.session_token {
        Some(t) if !t.is_empty() => Ok(t),
        _ => Err(Error::NotAuthenticated),
    }
}
