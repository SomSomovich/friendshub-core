use serde::{Deserialize, Serialize};

use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
}

pub async fn register(state: &ActorState, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: RegisterRequest = serde_json::from_slice(&payload)?;
    let resp: RegisterResponse = state.http.post("/api/v1/register", &req, None).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub fh_number: String,
    pub password: String,
    pub device_number: i64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginResponse {
    Session { session_token: String, expires_at: i64 },
    TotpRequired { challenge_token: String, expires_in_seconds: u64 },
}

#[derive(Serialize)]
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

pub async fn login(state: &ActorState, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: LoginRequest = serde_json::from_slice(&payload)?;
    let resp: LoginResponse = state.http.post("/api/v1/login", &req, None).await?;

    match resp {
        LoginResponse::Session { session_token, expires_at } => {
            let me: MeResponse =
                state.http.get("/api/v1/me", Some(&session_token)).await?;

            db_auth::store(
                &state.db,
                &me.id,
                "",
                &session_token,
                req.device_number,
                Some(&me.fh_number),
                expires_at,
            )
            .await?;

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

#[derive(Serialize, Deserialize)]
pub struct Login2faRequest {
    pub challenge_token: String,
    pub code: String,
    pub device_number: i64,
}

pub async fn login_2fa(state: &ActorState, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: Login2faRequest = serde_json::from_slice(&payload)?;
    let resp: LoginResponse = state.http.post("/api/v1/login/2fa", &req, None).await?;

    let LoginResponse::Session { session_token, expires_at } = resp else {
        return Err(Error::Internal("2fa endpoint returned a challenge".into()));
    };

    let me: MeResponse = state.http.get("/api/v1/me", Some(&session_token)).await?;

    db_auth::store(
        &state.db,
        &me.id,
        "",
        &session_token,
        req.device_number,
        Some(&me.fh_number),
        expires_at,
    )
    .await?;

    Ok(serde_json::to_vec(&LoginResult {
        kind: "session".into(),
        session_token: Some(session_token),
        expires_at: Some(expires_at),
        challenge_token: None,
        expires_in_seconds: None,
        account: Some(me),
    })?)
}

pub async fn logout(state: &ActorState) -> Result<Vec<u8>> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    let token = auth.session_token.clone().ok_or(Error::NotAuthenticated)?;

    // A 401 on logout means the session is already gone; local state is
    // cleared regardless. Only genuine transport failures surface.
    if let Err(Error::Server { status, .. }) = state.http.post_void("/api/v1/logout", &serde_json::json!({}), Some(&token)).await {
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

pub async fn me(state: &ActorState) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let me: MeResponse = state.http.get("/api/v1/me", Some(&token)).await?;
    Ok(serde_json::to_vec(&me)?)
}

async fn bearer(state: &ActorState) -> Result<String> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    match auth.session_token {
        Some(t) if !t.is_empty() => Ok(t),
        _ => Err(Error::NotAuthenticated),
    }
}

#[allow(dead_code)]
fn _touch(_: i64) -> i64 {
    now_unix()
}
