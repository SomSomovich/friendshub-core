use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::Result;
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

// ---------------------------------------------------------------
// End-to-end call signaling: create or accept a peer connection and
// send the SDP through the Signal-encrypted envelope channel in one call.
// ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InitiateCallRequest {
    pub recipient_account_id: String,
    pub call_id: String,
}

pub async fn initiate_call(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: InitiateCallRequest = serde_json::from_slice(&payload)?;
    let ice = fetch_ice(state).await?;
    let sdp = state.webrtc.create_offer(&req.call_id, ice).await?;
    let sent = match crate::webrtc::signal::send_call_offer(
        state,
        &req.recipient_account_id,
        &req.call_id,
        &sdp,
    )
    .await
    {
        Ok(sent) => sent,
        Err(error) => {
            let _ = state.webrtc.close(&req.call_id).await;
            return Err(error);
        }
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "call_id": req.call_id,
        "sdp": sdp,
        "envelopes_sent": sent.len(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct AcceptIncomingCallRequest {
    pub recipient_account_id: String,
    pub call_id: String,
    pub remote_sdp: String,
}

pub async fn accept_call(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: AcceptIncomingCallRequest = serde_json::from_slice(&payload)?;
    let ice = fetch_ice(state).await?;
    let sdp = state
        .webrtc
        .accept_offer(&req.call_id, &req.remote_sdp, ice)
        .await?;
    let sent = match crate::webrtc::signal::send_call_answer(
        state,
        &req.recipient_account_id,
        &req.call_id,
        &sdp,
    )
    .await
    {
        Ok(sent) => sent,
        Err(error) => {
            let _ = state.webrtc.close(&req.call_id).await;
            return Err(error);
        }
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "call_id": req.call_id,
        "sdp": sdp,
        "envelopes_sent": sent.len(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct SendIceRequest {
    pub recipient_account_id: String,
    pub call_id: String,
    pub candidate: serde_json::Value,
}

pub async fn send_ice(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: SendIceRequest = serde_json::from_slice(&payload)?;
    let sent = crate::webrtc::signal::send_call_ice(
        state,
        &req.recipient_account_id,
        &req.call_id,
        req.candidate,
    )
    .await?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes_sent": sent.len(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct HangupRequest {
    pub recipient_account_id: String,
    pub call_id: String,
    pub reason: Option<String>,
}

pub async fn hangup(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: HangupRequest = serde_json::from_slice(&payload)?;
    let _ = state.webrtc.close(&req.call_id).await;
    let sent = crate::webrtc::signal::send_call_hangup(
        state,
        &req.recipient_account_id,
        &req.call_id,
        req.reason.as_deref(),
    )
    .await?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes_sent": sent.len(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct RejectRequest {
    pub recipient_account_id: String,
    pub call_id: String,
    pub reason: Option<String>,
}

pub async fn reject(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: RejectRequest = serde_json::from_slice(&payload)?;
    let sent = crate::webrtc::signal::send_call_reject(
        state,
        &req.recipient_account_id,
        &req.call_id,
        req.reason.as_deref(),
    )
    .await?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes_sent": sent.len(),
    }))?)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use prost::Message;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;
    use crate::config::{Config, DiscoveryConfig};
    use crate::db::{auth::AuthState, migrations::MIGRATOR};
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    fn respond(mut stream: &TcpStream, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write response headers");
        stream.write_all(body).expect("write response body");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn initiate_call_closes_peer_when_signal_delivery_fails() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
                let address = listener.local_addr().expect("fixture address");
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accept ICE request");
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request);
                    let body = crate::proto::rest::community::IceServersResponse {
                        ice_servers: Vec::new(),
                        ttl_seconds: 60,
                    }
                    .encode_to_vec();
                    respond(&stream, &body);
                });

                let config = Config {
                    db_path: "/tmp/friendshub-core-webrtc-test.db".into(),
                    api_base: format!("http://{address}"),
                    ws_url: format!("ws://{address}/ws"),
                    discovery: DiscoveryConfig {
                        enabled: false,
                        ..DiscoveryConfig::default()
                    },
                    log_level: "error".into(),
                    log_format: "text".into(),
                };
                let db = SqlitePoolOptions::new()
                    .max_connections(2)
                    .connect("sqlite::memory:")
                    .await
                    .expect("open in-memory database");
                MIGRATOR.run(&db).await.expect("apply migrations");
                crate::db::auth::store(
                    &db,
                    &AuthState {
                        account_id: Some("sender".into()),
                        session_token: Some("session-token".into()),
                        device_number: Some(1),
                        totp_enabled: Some(0),
                        ..AuthState::default()
                    },
                )
                .await
                .expect("store session");
                sqlx::query(
                    "INSERT INTO device_cache (account_id, devices_json, fetched_at) VALUES ('recipient', '[]', ?)",
                )
                .bind(crate::util::time::now_unix())
                .execute(&db)
                .await
                .expect("seed an empty recipient device list");
                let http = HttpClient::new(&config).expect("build HTTP client");
                let state = Arc::new(ActorState::new(config, db, http));

                let result = initiate_call(
                    &state,
                    br#"{"recipient_account_id":"recipient","call_id":"call-1"}"#.to_vec(),
                )
                .await;
                assert!(result.is_err(), "missing recipient devices must fail signaling");
                assert!(
                    state.webrtc.list_active().await.is_empty(),
                    "failed signaling must not retain the newly created peer"
                );

                drop(state);
                server.join().expect("fixture server must exit");
            })
            .await;
    }
}
