use std::sync::Arc;

use crate::error::{Error, Result};
use crate::runtime::ActorState;

pub mod account_deletion;
pub mod attachments;
pub mod auth;
pub mod avatars;
pub mod bots;
pub mod calls;
pub mod channels;
pub mod contacts;
pub mod conversations;
pub mod devices;
pub mod groups;
pub mod invites;
pub mod messages;
pub mod prekeys;
pub mod profile;
pub mod sessions;
pub mod user_profiles;
pub mod webrtc;

/// Marker so ffi/mod.rs can reference the dispatch module without pulling
/// in all the endpoint stubs.
pub struct DispatchMarker;

/// Method IDs are namespaced by area; the ranges are documented in
/// docs/ffi.md. Only the service range is wired up so far.
pub async fn dispatch(state: &Arc<ActorState>, method: u32, _payload: Vec<u8>) -> Result<Vec<u8>> {
    match method {
        0x0000_0001 => ping().await,
        0x0000_0002 => version(state).await,
        _ => Err(Error::UnknownMethod(method)),
    }
}

async fn ping() -> Result<Vec<u8>> {
    Ok(br#"{"pong":true}"#.to_vec())
}

async fn version(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    let v = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "abi": crate::ffi::ABI_VERSION,
        "api_base": state.config.api_base,
        "ws_url": state.config.ws_url,
    });
    Ok(serde_json::to_vec(&v)?)
}
