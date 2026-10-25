//! Shared protobuf and REST wire contracts for FriendsHub.
//!
//! The default `native` feature enables the actor, persistence, transports,
//! WebRTC, and C ABI. The `wasm` feature keeps the portable schema and route
//! codec available to browser bindings without compiling native runtime
//! dependencies.

#[cfg(feature = "native")]
pub mod api;
#[cfg(feature = "native")]
pub mod bot_api;
#[cfg(feature = "native")]
pub mod client;
#[cfg(feature = "native")]
pub mod config;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod crypto;
#[cfg(feature = "native")]
pub mod db;
#[cfg(feature = "native")]
pub mod discovery;
pub mod error;
#[cfg(feature = "native")]
pub mod events;
#[cfg(feature = "native")]
pub mod ffi;
#[cfg(feature = "native")]
pub mod logging;
#[cfg(feature = "native")]
pub mod method_ids;
pub mod proto;
#[cfg(feature = "native")]
pub mod runtime;
pub mod transport;
#[cfg(feature = "native")]
pub mod util;
#[cfg(feature = "native")]
pub mod webrtc;

#[cfg(feature = "native")]
pub use client::Client;
#[cfg(feature = "native")]
pub use events::EventHandler;
