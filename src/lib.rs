//! FriendsHub core client library.
//!
//! Everything between the UI and the server. The public surface is the flat
//! C ABI in [`ffi`].

pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod events;
pub mod logging;
pub mod ffi;
pub mod proto;
pub mod runtime;
pub mod transport;
pub mod util;
pub mod webrtc;
