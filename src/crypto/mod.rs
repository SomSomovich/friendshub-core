//! Signal end-to-end encryption: stores, session management, envelope packing.

pub mod attachments;
#[cfg(feature = "native")]
pub mod device_cache;
#[cfg(feature = "native")]
pub mod error;
#[cfg(feature = "native")]
pub mod groups;
pub mod history_protocol;
#[cfg(feature = "native")]
pub mod history_stage;
#[cfg(feature = "native")]
pub mod init;
#[cfg(feature = "native")]
pub mod manager;
pub mod receive;
#[cfg(feature = "native")]
pub mod send;
#[cfg(feature = "native")]
pub mod stores;

#[cfg(feature = "native")]
pub use error::{CryptoError, CryptoResult};
#[cfg(feature = "native")]
pub use send::SentEnvelope;
#[cfg(feature = "native")]
pub use stores::Store;
