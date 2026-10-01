//! Signal end-to-end encryption: stores, session management, envelope packing.

pub mod attachments;
pub mod device_cache;
pub mod error;
pub mod groups;
pub mod init;
pub mod manager;
pub mod send;
pub mod stores;

pub use error::{CryptoError, CryptoResult};
pub use send::SentEnvelope;
pub use stores::Store;
