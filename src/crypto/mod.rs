//! Signal end-to-end encryption: stores, session management, envelope packing.

pub mod device_cache;
pub mod error;
pub mod manager;
pub mod stores;

pub use error::{CryptoError, CryptoResult};
pub use stores::Store;
