//! Device lists for peers.
//!
//! The server exposes one endpoint per account (account_id -> devices), and
//! multi-device fanout needs to know every device of the recipient before
//! encrypting. The cache table already exists; the fetch path lands once the
//! backend endpoint is wired up.

use sqlx::SqlitePool;

use crate::error::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedDevice {
    pub device_number: i64,
    pub registration_id: i64,
    pub identity_key_pub: String,
}

pub async fn get(_db: &SqlitePool, _account_id: &str) -> Result<Option<Vec<CachedDevice>>> {
    Ok(None)
}
