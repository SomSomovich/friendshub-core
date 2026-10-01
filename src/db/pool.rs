use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::error::{Error, Result};

pub type Db = SqlitePool;

pub async fn open(path: &Path) -> Result<Db> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .map_err(|e| Error::Database(format!("failed to open database: {e}")))?;

    Ok(pool)
}
