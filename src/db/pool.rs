use std::path::Path;
use std::sync::Arc;

use crate::db::encryption::{self, DatabaseFileState};
use crate::db::key_store::{self, DatabaseKeyStore, SystemKeyStore};
use crate::db::open_lock::DatabaseOpenLock;
use crate::error::{Error, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

pub type Db = SqlitePool;

pub async fn open(path: &Path) -> Result<Db> {
    let (path, file_state, open_lock) = acquire_open_lock(path).await?;
    let store = tokio::task::spawn_blocking(SystemKeyStore::new)
        .await
        .map_err(|_| Error::Database("key-store initialization task failed".into()))??;
    open_normalized_with_key_store(path, file_state, open_lock, Arc::new(store)).await
}

#[cfg(test)]
pub(crate) async fn open_with_key_store(
    path: &Path,
    store: Arc<dyn DatabaseKeyStore>,
) -> Result<Db> {
    let (path, file_state, open_lock) = acquire_open_lock(path).await?;
    open_normalized_with_key_store(path, file_state, open_lock, store).await
}

async fn acquire_open_lock(
    path: &Path,
) -> Result<(std::path::PathBuf, DatabaseFileState, DatabaseOpenLock)> {
    let requested_path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let path = key_store::normalize_path(&requested_path)?;
        let open_lock = DatabaseOpenLock::acquire(&path)?;
        let file_state = encryption::classify(&path)?;
        if file_state == DatabaseFileState::PlaintextSqlite {
            return Err(Error::Database(
                "plaintext SQLite databases are unsupported; use a new database path".into(),
            ));
        }
        Ok::<_, Error>((path, file_state, open_lock))
    })
    .await
    .map_err(|_| Error::Database("database startup lock task failed".into()))?
}

async fn open_normalized_with_key_store(
    path: std::path::PathBuf,
    file_state: DatabaseFileState,
    open_lock: DatabaseOpenLock,
    store: Arc<dyn DatabaseKeyStore>,
) -> Result<Db> {
    let provider = store.clone();
    let path_for_lookup = path.clone();
    let key = tokio::task::spawn_blocking(move || {
        let account = key_store::account_for_normalized_path(&path_for_lookup)?;
        let key = match file_state {
            DatabaseFileState::EncryptedOrUnknown => provider.get(&account)?.ok_or_else(|| {
                Error::Database("key for existing database is unavailable".into())
            })?,
            DatabaseFileState::Missing => {
                key_store::get_or_create_for_normalized_path(&path_for_lookup, provider.as_ref())?
            }
            DatabaseFileState::PlaintextSqlite => unreachable!("rejected before key-store setup"),
        };
        Ok::<_, Error>(key)
    })
    .await
    .map_err(|_| Error::Database("database key lookup task failed".into()))??;

    // SQLx keeps connect options for the lifetime of the pool. Keep the key
    // in a shared zeroizing buffer and install it through sqlite3_key after
    // each raw connection opens, rather than storing a normal string pragma.
    let key = Arc::new(key);
    let connection_key = key.clone();
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(file_state == DatabaseFileState::Missing)
        .pragma("temp_store", "MEMORY")
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _metadata| {
            let key = connection_key.clone();
            Box::pin(async move {
                encryption::apply_key(connection, key.as_ref()).await?;
                sqlx::query("PRAGMA cipher_compatibility = 4")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(|e| Error::Database(format!("failed to open database: {e}")))?;

    if let Err(error) = encryption::verify_pool(&pool).await {
        pool.close().await;
        return Err(error);
    }

    drop(key);
    drop(open_lock);
    Ok(pool)
}
