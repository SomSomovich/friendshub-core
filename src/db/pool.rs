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
        match std::fs::symlink_metadata(removal_marker_path(&path)) {
            Ok(_) => return Err(Error::Database("local account removal is pending".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(Error::Database(
                    "could not inspect database removal marker".into(),
                ));
            }
        }
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

/// App-owned durable journal filename. Its presence prevents database opens
/// even after a crash between tombstoning and physical cleanup.
pub fn removal_marker_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".removing.json");
    name.into()
}

/// Non-sensitive cleanup stage, preserved for a specific native UI retry
/// message without exposing SQLite paths or credential-provider payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDatabaseRemovalError {
    InvalidPath,
    LockUnavailable,
    MissingMarker,
    Files,
    SecureStore,
}

/// Retryable physical cleanup, protected by the same lifetime lock used by
/// database opens. Missing files/credentials mean an earlier retry removed
/// them. The marker is retained by the caller until the manifest is committed.
pub fn remove_local_database(path: &Path) -> std::result::Result<(), LocalDatabaseRemovalError> {
    let fail = || LocalDatabaseRemovalError::Files;
    if !path.is_absolute() {
        return Err(fail());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => return Err(fail()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(fail()),
    }
    let path =
        key_store::normalize_path(path).map_err(|_| LocalDatabaseRemovalError::InvalidPath)?;
    let _lock =
        DatabaseOpenLock::acquire(&path).map_err(|_| LocalDatabaseRemovalError::LockUnavailable)?;
    // Never follow a database symlink to another account or a hard link to a
    // shared file. Validate all siblings before removing any of them.
    let paths = ["", "-wal", "-shm", "-journal"].map(|suffix| {
        let mut file = path.as_os_str().to_os_string();
        file.push(suffix);
        std::path::PathBuf::from(file)
    });
    for path in &paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(fail());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.nlink() != 1 {
                        return Err(fail());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(fail()),
        }
    }
    let marker = removal_marker_path(&path);
    if !std::fs::symlink_metadata(&marker)
        .map_err(|_| LocalDatabaseRemovalError::MissingMarker)?
        .file_type()
        .is_file()
    {
        return Err(LocalDatabaseRemovalError::MissingMarker);
    }
    let store = SystemKeyStore::new().map_err(|_| LocalDatabaseRemovalError::SecureStore)?;
    let account = key_store::account_for_normalized_path(&path)
        .map_err(|_| LocalDatabaseRemovalError::InvalidPath)?;
    for path in paths {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(fail()),
        }
    }
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or_else(fail)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| fail())?;
    // Delete the credential last; a failed file unlink must not make the
    // remaining encrypted database permanently unreadable.
    store
        .remove(&account)
        .map_err(|_| LocalDatabaseRemovalError::SecureStore)
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

    // Keep the cross-process path lock for the complete pool lifetime, not
    // just key setup. Purge must never unlink another live client's database.
    let open_lock = Arc::new(open_lock);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _metadata| {
            let _open_lock = &open_lock;
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
    Ok(pool)
}
