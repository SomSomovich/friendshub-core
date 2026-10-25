//! SQLCipher file identification and connection verification.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatabaseFileState {
    Missing,
    PlaintextSqlite,
    EncryptedOrUnknown,
}

/// Install the key through SQLCipher's raw API, before any schema query. This
/// avoids copying key material into SQLx's cloneable connection options or
/// query argument buffers; SQLCipher retains its native copy for the open
/// connection.
pub(crate) async fn apply_key(
    connection: &mut sqlx::SqliteConnection,
    key: &[u8; 32],
) -> std::result::Result<(), sqlx::Error> {
    let mut handle = connection.lock_handle().await?;
    // SAFETY: SQLx's locked handle excludes concurrent access; `key` remains
    // valid for the duration of the FFI call.
    let status = unsafe {
        libsqlite3_sys::sqlite3_key(
            handle.as_raw_handle().as_ptr(),
            key.as_ptr().cast(),
            key.len() as i32,
        )
    };
    if status == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(format!(
            "SQLCipher rejected database key initialization with status {status}"
        )))
    }
}

pub(crate) fn classify(path: &Path) -> Result<DatabaseFileState> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DatabaseFileState::Missing);
        }
        Err(_) => {
            return Err(Error::Database("could not inspect database file".into()));
        }
    };
    if !metadata.file_type().is_file() {
        return Err(Error::Database(
            "database path is not a regular file".into(),
        ));
    }

    let mut file = File::open(path)
        .map_err(|_| Error::Database("could not read database file header".into()))?;
    let mut header = [0; SQLITE_HEADER.len()];
    let mut filled = 0;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(Error::Database(
                    "could not read database file header".into(),
                ));
            }
        }
    }

    if filled == header.len() && &header == SQLITE_HEADER {
        Ok(DatabaseFileState::PlaintextSqlite)
    } else {
        Ok(DatabaseFileState::EncryptedOrUnknown)
    }
}

pub(crate) async fn verify_pool(pool: &sqlx::SqlitePool) -> Result<()> {
    use sqlx::Row;

    let cipher_version = sqlx::query("PRAGMA cipher_version")
        .fetch_optional(pool)
        .await
        .map_err(|error| Error::Database(format!("database cipher verification failed: {error}")))?
        .and_then(|row| row.try_get::<String, _>(0).ok())
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| Error::Database("SQLCipher is unavailable for the database".into()))?;

    let _ = cipher_version;
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master")
        .fetch_one(pool)
        .await
        .map_err(|error| Error::Database(format!("database authentication failed: {error}")))?;

    let integrity = sqlx::query("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .map_err(|error| Error::Database(format!("database integrity check failed: {error}")))?
        .try_get::<String, _>(0)
        .map_err(|error| Error::Database(format!("database integrity check failed: {error}")))?;
    if integrity != "ok" {
        return Err(Error::Database("database integrity check failed".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::key_store::DatabaseKeyStore;
    use crate::db::pool;
    use crate::error::{Error, Result};
    use sqlx::Row;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct MemoryKeyStore {
        entries: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
        fail_get: bool,
        fail_set: bool,
        get_calls: AtomicUsize,
        set_calls: AtomicUsize,
    }

    impl DatabaseKeyStore for MemoryKeyStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_get {
                return Err(Error::Database("injected key-store failure".into()));
            }
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(account)
                .map(|key| Zeroizing::new(**key)))
        }

        fn set(&self, account: &str, key: &[u8; 32]) -> Result<()> {
            self.set_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_set {
                return Err(Error::Database("injected key-store failure".into()));
            }
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_owned(), Zeroizing::new(*key));
            Ok(())
        }
    }

    fn database_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "friendshub-encryption-{label}-{}-{}.sqlite",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn remove_database(path: &Path) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
    }

    #[test]
    fn classification_distinguishes_missing_plaintext_and_unknown_files() {
        let path = database_path("classify");
        assert_eq!(classify(&path).unwrap(), DatabaseFileState::Missing);

        std::fs::write(&path, b"SQLite format 3\0plaintext fixture").unwrap();
        assert_eq!(classify(&path).unwrap(), DatabaseFileState::PlaintextSqlite);

        std::fs::write(&path, b"encrypted or arbitrary bytes").unwrap();
        assert_eq!(
            classify(&path).unwrap(),
            DatabaseFileState::EncryptedOrUnknown
        );
        remove_database(&path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn symlink_alias_uses_the_same_normalized_database_and_key() {
        let target = database_path("symlink-target");
        let alias = database_path("symlink-alias");
        let store = Arc::new(MemoryKeyStore::default());
        let db = pool::open_with_key_store(&target, store.clone())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE private_rows (value INTEGER NOT NULL)")
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO private_rows VALUES (41)")
            .execute(&db)
            .await
            .unwrap();
        db.close().await;
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        let db = pool::open_with_key_store(&alias, store).await.unwrap();
        let value: i64 = sqlx::query_scalar("SELECT value FROM private_rows")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(value, 41);
        db.close().await;
        let _ = std::fs::remove_file(&alias);
        remove_database(&target);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn new_file_is_keyed_reopenable_and_unreadable_without_its_key() {
        let path = database_path("roundtrip");
        let store = Arc::new(MemoryKeyStore::default());

        let db = pool::open_with_key_store(&path, store.clone())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE private_rows (value TEXT NOT NULL)")
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO private_rows VALUES ('secret row')")
            .execute(&db)
            .await
            .unwrap();
        db.close().await;

        let db = pool::open_with_key_store(&path, store).await.unwrap();
        let value: String = sqlx::query_scalar("SELECT value FROM private_rows")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(value, "secret row");
        db.close().await;

        let unkeyed = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(false),
            )
            .await
            .unwrap();
        assert!(
            sqlx::query("SELECT name FROM sqlite_master")
                .fetch_all(&unkeyed)
                .await
                .is_err()
        );
        unkeyed.close().await;
        remove_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn plaintext_database_is_rejected_unchanged_before_key_store_access() {
        let path = database_path("plaintext-rejected");
        let plaintext = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::query("CREATE TABLE plaintext_marker (value TEXT NOT NULL)")
            .execute(&plaintext)
            .await
            .unwrap();
        sqlx::query("INSERT INTO plaintext_marker VALUES ('keep unchanged')")
            .execute(&plaintext)
            .await
            .unwrap();
        plaintext.close().await;

        let original = std::fs::read(&path).unwrap();
        let sidecars = ["-wal", "-shm", "-journal"]
            .map(|suffix| (suffix, format!("preserve {suffix}").into_bytes()));
        for (suffix, contents) in &sidecars {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            std::fs::write(sidecar, contents).unwrap();
        }
        let store = Arc::new(MemoryKeyStore::default());
        let error = pool::open_with_key_store(&path, store.clone())
            .await
            .expect_err("plaintext databases are unsupported; no import path exists");

        assert!(error.to_string().contains("plaintext"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        for (suffix, contents) in sidecars {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            assert_eq!(std::fs::read(sidecar).unwrap(), contents);
        }
        assert_eq!(store.get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.set_calls.load(Ordering::SeqCst), 0);
        remove_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_key_is_rejected_without_changing_encrypted_file() {
        let path = database_path("wrong-key");
        let original_store = Arc::new(MemoryKeyStore::default());
        let db = pool::open_with_key_store(&path, original_store)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE protected (id INTEGER PRIMARY KEY)")
            .execute(&db)
            .await
            .unwrap();
        db.close().await;
        let original_bytes = std::fs::read(&path).unwrap();

        let wrong_store = Arc::new(MemoryKeyStore::default());
        let account = crate::db::key_store::account_for_path(&path).unwrap();
        wrong_store
            .entries
            .lock()
            .unwrap()
            .insert(account, Zeroizing::new([0xA5; 32]));
        assert!(pool::open_with_key_store(&path, wrong_store).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        remove_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unavailable_key_store_does_not_create_a_database_file() {
        let path = database_path("store-unavailable");
        let store = Arc::new(MemoryKeyStore {
            fail_get: true,
            ..MemoryKeyStore::default()
        });
        assert!(pool::open_with_key_store(&path, store).await.is_err());
        assert!(!path.exists());
        remove_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn moved_encrypted_file_is_not_replaced_when_its_path_has_no_key() {
        let original = database_path("moved-original");
        let moved = database_path("moved-copy");
        let store = Arc::new(MemoryKeyStore::default());
        let db = pool::open_with_key_store(&original, store.clone())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE protected (id INTEGER PRIMARY KEY)")
            .execute(&db)
            .await
            .unwrap();
        db.close().await;
        std::fs::copy(&original, &moved).unwrap();
        let before = std::fs::read(&moved).unwrap();

        assert!(pool::open_with_key_store(&moved, store).await.is_err());
        assert_eq!(std::fs::read(&moved).unwrap(), before);
        remove_database(&original);
        remove_database(&moved);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_acquired_pool_connection_can_read_encrypted_schema() {
        let path = database_path("connections");
        let db = pool::open_with_key_store(&path, Arc::new(MemoryKeyStore::default()))
            .await
            .unwrap();
        let mut connections = Vec::new();
        for _ in 0..4 {
            connections.push(db.acquire().await.unwrap());
        }
        for connection in &mut connections {
            let row = sqlx::query("SELECT count(*) AS count FROM sqlite_master")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            assert!(row.get::<i64, _>("count") >= 0);
        }
        drop(connections);
        db.close().await;
        remove_database(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn key_persistence_failure_does_not_create_a_database_file() {
        let path = database_path("set-failure");
        let store = Arc::new(MemoryKeyStore {
            fail_set: true,
            ..MemoryKeyStore::default()
        });
        assert!(pool::open_with_key_store(&path, store).await.is_err());
        assert!(!path.exists());
        remove_database(&path);
    }
}
