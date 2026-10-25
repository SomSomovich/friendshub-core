use std::path::{Path, PathBuf};

use friendshub_core::Client;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::db;
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqlitePoolOptions};

#[path = "support/keyring.rs"]
mod keyring;

fn database_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "friendshub-db-encryption-{label}-{}-{}.sqlite",
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

async fn apply_raw_key(connection: &mut SqliteConnection, key: &[u8; 32]) {
    let mut handle = connection.lock_handle().await.unwrap();
    // SAFETY: `lock_handle` gives exclusive access to this live SQLite
    // connection, and `key` remains readable for the duration of the call.
    let status = unsafe {
        libsqlite3_sys::sqlite3_key(
            handle.as_raw_handle().as_ptr(),
            key.as_ptr().cast(),
            key.len() as i32,
        )
    };
    assert_eq!(status, libsqlite3_sys::SQLITE_OK);
}

#[tokio::test(flavor = "current_thread")]
async fn raw_key_can_be_installed_before_the_first_schema_access() {
    let path = database_path("raw-key");
    let key = [0x6d; 32];
    let create_options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .pragma("temp_store", "MEMORY")
        .foreign_keys(true);

    let mut connection = SqliteConnection::connect_with(&create_options)
        .await
        .unwrap();
    apply_raw_key(&mut connection, &key).await;
    sqlx::query("PRAGMA cipher_compatibility = 4")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE private_rows (value TEXT NOT NULL)")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO private_rows VALUES ('raw-key-marker')")
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();

    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
    assert!(
        !bytes
            .windows(b"raw-key-marker".len())
            .any(|window| window == b"raw-key-marker")
    );

    let reopen_options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .pragma("temp_store", "MEMORY")
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&reopen_options)
        .await
        .unwrap();
    apply_raw_key(&mut connection, &key).await;
    sqlx::query("PRAGMA cipher_compatibility = 4")
        .execute(&mut connection)
        .await
        .unwrap();
    let value: String = sqlx::query_scalar("SELECT value FROM private_rows")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(value, "raw-key-marker");
    connection.close().await.unwrap();
    remove_database(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn opened_file_has_sqlcipher_header_and_reopens_with_library_key() {
    keyring::use_memory_keyring();
    let path = database_path("roundtrip");

    let pool = db::pool::open(&path).await.unwrap();
    sqlx::query("CREATE TABLE private_rows (value TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    const SECRET_MARKER: &str = "FH_SQLCIPHER_AT_REST_MARKER_9f14a7d3";
    sqlx::query("INSERT INTO private_rows VALUES (?)")
        .bind(SECRET_MARKER)
        .execute(&pool)
        .await
        .unwrap();
    let cipher_version: String = sqlx::query_scalar("PRAGMA cipher_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!cipher_version.is_empty());
    pool.close().await;

    let header = std::fs::read(&path).unwrap();
    assert!(header.len() >= 16);
    assert_ne!(&header[..16], b"SQLite format 3\0");
    assert!(
        !header
            .windows(SECRET_MARKER.len())
            .any(|window| window == SECRET_MARKER.as_bytes())
    );

    let pool = db::pool::open(&path).await.unwrap();
    let value: String = sqlx::query_scalar("SELECT value FROM private_rows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, SECRET_MARKER);

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
    pool.close().await;
    remove_database(&path);
}

#[test]
fn client_startup_uses_encrypted_database_pool() {
    keyring::use_memory_keyring();
    let path = database_path("client");
    let client = Client::open(Config {
        db_path: path.clone(),
        api_base: "http://127.0.0.1:1".into(),
        ws_url: "ws://127.0.0.1:1".into(),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    })
    .unwrap();
    drop(client);

    let header = std::fs::read(&path).unwrap();
    assert!(header.len() >= 16);
    assert_ne!(&header[..16], b"SQLite format 3\0");
    remove_database(&path);
}
