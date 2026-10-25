use std::ffi::c_void;
use std::path::{Path, PathBuf};

use friendshub_core::Client;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::db;
use friendshub_core::ffi::{self, handle::FhHandle};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[path = "support/keyring.rs"]
mod keyring;

const PLAINTEXT_VALUE: &str = "FH_PLAINTEXT_DB_MUST_REMAIN_UNCHANGED";

#[derive(Default)]
struct CapturedResult {
    status: Option<i32>,
    bytes: Vec<u8>,
}

unsafe extern "C" fn capture_result(
    user_data: *mut c_void,
    status: i32,
    data: *const u8,
    data_len: usize,
) {
    // SAFETY: each test passes a live CapturedResult and fh_init invokes this
    // callback synchronously before returning.
    let captured = unsafe { &mut *user_data.cast::<CapturedResult>() };
    captured.status = Some(status);
    if !data.is_null() {
        // SAFETY: the result bytes are borrowed and readable for data_len
        // until this callback returns, as required by the C ABI.
        captured.bytes = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
    }
}

fn database_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "friendshub-db-entrypoint-{label}-{}-{}.sqlite",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

fn config(path: PathBuf) -> Config {
    Config {
        db_path: path,
        api_base: "http://127.0.0.1:1".into(),
        ws_url: "ws://127.0.0.1:1".into(),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    }
}

fn config_json(path: &Path) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "db_path": path,
        "api_base": "http://127.0.0.1:1",
        "ws_url": "ws://127.0.0.1:1",
        "discovery": { "enabled": false },
        "log_level": "off",
        "log_format": "text"
    }))
    .unwrap()
}

async fn create_plaintext_database(path: &Path) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE plaintext_rows (value TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO plaintext_rows VALUES (?)")
        .bind(PLAINTEXT_VALUE)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn assert_plaintext_database_unchanged(path: &Path, original: &[u8]) {
    let current = std::fs::read(path).unwrap();
    assert_eq!(current, original);
    assert_eq!(&current[..16], b"SQLite format 3\0");

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let value: String = sqlx::query_scalar("SELECT value FROM plaintext_rows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, PLAINTEXT_VALUE);
    pool.close().await;
}

fn remove_database(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn database_pool_rejects_plaintext_without_modifying_it() {
    keyring::use_memory_keyring();
    let path = database_path("pool");
    create_plaintext_database(&path).await;
    let original = std::fs::read(&path).unwrap();

    let error = db::pool::open(&path)
        .await
        .expect_err("plaintext databases have no import or fallback path");
    assert!(error.to_string().contains("plaintext"));
    assert_plaintext_database_unchanged(&path, &original).await;
    remove_database(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn safe_client_open_rejects_plaintext_without_modifying_it() {
    keyring::use_memory_keyring();
    let path = database_path("safe-client");
    create_plaintext_database(&path).await;
    let original = std::fs::read(&path).unwrap();

    assert!(Client::open(config(path.clone())).is_err());
    assert_plaintext_database_unchanged(&path, &original).await;
    remove_database(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn c_init_rejects_plaintext_without_returning_a_handle_or_modifying_it() {
    keyring::use_memory_keyring();
    let path = database_path("c-init");
    create_plaintext_database(&path).await;
    let original = std::fs::read(&path).unwrap();
    let config = config_json(&path);
    let mut handle: *mut FhHandle = std::ptr::null_mut();
    let mut captured = CapturedResult::default();

    // SAFETY: the config, output handle, and callback context remain valid;
    // the callback copies its borrowed bytes before fh_init returns.
    let status = unsafe {
        ffi::fh_init(
            config.as_ptr(),
            config.len(),
            &mut handle,
            capture_result,
            (&mut captured as *mut CapturedResult).cast(),
        )
    };

    assert_ne!(status, 0);
    assert!(handle.is_null());
    assert_eq!(captured.status, Some(status));
    assert!(!captured.bytes.is_empty());
    assert!(String::from_utf8_lossy(&captured.bytes).contains("plaintext"));
    assert_plaintext_database_unchanged(&path, &original).await;
    remove_database(&path);
}
