//! Native database credentials. Call synchronous store operations via spawn_blocking.
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Once;
use std::sync::{Arc, Mutex};

use rand::TryRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

#[cfg(any(target_os = "android", test))]
pub(crate) mod android;

const SERVICE: &str = "com.friendshub.core.database-key.v1";

/// Installs one shared mock before unit tests exercise production database
/// opening. Keep it separate from the production store-initialization guard:
/// test processes may invoke this from multiple concurrently running tests.
#[cfg(test)]
pub(crate) fn use_test_keyring() {
    static INITIALIZED: Once = Once::new();
    INITIALIZED.call_once(|| {
        let store = keyring_core::mock::Store::new().expect("create in-memory keyring store");
        let store: Arc<keyring_core::CredentialStore> = store;
        keyring_core::set_default_store(store);
    });
}

pub(crate) trait DatabaseKeyStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>>;
    fn set(&self, account: &str, key: &[u8; 32]) -> Result<()>;
}

pub(crate) fn normalize_path(path: &Path) -> Result<PathBuf> {
    let invalid = || Error::Database("invalid database path or missing parent".into());
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(invalid());
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let path = path.canonicalize().map_err(|_| invalid())?;
            if !path.is_file() {
                return Err(invalid());
            }
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = parent.canonicalize().map_err(|_| invalid())?;
            if !parent.is_dir() {
                return Err(invalid());
            }
            Ok(parent.join(path.file_name().ok_or_else(invalid)?))
        }
        Err(_) => Err(invalid()),
    }
}

#[cfg(test)]
pub(crate) fn account_for_path(path: &Path) -> Result<String> {
    let path = normalize_path(path)?;
    account_for_normalized_path(&path)
}

/// Hash a path that has already been normalized by `normalize_path`.
/// Callers use this to keep key identity, lock identity, and SQLite filename
/// on the same canonical path without normalizing it again.
pub(crate) fn account_for_normalized_path(path: &Path) -> Result<String> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::Database("invalid normalized database path".into()));
    }
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    };
    #[cfg(not(any(unix, windows)))]
    let bytes = path.as_os_str().as_encoded_bytes().to_vec();
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Caller must first confirm the database is absent and hold its startup lock.
/// Persist the key before allowing encrypted database creation.
#[cfg(test)]
pub(crate) fn get_or_create(
    path: &Path,
    store: &dyn DatabaseKeyStore,
) -> Result<Zeroizing<[u8; 32]>> {
    let path = normalize_path(path)?;
    get_or_create_for_normalized_path(&path, store)
}

/// Caller must hold the database-open lock and pass its normalized path.
pub(crate) fn get_or_create_for_normalized_path(
    path: &Path,
    store: &dyn DatabaseKeyStore,
) -> Result<Zeroizing<[u8; 32]>> {
    let account = account_for_normalized_path(path)?;
    if let Some(key) = store.get(&account)? {
        return Ok(key);
    }
    let mut key = Zeroizing::new([0; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut *key)
        .map_err(|_| Error::Database("database key generation failed".into()))?;
    store.set(&account, &key)?;
    Ok(key)
}

fn store_error(mut error: keyring_core::Error) -> Error {
    // Providers may attach secret buffers to decoding errors. Scrub them and
    // deliberately omit provider Debug/Display output from public errors.
    match &mut error {
        keyring_core::Error::BadEncoding(bytes) | keyring_core::Error::BadDataFormat(bytes, _) => {
            bytes.zeroize()
        }
        _ => {}
    }
    Error::Database("secure database key store unavailable".into())
}

fn decode_secret(result: keyring_core::Result<Vec<u8>>) -> Result<Option<Zeroizing<[u8; 32]>>> {
    match result {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.len() != 32 {
                return Err(Error::Database("invalid database key length".into()));
            }
            let mut key = Zeroizing::new([0; 32]);
            key.copy_from_slice(&bytes);
            Ok(Some(key))
        }
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(error) => Err(store_error(error)),
    }
}

/// Select the platform store in production. The volatile mock is accepted
/// only from unit-test builds or the explicit `test-keyring` feature used by
/// file-backed integration tests; a normal library build never adopts a
/// process-local credential store installed by its host or another crate.
fn select_store(
    current: Option<Arc<keyring_core::CredentialStore>>,
    create_platform: impl FnOnce() -> keyring_core::Result<Arc<keyring_core::CredentialStore>>,
    allow_test_mock: bool,
) -> Result<Arc<keyring_core::CredentialStore>> {
    if allow_test_mock
        && let Some(store) =
            current.filter(|store| store.as_any().is::<keyring_core::mock::Store>())
    {
        return Ok(store);
    }
    create_platform().map_err(store_error)
}

#[cfg(any(test, feature = "test-keyring"))]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    // Tests must install a memory store or inject a factory into select_store.
    // Never initialize an OS keychain from a test-keyring build.
    Err(keyring_core::Error::NoDefaultStore)
}

#[cfg(not(any(test, feature = "test-keyring")))]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    #[cfg(target_os = "linux")]
    let store = zbus_secret_service_keyring_store::Store::new();
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new();
    #[cfg(target_os = "ios")]
    let store = apple_native_keyring_store::protected::Store::new();
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new();
    #[cfg(target_os = "android")]
    let store = android_native_keyring_store::Store::new();
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "android"
    ))]
    return store.map(|store| store as Arc<keyring_core::CredentialStore>);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "android"
    )))]
    Err(keyring_core::Error::NotSupportedByStore(
        "secure database key store unsupported".into(),
    ))
}

pub(crate) struct SystemKeyStore;

impl SystemKeyStore {
    pub(crate) fn remove(&self, account: &str) -> Result<()> {
        match keyring_core::Entry::new(SERVICE, account)
            .map_err(store_error)?
            .delete_credential()
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(store_error(error)),
        }
    }

    pub(crate) fn new() -> Result<Self> {
        static INITIALIZED: Mutex<bool> = Mutex::new(false);
        let mut initialized = INITIALIZED
            .lock()
            .map_err(|_| Error::Database("key store initialization failed".into()))?;
        if !*initialized {
            let store = select_store(
                keyring_core::get_default_store(),
                platform_store,
                cfg!(any(test, feature = "test-keyring")),
            )?;
            keyring_core::set_default_store(store);
            *initialized = true;
        }
        Ok(Self)
    }
}

impl DatabaseKeyStore for SystemKeyStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let entry = keyring_core::Entry::new(SERVICE, account).map_err(store_error)?;
        decode_secret(entry.get_secret())
    }
    fn set(&self, account: &str, key: &[u8; 32]) -> Result<()> {
        keyring_core::Entry::new(SERVICE, account)
            .map_err(store_error)?
            .set_secret(key)
            .map_err(store_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeStore {
        key: Mutex<Option<Zeroizing<[u8; 32]>>>,
        fail: bool,
        writes: Mutex<usize>,
    }
    impl DatabaseKeyStore for FakeStore {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
            if self.fail {
                return Err(Error::Database("store unavailable".into()));
            }
            Ok(self
                .key
                .lock()
                .unwrap()
                .as_ref()
                .map(|k| Zeroizing::new(**k)))
        }
        fn set(&self, _: &str, key: &[u8; 32]) -> Result<()> {
            if self.fail {
                return Err(Error::Database("store unavailable".into()));
            }
            *self.writes.lock().unwrap() += 1;
            *self.key.lock().unwrap() = Some(Zeroizing::new(*key));
            Ok(())
        }
    }
    #[test]
    #[cfg(not(target_os = "android"))]
    fn android_bridge_is_unsupported_off_android() {
        assert_eq!(
            unsafe { crate::ffi::fh_android_init(std::ptr::null_mut(), std::ptr::null_mut()) },
            -2
        );
    }
    fn directory() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fh-key-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn normalized_identity_survives_file_creation() {
        let dir = directory();
        let path = dir.join("db.sqlite");
        let before = account_for_path(&path).unwrap();
        assert_eq!(before.len(), 64);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(before, account_for_path(&dir.join("./db.sqlite")).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn invalid_paths_fail() {
        assert!(normalize_path(std::path::Path::new("")).is_err());
        let dir = directory();
        assert!(normalize_path(&dir.join("missing/db")).is_err());
        assert!(normalize_path(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn only_no_entry_means_absent_and_key_length_is_validated() {
        assert!(
            decode_secret(Err(keyring_core::Error::NoEntry))
                .unwrap()
                .is_none()
        );
        assert!(decode_secret(Err(keyring_core::Error::NoDefaultStore)).is_err());
        for len in [0, 31, 33] {
            assert!(decode_secret(Ok(vec![7; len])).is_err());
        }
        assert_eq!(
            **decode_secret(Ok(vec![7; 32])).unwrap().as_ref().unwrap(),
            [7; 32]
        );
    }
    #[test]
    fn generated_key_is_persisted_before_caller_can_create_file() {
        let dir = directory();
        let path = dir.join("db");
        let store = FakeStore::default();
        let key = get_or_create(&path, &store).unwrap();
        assert!(!path.exists());
        assert_eq!(*store.writes.lock().unwrap(), 1);
        assert_eq!(*key, *get_or_create(&path, &store).unwrap());
        assert_eq!(*store.writes.lock().unwrap(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn store_selection_preserves_only_preinstalled_memory_mock() {
        let memory: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let selected = select_store(
            Some(memory.clone()),
            || panic!("a preinstalled memory store must prevent platform initialization"),
            true,
        )
        .unwrap();
        assert!(std::sync::Arc::ptr_eq(&memory, &selected));
    }
    #[test]
    fn store_selection_without_mock_uses_platform_factory() {
        let platform: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let selected = select_store(None, || Ok(platform.clone()), true).unwrap();
        assert!(std::sync::Arc::ptr_eq(&platform, &selected));
        assert!(select_store(None, || Err(keyring_core::Error::NoDefaultStore), true).is_err());
    }
    #[test]
    fn production_store_selection_rejects_preinstalled_memory_mock() {
        let memory: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let platform: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let selected = select_store(Some(memory.clone()), || Ok(platform.clone()), false).unwrap();
        assert!(std::sync::Arc::ptr_eq(&platform, &selected));
        assert!(!std::sync::Arc::ptr_eq(&memory, &selected));
    }
    #[test]
    fn store_selection_does_not_preserve_arbitrary_custom_store() {
        struct CustomStore;
        impl keyring_core::api::CredentialStoreApi for CustomStore {
            fn vendor(&self) -> String {
                "test-custom".into()
            }
            fn id(&self) -> String {
                "test-custom".into()
            }
            fn build(
                &self,
                _: &str,
                _: &str,
                _: Option<&std::collections::HashMap<&str, &str>>,
            ) -> keyring_core::Result<keyring_core::Entry> {
                panic!("selection must not read or write credentials")
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        let custom: std::sync::Arc<keyring_core::CredentialStore> =
            std::sync::Arc::new(CustomStore);
        let platform: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let selected = select_store(Some(custom.clone()), || Ok(platform.clone()), true).unwrap();
        assert!(std::sync::Arc::ptr_eq(&platform, &selected));
        assert!(!std::sync::Arc::ptr_eq(&custom, &selected));
    }
    #[test]
    fn system_adapter_preserves_preinstalled_memory_store() {
        use_test_keyring();
        let memory = keyring_core::get_default_store().unwrap();
        let store = SystemKeyStore::new().unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &memory,
            &keyring_core::get_default_store().unwrap()
        ));
        let key = Zeroizing::new([42; 32]);
        assert!(store.get("task-1-test").unwrap().is_none());
        store.set("task-1-test", &key).unwrap();
        assert_eq!(*store.get("task-1-test").unwrap().unwrap(), *key);
    }
    #[test]
    fn failed_write_does_not_return_an_unpersisted_key() {
        struct RejectWrites;
        impl DatabaseKeyStore for RejectWrites {
            fn get(&self, _: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
                Ok(None)
            }
            fn set(&self, _: &str, _: &[u8; 32]) -> Result<()> {
                Err(Error::Database("write denied".into()))
            }
        }
        let dir = directory();
        let path = dir.join("db");
        assert!(get_or_create(&path, &RejectWrites).is_err());
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn aliases_share_the_normalized_identity() {
        let dir = directory();
        let real = dir.join("db");
        std::fs::write(&real, b"").unwrap();
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(
            account_for_path(&real).unwrap(),
            account_for_path(&alias).unwrap()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn unavailable_store_never_creates_file_or_key() {
        let dir = directory();
        let path = dir.join("db");
        let store = FakeStore {
            fail: true,
            ..Default::default()
        };
        assert!(get_or_create(&path, &store).is_err());
        assert!(!path.exists());
        assert_eq!(*store.writes.lock().unwrap(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
