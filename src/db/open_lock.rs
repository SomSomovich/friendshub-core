//! Cross-process serialization for database key setup and initial creation.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::db::key_store;
use crate::error::{Error, Result};

/// Cross-process startup lock for one normalized database identity.
///
/// Callers retain the lock from before key lookup until an encrypted pool has
/// been initialized and verified. The lock file stays on disk because
/// unlinking an advisory lock can split processes across inodes.
pub(crate) struct DatabaseOpenLock {
    _file: File,
}

impl DatabaseOpenLock {
    pub(crate) fn acquire(normalized_database_path: &Path) -> Result<Self> {
        let path = Self::path_for(normalized_database_path)?;
        let file = open_lock_file(&path)
            .map_err(|_| Error::Database("could not create database startup lock".into()))?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { _file: file }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(Error::Database("database is busy; retry opening it".into()))
            }
            Err(_) => Err(Error::Database(
                "could not acquire database startup lock".into(),
            )),
        }
    }

    fn path_for(normalized_database_path: &Path) -> Result<PathBuf> {
        let identity = key_store::account_for_normalized_path(normalized_database_path)?;
        let parent = normalized_database_path
            .parent()
            .filter(|parent| parent.is_dir())
            .ok_or_else(|| Error::Database("invalid normalized database path".into()))?;
        Ok(parent.join(format!(".friendshub-{identity}.open.lock")))
    }
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database lock path is not a private regular file",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database lock path is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "friendshub-open-lock-{label}-{}-{}.sqlite",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        if let Ok(normalized) = key_store::normalize_path(path)
            && let Ok(lock) = DatabaseOpenLock::path_for(&normalized)
        {
            let _ = std::fs::remove_file(lock);
        }
    }

    #[cfg(unix)]
    #[test]
    fn lock_uses_normalized_identity_and_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = path("permissions");
        std::fs::write(&path, b"encrypted database fixture").unwrap();
        let normalized = key_store::normalize_path(&path).unwrap();
        let lock = DatabaseOpenLock::acquire(&normalized).unwrap();
        let alias = normalized
            .parent()
            .unwrap()
            .join(".")
            .join(normalized.file_name().unwrap());
        let alias = key_store::normalize_path(&alias).unwrap();
        assert_eq!(
            DatabaseOpenLock::path_for(&normalized).unwrap(),
            DatabaseOpenLock::path_for(&alias).unwrap()
        );
        let lock_path = DatabaseOpenLock::path_for(&normalized).unwrap();
        let mode = std::fs::metadata(lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(lock);
        cleanup(&path);
    }

    #[test]
    fn another_process_cannot_acquire_the_same_startup_lock() {
        let path = path("process-lock");
        std::fs::write(&path, b"encrypted database fixture").unwrap();
        let normalized = key_store::normalize_path(&path).unwrap();
        let lock = DatabaseOpenLock::acquire(&normalized).unwrap();
        let started = Instant::now();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "db::open_lock::tests::child_lock_reports_busy",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("FH_TEST_DATABASE_LOCK_CHILD", &normalized)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(lock);
        cleanup(&path);
    }

    #[test]
    fn child_lock_reports_busy() {
        let Some(path) = std::env::var_os("FH_TEST_DATABASE_LOCK_CHILD") else {
            return;
        };
        let path = PathBuf::from(path);
        let error = match DatabaseOpenLock::acquire(&path) {
            Ok(_) => panic!("a competing process must not acquire the startup lock"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("busy"));
        assert!(error.to_string().contains("retry"));
    }
}
