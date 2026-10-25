use std::sync::{Arc, Once};

/// Installs one process-local keyring mock before any test opens a database.
/// The mock must survive across multiple databases during the integration
/// test process so independently opened clients can load the same key.
pub fn use_memory_keyring() {
    static INITIALIZED: Once = Once::new();
    INITIALIZED.call_once(|| {
        let store = keyring_core::mock::Store::new().expect("create in-memory keyring store");
        let store: Arc<keyring_core::CredentialStore> = store;
        keyring_core::set_default_store(store);
    });
}
