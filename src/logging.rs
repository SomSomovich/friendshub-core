//! Process-wide tracing setup.
//!
//! `tracing_subscriber` can only be initialised once per process. Multiple
//! handles may exist simultaneously, so the initialisation is guarded by a
//! `Once`; the first `fh_init` decides the level, later ones are no-ops.

use std::sync::Once;

use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

pub fn init_once(level: &str) {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(level));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .try_init();
    });
}
