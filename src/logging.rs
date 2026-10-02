//! Process-wide tracing setup.
//!
//! `tracing_subscriber` can only be initialised once per process. Multiple
//! handles may exist simultaneously, so the initialisation is guarded by a
//! `Once`; the first `fh_init` decides the level and format, later ones are
//! no-ops.

use std::sync::Once;

use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// Initialises the subscriber. `format` is either `"text"` (default) or
/// `"json"`. Anything else is treated as `"text"`.
pub fn init_once(level: &str, format: &str) {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(level));

        if format.eq_ignore_ascii_case("json") {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .json()
                .try_init();
        } else {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .try_init();
        }
    });
}
