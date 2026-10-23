//! Browser-side Signal Protocol engine.
//!
//! Signal state stays in Rust memory. The browser persists the opaque JSON
//! snapshot through its existing IndexedDB layer and restores it on startup.

mod api;
mod store;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use wasm_bindgen::JsValue;

pub use api::{
    clear_identity_changes, create_sender_key_distribution, decrypt, encrypt, establish_session,
    generate_identity, generate_prekeys, group_decrypt, group_encrypt, identity_changes,
    load_identity, local_identity_public, ping, prekey_counts, process_sender_key_distribution,
    reset, restore, snapshot,
};

/// Keeps the legacy generated WASM package's startup export and panic diagnostics.
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

/// libsignal protocol/store futures in this binding do no I/O and are ready
/// during the initial poll. Keep the legacy synchronous WEB API while making
/// that invariant explicit instead of spinning forever on an unexpected yield.
pub(crate) fn block_on<F: Future>(mut future: F) -> Result<F::Output, JsValue> {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    fn raw_waker() -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    // SAFETY: this vtable only performs no-op operations and never dereferences
    // the null data pointer. All libsignal store futures used here are immediate.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    // SAFETY: the future remains pinned to this stack location until it returns.
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(js_err(
            "Signal operation attempted asynchronous I/O; browser API requires an immediate future",
        )),
    }
}

pub(crate) fn now() -> SystemTime {
    #[cfg(target_arch = "wasm32")]
    {
        let millis = js_sys::Date::now();
        if millis.is_finite() && millis >= 0.0 {
            UNIX_EPOCH + Duration::from_millis(millis as u64)
        } else {
            UNIX_EPOCH
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
    }
}

pub(crate) fn now_unix() -> i64 {
    now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn now_millis() -> u64 {
    now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn js_err(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
