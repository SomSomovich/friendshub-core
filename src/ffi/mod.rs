//! C ABI surface. Each raw-pointer boundary has an explicit safety contract.
//!
//! Every function that touches raw pointers is `unsafe extern "C"` and
//! carries a `# Safety` section spelling out what the caller must guarantee.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::Arc;

use crate::api;
use crate::config::Config;
use crate::db;
use crate::error::{Error, Result};
use crate::events::EventQueue;
use crate::runtime::{Actor, ActorState};
use crate::transport::HttpClient;

pub mod events;
pub mod handle;
pub mod panic;

pub use events::{
    FH_EVENT_CALLBACKS_V2_ABI_VERSION, FhEventCallback, FhEventCallbacks, FhEventCallbacksV2,
    FhEventView,
};

/// Receives a synchronous result from `fh_init` or `fh_call`. `data` is
/// borrowed until the callback returns.
pub type FhResultCallback =
    unsafe extern "C" fn(user_data: *mut c_void, status: i32, data: *const u8, data_len: usize);

use handle::FhHandle;
use panic::guard;

pub const ABI_VERSION: u32 = 3;

const ABI_STRING: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

const METHOD_ACK_EVENT: u32 = 0x0000_0004;

#[unsafe(no_mangle)]
pub extern "C" fn fh_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn fh_abi_string() -> *const c_char {
    ABI_STRING.as_ptr() as *const c_char
}

/// Registers the Android application context before core startup.
/// Returns 0 on success, -1 on failure, and -2 on non-Android targets.
///
/// # Safety
/// On Android, java_vm must be a valid JavaVM pointer and the context must be
/// a JNI global reference to the application context. Both must remain valid
/// for the process lifetime. The host must not initialize/release ndk-context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_android_init(
    java_vm: *mut c_void,
    application_context_global_ref: *mut c_void,
) -> i32 {
    guard(-1, || {
        #[cfg(target_os = "android")]
        {
            // SAFETY: forwarded from this function's host pointer contract.
            match unsafe {
                db::key_store::android::initialize_android_context(
                    java_vm,
                    application_context_global_ref,
                )
            } {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (java_vm, application_context_global_ref);
            -2
        }
    })
}

/// Registers an Android context already initialized by `android-activity`.
/// This is intended for hosts such as Slint's Android backend, which installs
/// the process-lifetime Application context before entering `android_main`.
/// Unlike [`fh_android_init`], this function reuses `ndk-context`'s existing
/// handles and does not initialize its singleton again. Call it after the
/// Android activity runtime startup and before `fh_init` or `Client::open`.
/// Returns 0 on success, -1 on failure (including a call before the context is
/// available), and -2 on non-Android targets.
#[unsafe(no_mangle)]
pub extern "C" fn fh_android_init_from_ndk_context() -> i32 {
    guard(-1, || {
        #[cfg(target_os = "android")]
        {
            match db::key_store::android::initialize_existing_ndk_context() {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            -2
        }
    })
}

/// Initialises a handle for one account and supplies any result through a
/// synchronous callback borrow. On success the result is empty; on failure it
/// is a JSON error object. The result memory is owned and released by the
/// library after the callback returns.
///
/// # Safety
///
/// - `config_json` must point to at least `config_len` readable bytes, or be
///   null with `config_len == 0`.
/// - `out_handle` must be a valid, writable pointer.
/// - `callback` must be a valid function pointer and must not unwind across
///   the C ABI boundary.
/// - `user_data` must remain valid for the duration of the callback.
/// - callback `data` is borrowed only until the callback returns; it must not
///   be retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_init(
    config_json: *const u8,
    config_len: usize,
    out_handle: *mut *mut FhHandle,
    callback: FhResultCallback,
    user_data: *mut c_void,
) -> i32 {
    guard(-1, || {
        // SAFETY: this wrapper forwards the input and output pointer contracts
        // to the private initializer and keeps the result alive through the
        // synchronous callback.
        let (status, result) = unsafe { init_inner(config_json, config_len, out_handle) };
        deliver_result(callback, user_data, status, &result);
        status
    })
}

unsafe fn init_inner(
    config_json: *const u8,
    config_len: usize,
    out_handle: *mut *mut FhHandle,
) -> (i32, Vec<u8>) {
    guard((-1, Vec::new()), || {
        if out_handle.is_null() {
            return (-1, Vec::new());
        }
        // SAFETY: the public `fh_init` contract requires a valid writable
        // out_handle pointer.
        unsafe { *out_handle = std::ptr::null_mut() };

        if config_json.is_null() || config_len == 0 {
            return error_result(&Error::Config("config is empty".into()));
        }

        // SAFETY: the public `fh_init` contract requires config_json to be
        // readable for config_len bytes.
        let bytes = unsafe { std::slice::from_raw_parts(config_json, config_len) };

        let cfg = match Config::from_json(bytes) {
            Ok(c) => c,
            Err(e) => return error_result(&e),
        };

        #[cfg(target_os = "android")]
        let android_open_guard = match db::key_store::android::begin_core_open() {
            Ok(open_guard) => open_guard,
            Err(error) => return error_result(&error),
        };

        crate::logging::init_once(&cfg.log_level, &cfg.log_format);

        let events = Arc::new(EventQueue::new());
        let actor_events = events.clone();

        let actor = match Actor::spawn(move || {
            Box::pin(async move {
                // Resolve the backend URLs before anything touches the network.
                // The discovery step is allowed to fail back to config-supplied
                // URLs, so a missing discovery file is not fatal on its own.
                let resolved = crate::discovery::resolve(&cfg).await?;
                let mut config = cfg;
                config.api_base = resolved.api_base;
                config.ws_url = resolved.ws_url;

                let http = HttpClient::new(&config)?;
                let db = db::pool::open(&config.db_path).await?;
                db::migrations::MIGRATOR
                    .run(&db)
                    .await
                    .map_err(|e| Error::Database(format!("migrations failed: {e}")))?;
                Ok(ActorState::new_with_events(config, db, http, actor_events))
            })
        }) {
            Ok(actor) => actor,
            Err(error) => return error_result(&error),
        };

        #[cfg(target_os = "android")]
        android_open_guard.commit();

        let handle = Box::new(FhHandle::new(actor, events));
        // SAFETY: out_handle was checked non-null and is writable by contract.
        unsafe { *out_handle = Box::into_raw(handle) };
        (0, Vec::new())
    })
}

/// Destroys a handle and everything it owns.
///
/// # Safety
///
/// `handle` must be either null or a pointer returned by `fh_init` that
/// has not been destroyed yet. Passing the same non-null pointer twice is
/// undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_destroy(handle: *mut FhHandle) {
    guard((), || {
        if handle.is_null() {
            return;
        }
        // Clone the shared inner state before shutdown. A callback already in
        // flight may also call `fh_destroy`, so this local Arc must keep the
        // actor and event queue alive until cleanup finishes.
        // SAFETY: the caller promises `handle` came from `fh_init` and has
        // not been destroyed.
        let inner = unsafe { (&*handle).inner_arc() };
        if !inner.begin_destroy() {
            return;
        }
        unsafe {
            inner.clear_event_callbacks();
            drop(Box::from_raw(handle));
        }
    });
}

/// Installs or clears the per-event callback table.
///
/// Passing a null `callbacks` pointer clears the current handler. Events
/// produced until another handler is registered are queued internally and
/// pushed to the next handler. Each non-null slot is called on the library's
/// dedicated callback worker thread. The event view and its JSON bytes are
/// borrowed only for the duration of the callback; the library allocates and
/// releases that memory.
///
/// `user_data` must remain valid until this function returns after replacing
/// or clearing a handler, or until `fh_destroy` returns. When clear/destroy is
/// called reentrantly from a callback, the currently executing callback must
/// keep using its context only until that callback itself returns.
///
/// # Safety
///
/// - `handle` must be a live handle returned by `fh_init`.
/// - `callbacks` must point to a readable `FhEventCallbacks` when non-null.
/// - `user_data` must satisfy the lifetime rules above for every installed
///   callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_set_event_callbacks(
    handle: *mut FhHandle,
    callbacks: *const FhEventCallbacks,
    user_data: *mut c_void,
) -> i32 {
    guard(-1, || {
        if handle.is_null() {
            return -1;
        }
        // Clone the state before any operation that can wait for callbacks;
        // a callback may destroy the public handle while it is waiting.
        // SAFETY: the caller promises a live handle.
        let inner = unsafe { (&*handle).inner_arc() };
        if callbacks.is_null() {
            inner.clear_event_callbacks();
            return 0;
        }
        // SAFETY: the caller promises a readable callback table; it is Copy,
        // so no pointer to the caller's table is retained.
        let callbacks = unsafe { *callbacks };
        let handler = Arc::new(events::FfiEventHandler::new(callbacks, user_data));
        if let Err(error) = inner.set_event_callbacks(Some(handler)) {
            tracing::warn!(%error, "could not start callback worker");
            return 1;
        }
        if let Err(error) = inner.activate_event_push() {
            tracing::warn!(%error, "could not activate event callbacks");
            return 1;
        }
        0
    })
}

/// Registers the size/versioned V2 callback table, including semantic events
/// for decrypted messages, actions, calls, attachments, and history transfer.
///
/// The original `fh_set_event_callbacks` and `FhEventCallbacks` layout are
/// unchanged. V2 callbacks receive the same library-owned borrowed event view;
/// durable IDs remain valid for `fh_ack_event` and must be acknowledged only
/// after the caller has persisted the event. In particular, history chunks
/// must remain unacknowledged until the reassembled history item is committed.
///
/// # Safety
///
/// - `handle` must be a live handle returned by `fh_init`.
/// - `callbacks` must be null or point to a readable V2 header containing
///   `struct_size` and `abi_version`. If those fields identify a supported V2
///   table, the entire region described by `struct_size` must be readable.
/// - `user_data` must remain valid through callback completion, following the
///   same replacement, unregister, and destruction rules as the legacy API.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_set_event_callbacks_v2(
    handle: *mut FhHandle,
    callbacks: *const FhEventCallbacksV2,
    user_data: *mut c_void,
) -> i32 {
    guard(-1, || {
        if handle.is_null() {
            return -1;
        }
        // SAFETY: the caller promises a live handle.
        let inner = unsafe { (&*handle).inner_arc() };
        if callbacks.is_null() {
            inner.clear_event_callbacks();
            return 0;
        }

        // SAFETY: the public contract requires a readable fixed header and a
        // readable full table whenever that header declares its full size.
        let Some(callbacks) = (unsafe { events::copy_v2_callback_table(callbacks) }) else {
            return -1;
        };
        let handler = Arc::new(events::FfiEventHandler::new_v2(callbacks, user_data));
        if let Err(error) = inner.set_event_callbacks(Some(handler)) {
            tracing::warn!(%error, "could not start V2 callback worker");
            return 1;
        }
        if let Err(error) = inner.activate_event_push() {
            tracing::warn!(%error, "could not activate V2 event callbacks");
            return 1;
        }
        0
    })
}

/// Invokes one method by id and supplies its result through a synchronous
/// callback borrow. The callback receives the method response on success and
/// a JSON error object on failure. The result memory is owned and released by
/// the library after the callback returns. See docs/ffi.md for method IDs.
///
/// # Safety
///
/// - `handle` must be a live pointer from `fh_init`.
/// - `req` must point to at least `req_len` readable bytes, or be null with
///   `req_len == 0`.
/// - `callback` must be a valid function pointer and must not unwind across
///   the C ABI boundary.
/// - `user_data` must remain valid for the duration of the callback.
/// - callback `data` is borrowed only until the callback returns; it must not
///   be retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_call(
    handle: *mut FhHandle,
    method_id: u32,
    req: *const u8,
    req_len: usize,
    callback: FhResultCallback,
    user_data: *mut c_void,
) -> i32 {
    guard(-1, || {
        // SAFETY: this wrapper forwards pointer requirements to the private
        // dispatcher and keeps its owned result alive through the callback.
        let (status, result) = unsafe { call_inner(handle, method_id, req, req_len) };
        deliver_result(callback, user_data, status, &result);
        status
    })
}

unsafe fn call_inner(
    handle: *mut FhHandle,
    method_id: u32,
    req: *const u8,
    req_len: usize,
) -> (i32, Vec<u8>) {
    guard((-1, Vec::new()), || {
        if handle.is_null() {
            return (-1, Vec::new());
        }

        let payload = if req.is_null() || req_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the public `fh_call` contract requires req to be
            // readable for req_len bytes; copy it before dispatch.
            unsafe { std::slice::from_raw_parts(req, req_len) }.to_vec()
        };

        // Clone shared state so an event callback may destroy the public
        // handle while this request is in flight.
        // SAFETY: the public `fh_call` contract requires a live handle.
        let inner = unsafe { (&*handle).inner_arc() };
        match inner.call(method_id, payload) {
            Ok(response) => (0, response),
            Err(error) => error_result(&error),
        }
    })
}

/// Releases the database row for a durable event and, where the event is an
/// incoming envelope, sends the matching receipt.
///
/// # Safety
///
/// `handle` must be a live pointer from `fh_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_ack_event(handle: *mut FhHandle, event_id: u64) -> i32 {
    guard(-1, || {
        if handle.is_null() {
            return -1;
        }
        // Clone the shared state before the actor call; delivery callbacks may
        // destroy the public handle while the ACK request is in flight.
        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let inner = unsafe { (&*handle).inner_arc() };
        let payload = event_id.to_le_bytes().to_vec();
        match inner.call(METHOD_ACK_EVENT, payload) {
            Ok(_) => 0,
            Err(e) => {
                tracing::warn!(error = %e, event_id, "fh_ack_event failed");
                1
            }
        }
    })
}

fn error_result(error: &Error) -> (i32, Vec<u8>) {
    (1, error.to_json().into_bytes())
}

#[allow(dead_code)]
fn _unused(_: Result<()>, _: api::DispatchMarker) {}

fn deliver_result(callback: FhResultCallback, user_data: *mut c_void, status: i32, result: &[u8]) {
    let data = if result.is_empty() {
        std::ptr::null()
    } else {
        result.as_ptr()
    };
    // SAFETY: the callback is required to be callable by the public function's
    // contract. `data` points into the library-owned result, which remains
    // allocated until after this synchronous callback returns.
    unsafe { callback(user_data, status, data, result.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CapturedResult {
        status: i32,
        bytes: Vec<u8>,
        was_null_for_empty: bool,
    }

    unsafe extern "C" fn capture_result(
        user_data: *mut c_void,
        status: i32,
        data: *const u8,
        data_len: usize,
    ) {
        // SAFETY: the test passes a pointer to a live CapturedResult and the
        // callback contract guarantees `data` is readable for `data_len`.
        let captured = unsafe { &mut *(user_data.cast::<CapturedResult>()) };
        captured.status = status;
        captured.was_null_for_empty = data.is_null() && data_len == 0;
        if !data.is_null() {
            // SAFETY: `deliver_result` keeps the library-owned allocation live
            // until this callback returns.
            captured.bytes = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
        }
    }

    #[test]
    fn callback_receives_borrowed_result() {
        let mut captured = CapturedResult::default();
        let result = br#"{"ok":true}"#.to_vec();

        deliver_result(
            capture_result,
            (&mut captured as *mut CapturedResult).cast(),
            0,
            &result,
        );

        assert_eq!(captured.status, 0);
        assert_eq!(captured.bytes, br#"{"ok":true}"#);
    }

    #[test]
    fn callback_receives_error_result() {
        let mut captured = CapturedResult::default();
        let result = br#"{"code":"denied","message":"no"}"#.to_vec();

        deliver_result(
            capture_result,
            (&mut captured as *mut CapturedResult).cast(),
            1,
            &result,
        );

        assert_eq!(captured.status, 1);
        assert_eq!(captured.bytes, br#"{"code":"denied","message":"no"}"#);
    }

    #[test]
    fn callback_receives_empty_results_as_null() {
        let mut captured = CapturedResult::default();
        let result = Vec::new();

        deliver_result(
            capture_result,
            (&mut captured as *mut CapturedResult).cast(),
            1,
            &result,
        );

        assert_eq!(captured.status, 1);
        assert!(captured.bytes.is_empty());
        assert!(captured.was_null_for_empty);
    }

    #[test]
    fn init_reports_json_errors_through_callback() {
        let config = b"{}";
        let mut handle: *mut FhHandle = std::ptr::null_mut();
        let mut captured = CapturedResult::default();

        // SAFETY: all pointers refer to valid memory for the duration of the
        // call, and the callback only reads its borrowed result synchronously.
        let status = unsafe {
            fh_init(
                config.as_ptr(),
                config.len(),
                &mut handle,
                capture_result,
                (&mut captured as *mut CapturedResult).cast(),
            )
        };

        assert_eq!(status, 1);
        assert!(handle.is_null());
        assert_eq!(captured.status, 1);
        assert!(
            std::str::from_utf8(&captured.bytes)
                .expect("error payload is UTF-8 JSON")
                .contains("db_path")
        );
    }

    #[test]
    fn init_inner_fails_closed_without_a_database_key_and_keeps_handle_null() {
        crate::db::key_store::use_test_keyring();
        let database_path = std::env::temp_dir().join(format!(
            "friendshub-ffi-missing-key-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let encrypted_or_unknown = b"unknown encrypted database bytes";
        std::fs::write(&database_path, encrypted_or_unknown).unwrap();
        let config = serde_json::to_vec(&serde_json::json!({
            "db_path": database_path,
            "api_base": "http://127.0.0.1:1",
            "ws_url": "ws://127.0.0.1:1",
            "discovery": { "enabled": false },
            "log_level": "off",
            "log_format": "text"
        }))
        .unwrap();
        let mut handle: *mut FhHandle = std::ptr::null_mut();

        // SAFETY: the config and output pointers remain valid for the call.
        let (status, error) = unsafe { init_inner(config.as_ptr(), config.len(), &mut handle) };

        assert_eq!(status, 1);
        assert!(handle.is_null());
        assert!(!error.is_empty());
        let error_json: serde_json::Value = serde_json::from_slice(&error).unwrap();
        assert_eq!(error_json["code"], "database");

        let mut ffi_handle: *mut FhHandle = std::ptr::null_mut();
        let mut captured = CapturedResult::default();
        // SAFETY: config, output, and callback context are valid for the
        // synchronous C ABI call; callback bytes are copied before return.
        let ffi_status = unsafe {
            fh_init(
                config.as_ptr(),
                config.len(),
                &mut ffi_handle,
                capture_result,
                (&mut captured as *mut CapturedResult).cast(),
            )
        };
        assert_eq!(ffi_status, 1);
        assert!(ffi_handle.is_null());
        assert_eq!(captured.status, 1);
        assert!(!captured.bytes.is_empty());
        let callback_error: serde_json::Value = serde_json::from_slice(&captured.bytes).unwrap();
        assert_eq!(callback_error["code"], "database");
        assert_eq!(std::fs::read(&database_path).unwrap(), encrypted_or_unknown);
        let _ = std::fs::remove_file(database_path);
    }
}
