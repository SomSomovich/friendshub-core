//! C ABI surface. Each raw-pointer boundary has an explicit safety contract.
//!
//! Every function that touches raw pointers is `unsafe extern "C"` and
//! carries a `# Safety` section spelling out what the caller must guarantee.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::Arc;
use std::time::Duration;

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
pub mod types;

pub use events::{FhEventCallback, FhEventCallbacks, FhEventView};
pub use types::FhBuffer;

use handle::FhHandle;
use panic::guard;

pub const ABI_VERSION: u32 = 1;

const ABI_STRING: &[u8] = b"0.1.2\0";

const METHOD_ACK_EVENT: u32 = 0x0000_0004;

#[unsafe(no_mangle)]
pub extern "C" fn fh_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn fh_abi_string() -> *const c_char {
    ABI_STRING.as_ptr() as *const c_char
}

/// Releases a buffer returned by any other `fh_*` call.
///
/// # Safety
///
/// `buf` must be either null or a pointer to an `FhBuffer` that was
/// returned by this library and has not been released yet. After the call
/// the buffer is reset to empty, so a second call on the same value is
/// safe and does nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_buffer_free(buf: *mut FhBuffer) {
    guard((), || {
        if buf.is_null() {
            return;
        }
        // SAFETY: the caller promises `buf` is a valid pointer to a buffer
        // this library produced.
        unsafe {
            (*buf).release();
        }
    });
}

/// Initialises a handle for one account.
///
/// # Safety
///
/// - `config_json` must point to at least `config_len` readable bytes, or
///   be null with `config_len == 0`.
/// - `out_handle` and `out` must be valid, writable pointers.
/// - `out_handle` is written to on success; on failure it stays null.
/// - `out` is always written to. Callers must free it with
///   `fh_buffer_free` when the return code is zero or one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_init(
    config_json: *const u8,
    config_len: usize,
    out_handle: *mut *mut FhHandle,
    out: *mut FhBuffer,
) -> i32 {
    guard(-1, || {
        if out_handle.is_null() || out.is_null() {
            return -1;
        }
        // SAFETY: both pointers were checked above.
        unsafe {
            *out_handle = std::ptr::null_mut();
            *out = FhBuffer::EMPTY;
        }

        if config_json.is_null() || config_len == 0 {
            return write_error(out, &Error::Config("config is empty".into()));
        }

        // SAFETY: the caller promises `config_json` is readable for
        // `config_len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(config_json, config_len) };

        let cfg = match Config::from_json(bytes) {
            Ok(c) => c,
            Err(e) => return write_error(out, &e),
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
            Ok(a) => a,
            Err(e) => return write_error(out, &e),
        };

        let handle = Box::new(FhHandle::new(actor, events));
        // SAFETY: `out_handle` was checked non-null.
        unsafe {
            *out_handle = Box::into_raw(handle);
        }
        0
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
/// Passing a null `callbacks` pointer clears the current handler and returns
/// future events to `fh_poll_event`. Each non-null slot is called on the
/// library's dedicated callback worker thread. The event view and its JSON
/// bytes are borrowed only for the duration of the callback; the library
/// allocates and releases that memory.
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

/// Invokes one method by id. See docs/ffi.md for the method table.
///
/// # Safety
///
/// - `handle` must be a live pointer from `fh_init`.
/// - `req` must point to at least `req_len` readable bytes, or be null
///   with `req_len == 0`.
/// - `out` must be a valid, writable pointer; it is always written to and
///   must be freed with `fh_buffer_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_call(
    handle: *mut FhHandle,
    method_id: u32,
    req: *const u8,
    req_len: usize,
    out: *mut FhBuffer,
) -> i32 {
    guard(-1, || {
        if handle.is_null() || out.is_null() {
            return -1;
        }
        // SAFETY: `out` was checked non-null.
        unsafe {
            *out = FhBuffer::EMPTY;
        }

        let payload = if req.is_null() || req_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the caller promises `req` is readable for `req_len`
            // bytes.
            unsafe { std::slice::from_raw_parts(req, req_len) }.to_vec()
        };

        // Clone the shared state so callbacks may destroy the opaque handle
        // while this actor request is in flight.
        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let inner = unsafe { (&*handle).inner_arc() };
        match inner.call(method_id, payload) {
            Ok(bytes) => {
                // SAFETY: `out` was checked non-null.
                unsafe {
                    *out = FhBuffer::from_vec(bytes);
                }
                0
            }
            Err(e) => write_error(out, &e),
        }
    })
}

/// Blocks up to `timeout_ms` for the next event.
///
/// On timeout returns 0 with an empty buffer. On any other outcome the
/// buffer carries a JSON event.
///
/// # Safety
///
/// - `handle` must be a live pointer from `fh_init`.
/// - `out` must be a valid, writable pointer; it is always written to and
///   must be freed with `fh_buffer_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_poll_event(
    handle: *mut FhHandle,
    timeout_ms: u32,
    out: *mut FhBuffer,
) -> i32 {
    guard(-1, || {
        if handle.is_null() || out.is_null() {
            return -1;
        }
        // SAFETY: `out` was checked non-null.
        unsafe {
            *out = FhBuffer::EMPTY;
        }

        // Clone the shared state before the blocking pull wait. A callback
        // may destroy the public handle while this call is waiting.
        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let inner = unsafe { (&*handle).inner_arc() };
        match inner.poll_event(Duration::from_millis(timeout_ms as u64)) {
            Ok(event) => {
                let bytes = match event {
                    Some(event) => match serde_json::to_vec(&event) {
                        Ok(bytes) => bytes,
                        Err(error) => return write_error(out, &Error::from(error)),
                    },
                    None => Vec::new(),
                };
                // SAFETY: `out` was checked non-null.
                unsafe {
                    *out = FhBuffer::from_vec(bytes);
                }
                0
            }
            Err(e) => write_error(out, &e),
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

fn write_error(out: *mut FhBuffer, e: &Error) -> i32 {
    let bytes = e.to_json().into_bytes();
    // SAFETY: every caller passes a pointer it has already checked non-null.
    unsafe {
        *out = FhBuffer::from_vec(bytes);
    }
    1
}

#[allow(dead_code)]
fn _unused(_: Result<()>, _: api::DispatchMarker) {}
