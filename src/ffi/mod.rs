//! C ABI surface. Kept deliberately small: eight functions total, so a
//! consumer written against one language trivially translates to another.
//!
//! Every function that touches raw pointers is `unsafe extern "C"` and
//! carries a `# Safety` section spelling out what the caller must guarantee.

use std::os::raw::c_char;

use crate::api;
use crate::config::Config;
use crate::db;
use crate::error::{Error, Result};
use crate::runtime::{Actor, ActorState};
use crate::transport::HttpClient;

pub mod handle;
pub mod panic;
pub mod types;

pub use types::FhBuffer;

use handle::FhHandle;
use panic::guard;

pub const ABI_VERSION: u32 = 1;

const ABI_STRING: &[u8] = b"0.1.0\\0";

const METHOD_POLL_EVENT: u32 = 0x0000_0003;
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
        unsafe { (*buf).release(); }
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
        let db_path = cfg.db_path.clone();
        let http = match HttpClient::new(&cfg) {
            Ok(h) => h,
            Err(e) => return write_error(out, &e),
        };

        let actor = match Actor::spawn(move || {
            Box::pin(async move {
                let db = db::pool::open(&db_path).await?;
                db::migrations::MIGRATOR
                    .run(&db)
                    .await
                    .map_err(|e| Error::Database(format!("migrations failed: {e}")))?;
                Ok(ActorState::new(cfg, db, http))
            })
        }) {
            Ok(a) => a,
            Err(e) => return write_error(out, &e),
        };

        let handle = Box::new(FhHandle::new(actor));
        // SAFETY: `out_handle` was checked non-null.
        unsafe { *out_handle = Box::into_raw(handle); }
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
        // SAFETY: the caller promises `handle` came from `fh_init` and has
        // not been destroyed.
        unsafe { drop(Box::from_raw(handle)); }
    });
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
        unsafe { *out = FhBuffer::EMPTY; }

        let payload = if req.is_null() || req_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the caller promises `req` is readable for `req_len`
            // bytes.
            unsafe { std::slice::from_raw_parts(req, req_len) }.to_vec()
        };

        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let h = unsafe { &*handle };
        match h.call(method_id, payload) {
            Ok(bytes) => {
                // SAFETY: `out` was checked non-null.
                unsafe { *out = FhBuffer::from_vec(bytes); }
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
        unsafe { *out = FhBuffer::EMPTY; }

        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let h = unsafe { &*handle };
        let payload = timeout_ms.to_le_bytes().to_vec();
        match h.call(METHOD_POLL_EVENT, payload) {
            Ok(bytes) => {
                // SAFETY: `out` was checked non-null.
                unsafe { *out = FhBuffer::from_vec(bytes); }
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
        // SAFETY: `handle` is a live pointer, per the caller's contract.
        let h = unsafe { &*handle };
        let payload = event_id.to_le_bytes().to_vec();
        match h.call(METHOD_ACK_EVENT, payload) {
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
    unsafe { *out = FhBuffer::from_vec(bytes); }
    1
}

#[allow(dead_code)]
fn _unused(_: Result<()>, _: api::DispatchMarker) {}
