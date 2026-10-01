//! C ABI surface. Kept deliberately small: eight functions total, so a
//! consumer written against one language trivially translates to another.

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_buffer_free(buf: *mut FhBuffer) {
    guard((), || {
        if buf.is_null() {
            return;
        }
        unsafe { (*buf).release(); }
    });
}

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
        unsafe {
            *out_handle = std::ptr::null_mut();
            *out = FhBuffer::EMPTY;
        }

        if config_json.is_null() || config_len == 0 {
            return write_error(out, &Error::Config("config is empty".into()));
        }

        let bytes = unsafe { std::slice::from_raw_parts(config_json, config_len) };

        let cfg = match Config::from_json(bytes) {
            Ok(c) => c,
            Err(e) => return write_error(out, &e),
        };

        crate::logging::init_once(&cfg.log_level);
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
        unsafe { *out_handle = Box::into_raw(handle); }
        0
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_destroy(handle: *mut FhHandle) {
    guard((), || {
        if handle.is_null() {
            return;
        }
        unsafe { drop(Box::from_raw(handle)); }
    });
}

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
        unsafe { *out = FhBuffer::EMPTY; }

        let payload = if req.is_null() || req_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(req, req_len) }.to_vec()
        };

        let h = unsafe { &*handle };
        match h.call(method_id, payload) {
            Ok(bytes) => {
                unsafe { *out = FhBuffer::from_vec(bytes); }
                0
            }
            Err(e) => write_error(out, &e),
        }
    })
}

/// Blocks up to timeout_ms for the next event. On timeout returns 0 with an
/// empty buffer. On any other outcome the buffer carries a JSON event.
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
        unsafe { *out = FhBuffer::EMPTY; }

        let h = unsafe { &*handle };
        let payload = timeout_ms.to_le_bytes().to_vec();
        match h.call(METHOD_POLL_EVENT, payload) {
            Ok(bytes) => {
                unsafe { *out = FhBuffer::from_vec(bytes); }
                0
            }
            Err(e) => write_error(out, &e),
        }
    })
}

/// Releases the database row for a durable event and, where the event is an
/// incoming envelope, sends the matching receipt.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fh_ack_event(handle: *mut FhHandle, event_id: u64) -> i32 {
    guard(-1, || {
        if handle.is_null() {
            return -1;
        }

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
    unsafe { *out = FhBuffer::from_vec(bytes); }
    1
}

#[allow(dead_code)]
fn _unused(_: Result<()>, _: api::DispatchMarker) {}
