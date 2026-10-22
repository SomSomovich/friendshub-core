//! C callback registrations for pushed events.

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::{Condvar, Mutex};

use crate::events::types::{Event, EventHandler};

/// Event JSON is library-owned and borrowed only until the callback returns.
/// `event_id == 0` means that this event is ephemeral; nonzero IDs must be
/// acknowledged with `fh_ack_event`.
#[repr(C)]
pub struct FhEventView {
    pub event_id: u64,
    pub event_json: *const u8,
    pub event_json_len: usize,
}

/// A callback receives a borrowed event view. The callback must not retain the
/// view or its `event_json` pointer after returning, and must not unwind across
/// the C ABI boundary.
pub type FhEventCallback = Option<unsafe extern "C" fn(*mut c_void, *const FhEventView)>;

/// Separate callback slots for every event family the library emits.
///
/// A null slot disables only that event callback. Unknown event kinds go to
/// `on_unhandled`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FhEventCallbacks {
    pub on_ws_connected: FhEventCallback,
    pub on_ws_disconnected: FhEventCallback,
    pub on_ws_stopped: FhEventCallback,
    pub on_envelope_received: FhEventCallback,
    pub on_receipt: FhEventCallback,
    pub on_server_error: FhEventCallback,
    pub on_fatal_error: FhEventCallback,
    pub on_presence_updated: FhEventCallback,
    pub on_bot_message: FhEventCallback,
    pub on_channel_post: FhEventCallback,
    pub on_typing: FhEventCallback,
    pub on_read_receipt: FhEventCallback,
    pub on_conversation_updated: FhEventCallback,
    pub on_history_request: FhEventCallback,
    pub on_nudge: FhEventCallback,
    pub on_nudge_result: FhEventCallback,
    pub on_conversation_expired: FhEventCallback,
    pub on_scheduled_created: FhEventCallback,
    pub on_scheduled_cancelled: FhEventCallback,
    pub on_folders_updated: FhEventCallback,
    pub on_bot_message_edited: FhEventCallback,
    pub on_bot_message_deleted: FhEventCallback,
    pub on_bot_callback_answered: FhEventCallback,
    pub on_poll_updated: FhEventCallback,
    pub on_poll_deleted: FhEventCallback,
    pub on_call_signal: FhEventCallback,
    pub on_identity_changed: FhEventCallback,
    pub on_webrtc_ice_candidate: FhEventCallback,
    pub on_webrtc_signaling_state_changed: FhEventCallback,
    pub on_webrtc_ice_connection_state_changed: FhEventCallback,
    pub on_webrtc_ice_gathering_state_changed: FhEventCallback,
    pub on_webrtc_connection_state_changed: FhEventCallback,
    pub on_webrtc_data_channel_opened: FhEventCallback,
    pub on_webrtc_data_channel_closed: FhEventCallback,
    pub on_webrtc_data_channel_message: FhEventCallback,
    pub on_webrtc_track_received: FhEventCallback,
    pub on_webrtc_closed: FhEventCallback,
    pub on_unhandled: FhEventCallback,
}

#[derive(Default)]
struct CallbackState {
    closing: bool,
    active: usize,
}

/// The C context pointer is only read by this handler's callback worker. The
/// registration API serializes shutdown against in-flight callbacks, and the
/// caller promises the pointed-to context remains valid until unregister or
/// `fh_destroy` returns. EventQueue invokes each handler on one worker thread.
pub(crate) struct FfiEventHandler {
    callbacks: FhEventCallbacks,
    user_data: *mut c_void,
    state: Mutex<CallbackState>,
    idle: Condvar,
}

// SAFETY: EventQueue invokes this handler serially on its dedicated worker.
// The raw context is not dereferenced by Rust; the C callback owns its meaning
// and the registration contract keeps it alive through callback completion.
unsafe impl Send for FfiEventHandler {}
unsafe impl Sync for FfiEventHandler {}

thread_local! {
    static CURRENT_FFI_CALLBACK: Cell<*const FfiEventHandler> = const { Cell::new(std::ptr::null()) };
}

impl FfiEventHandler {
    pub(crate) fn new(callbacks: FhEventCallbacks, user_data: *mut c_void) -> Self {
        Self {
            callbacks,
            user_data,
            state: Mutex::new(CallbackState::default()),
            idle: Condvar::new(),
        }
    }

    pub(crate) fn is_current_callback(&self) -> bool {
        let this = self as *const Self;
        CURRENT_FFI_CALLBACK.with(|current| current.get() == this)
    }

    /// Prevents future callbacks and waits for callbacks already in flight.
    /// Called only after EventQueue has stopped and joined this worker, unless
    /// unregister is called reentrantly by the callback itself.
    pub(crate) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closing = true;
        if self.is_current_callback() {
            return;
        }
        while state.active != 0 {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn invoke(&self, callback: FhEventCallback, event: &Event) {
        let Some(callback) = callback else { return };
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closing {
                return;
            }
            state.active += 1;
        }

        struct ActiveCallback<'a>(&'a FfiEventHandler);
        impl Drop for ActiveCallback<'_> {
            fn drop(&mut self) {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.active -= 1;
                if state.active == 0 {
                    self.0.idle.notify_all();
                }
            }
        }

        let _active = ActiveCallback(self);
        let Ok(json) = serde_json::to_vec(event) else {
            return;
        };
        let view = FhEventView {
            event_id: event.id.unwrap_or(0),
            event_json: json.as_ptr(),
            event_json_len: json.len(),
        };
        let this = self as *const Self;
        CURRENT_FFI_CALLBACK.with(|current| {
            let previous = current.replace(this);
            // SAFETY: `user_data` validity is the registration caller's
            // responsibility; `view` and its JSON buffer remain alive for the
            // complete synchronous callback invocation.
            unsafe { callback(self.user_data, &view) };
            current.set(previous);
        });
    }
}

macro_rules! callback_methods {
    ($($method:ident => $field:ident),+ $(,)?) => {
        impl EventHandler for FfiEventHandler {
            $(
                fn $method(&self, event: &Event) {
                    self.invoke(self.callbacks.$field, event);
                }
            )+
        }
    };
}

callback_methods!(
    on_ws_connected => on_ws_connected,
    on_ws_disconnected => on_ws_disconnected,
    on_ws_stopped => on_ws_stopped,
    on_envelope_received => on_envelope_received,
    on_receipt => on_receipt,
    on_server_error => on_server_error,
    on_fatal_error => on_fatal_error,
    on_presence_updated => on_presence_updated,
    on_bot_message => on_bot_message,
    on_channel_post => on_channel_post,
    on_typing => on_typing,
    on_read_receipt => on_read_receipt,
    on_conversation_updated => on_conversation_updated,
    on_history_request => on_history_request,
    on_nudge => on_nudge,
    on_nudge_result => on_nudge_result,
    on_conversation_expired => on_conversation_expired,
    on_scheduled_created => on_scheduled_created,
    on_scheduled_cancelled => on_scheduled_cancelled,
    on_folders_updated => on_folders_updated,
    on_bot_message_edited => on_bot_message_edited,
    on_bot_message_deleted => on_bot_message_deleted,
    on_bot_callback_answered => on_bot_callback_answered,
    on_poll_updated => on_poll_updated,
    on_poll_deleted => on_poll_deleted,
    on_call_signal => on_call_signal,
    on_identity_changed => on_identity_changed,
    on_webrtc_ice_candidate => on_webrtc_ice_candidate,
    on_webrtc_signaling_state_changed => on_webrtc_signaling_state_changed,
    on_webrtc_ice_connection_state_changed => on_webrtc_ice_connection_state_changed,
    on_webrtc_ice_gathering_state_changed => on_webrtc_ice_gathering_state_changed,
    on_webrtc_connection_state_changed => on_webrtc_connection_state_changed,
    on_webrtc_data_channel_opened => on_webrtc_data_channel_opened,
    on_webrtc_data_channel_closed => on_webrtc_data_channel_closed,
    on_webrtc_data_channel_message => on_webrtc_data_channel_message,
    on_webrtc_track_received => on_webrtc_track_received,
    on_webrtc_closed => on_webrtc_closed,
    on_unhandled => on_unhandled,
);

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{FfiEventHandler, FhEventCallbacks, FhEventView};
    use crate::events::types::{Event, EventHandler};

    unsafe extern "C" fn on_typing(user_data: *mut c_void, event: *const FhEventView) {
        // SAFETY: the test passes a live Sender pointer and EventQueue calls
        // synchronously with a stack view whose bytes are valid for this call.
        let tx = unsafe { &*(user_data as *const mpsc::Sender<(u64, String)>) };
        let view = unsafe { &*event };
        let json = unsafe { std::slice::from_raw_parts(view.event_json, view.event_json_len) };
        let _ = tx.send((view.event_id, String::from_utf8_lossy(json).into_owned()));
    }

    #[test]
    fn c_callback_receives_borrowed_library_json_and_event_id() {
        let (tx, rx): (mpsc::Sender<(u64, String)>, _) = mpsc::channel();
        let mut callbacks = FhEventCallbacks::default();
        callbacks.on_typing = Some(on_typing);
        let handler = FfiEventHandler::new(callbacks, &tx as *const _ as *mut c_void);
        handler.on_typing(&Event {
            id: Some(42),
            kind: "typing".into(),
            payload: serde_json::json!({"conversation_id":"c1"}),
        });
        handler.close();
        let (id, json) = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(id, 42);
        assert!(json.contains("conversation_id"));
        assert!(json.contains("\"kind\":\"typing\""));
    }
}
