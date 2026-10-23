use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Result;
use crate::events::EventQueue;
use crate::runtime::Actor;

use super::events::FfiEventHandler;

/// Opaque to C. One handle drives one account: its own runtime, its own
/// database, its own websocket.
pub struct FhHandle {
    inner: Arc<HandleInner>,
}

pub(crate) struct HandleInner {
    pub actor: Actor,
    pub events: Arc<EventQueue>,
    ffi_callbacks: Mutex<Option<Arc<FfiEventHandler>>>,
    destroy_started: AtomicBool,
}

impl FhHandle {
    pub fn new(actor: Actor, events: Arc<EventQueue>) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                actor,
                events,
                ffi_callbacks: Mutex::new(None),
                destroy_started: AtomicBool::new(false),
            }),
        }
    }

    pub fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.call(method, payload)
    }

    /// Clones the owned state out of an opaque FFI handle before an actor
    /// call. A callback may destroy the public handle reentrantly while that
    /// operation is in progress.
    pub(crate) fn inner_arc(&self) -> Arc<HandleInner> {
        self.inner.clone()
    }
}

impl HandleInner {
    pub(crate) fn begin_destroy(&self) -> bool {
        self.destroy_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.actor.call(method, payload)
    }

    pub(crate) fn set_event_callbacks(
        &self,
        handler: Option<Arc<FfiEventHandler>>,
    ) -> std::io::Result<()> {
        self.clear_event_callbacks();
        let Some(handler) = handler else {
            return Ok(());
        };
        self.events.set_handler(handler.clone())?;
        *self
            .ffi_callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handler);
        Ok(())
    }

    pub(crate) fn activate_event_push(&self) -> Result<()> {
        let result = self
            .actor
            .call(crate::client::method_ids::ACTIVATE_EVENT_PUSH, Vec::new())
            .map(|_| ());
        if result.is_err() {
            self.clear_event_callbacks();
        }
        result
    }

    pub(crate) fn clear_event_callbacks(&self) {
        let old = self
            .ffi_callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handler) = old {
            let called_from_callback = handler.is_current_callback();
            self.events.clear_handler_and_wait();
            // If called reentrantly, the worker cannot join itself. Closing
            // suppresses its queued callbacks after this callback returns.
            handler.close();
            if called_from_callback {
                // `clear_handler_and_wait` detached the current worker; the
                // handler remains alive on that thread until its callback
                // unwinds, and its context is now disabled.
            }
        } else {
            self.events.clear_handler_and_wait();
        }
    }
}
