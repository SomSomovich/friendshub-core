use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::error::Result;
use crate::events::{Event, EventQueue};
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
}

impl FhHandle {
    pub fn new(actor: Actor, events: Arc<EventQueue>) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                actor,
                events,
                ffi_callbacks: Mutex::new(None),
            }),
        }
    }

    pub fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.actor.call(method, payload)
    }

    pub fn poll_event(&self, timeout: Duration) -> Result<Option<Event>> {
        // Hold the shared state through the direct queue wait so a callback
        // that destroys the public C handle cannot tear down this operation.
        let inner = self.inner.clone();
        let bytes = inner.actor.call(
            crate::client::method_ids::POLL_EVENT,
            0_u32.to_le_bytes().to_vec(),
        )?;
        if !bytes.is_empty() {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(crate::error::Error::from);
        }
        Ok(inner.events.poll(timeout))
    }

    pub(crate) fn set_event_callbacks(
        &self,
        handler: Option<Arc<FfiEventHandler>>,
    ) -> std::io::Result<()> {
        self.clear_event_callbacks();
        let Some(handler) = handler else {
            return Ok(());
        };
        self.inner.events.set_handler(handler.clone())?;
        *self
            .inner
            .ffi_callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handler);
        Ok(())
    }

    pub(crate) fn activate_event_push(&self) -> Result<()> {
        // Keep the actor and event queue alive if a callback reentrantly
        // destroys the opaque C handle while startup backlog is dispatched.
        let inner = self.inner.clone();
        let result = inner
            .actor
            .call(crate::client::method_ids::ACTIVATE_EVENT_PUSH, Vec::new())
            .map(|_| ());
        if result.is_err() {
            inner.clear_event_callbacks();
        }
        result
    }

    pub(crate) fn clear_event_callbacks(&self) {
        self.inner.clear_event_callbacks();
    }
}

impl HandleInner {
    fn clear_event_callbacks(&self) {
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
