use std::sync::Arc;

use crate::error::Result;
use crate::runtime::Actor;

/// Opaque to C. One handle drives one account: its own runtime, its own
/// database, its own websocket.
pub struct FhHandle {
    inner: Arc<HandleInner>,
}

pub(crate) struct HandleInner {
    pub actor: Actor,
}

impl FhHandle {
    pub fn new(actor: Actor) -> Self {
        Self { inner: Arc::new(HandleInner { actor }) }
    }

    pub fn call(&self, method: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.actor.call(method, payload)
    }
}
