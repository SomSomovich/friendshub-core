use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::events::types::Event;

pub struct EventQueue {
    tx: mpsc::UnboundedSender<Event>,
    rx: Mutex<mpsc::UnboundedReceiver<Event>>,
}

impl EventQueue {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx: Mutex::new(rx) }
    }

    pub fn push(&self, ev: Event) {
        let _ = self.tx.send(ev);
    }

    /// Waits up to `timeout` for an event. Returns `None` on timeout.
    pub async fn poll(&self, timeout: Duration) -> Option<Event> {
        let mut rx = self.rx.lock().await;
        if timeout.is_zero() {
            return rx.try_recv().ok();
        }
        tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}
