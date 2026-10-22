use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TryRecvError};

use crate::events::types::{Event, EventHandler};

struct CallbackWorker {
    tx: std_mpsc::Sender<Event>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CallbackWorker {
    fn spawn(handler: Arc<dyn EventHandler>) -> std::io::Result<Self> {
        let (tx, rx) = std_mpsc::channel::<Event>();
        let thread = thread::Builder::new()
            .name("friendshub-callback".into())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    // A consumer callback must not terminate the dispatcher
                    // thread or unwind into the event producer.
                    let _ = catch_unwind(AssertUnwindSafe(|| {
                        dispatch_event(handler.as_ref(), &event);
                    }));
                }
            })?;
        Ok(Self {
            tx,
            thread: Some(thread),
        })
    }

    fn stop_and_wait(mut self) {
        drop(self.tx);
        if let Some(join_handle) = self.thread.take() {
            // A callback may destroy its own handle. It cannot join itself;
            // dropping the JoinHandle detaches the worker, which exits after
            // the current callback returns and its channel has drained.
            if join_handle.thread().id() != thread::current().id() {
                let _ = join_handle.join();
            }
        }
    }
}

pub struct EventQueue {
    tx: Sender<Event>,
    rx: Receiver<Event>,
    callback: Mutex<CallbackState>,
}

#[derive(Default)]
struct CallbackState {
    worker: Option<CallbackWorker>,
    active: bool,
}

impl EventQueue {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self {
            tx,
            rx,
            callback: Mutex::new(CallbackState::default()),
        }
    }

    pub fn push(&self, ev: Event) {
        let mut callback = self
            .callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if callback.active {
            let Some(worker) = callback.worker.as_ref() else {
                callback.active = false;
                let _ = self.tx.send(ev);
                return;
            };
            match worker.tx.send(ev) {
                Ok(()) => return,
                Err(error) => {
                    // If the callback thread exited unexpectedly, discard the
                    // stale registration and preserve the event in PULL mode.
                    callback.worker.take();
                    callback.active = false;
                    let _ = self.tx.send(error.0);
                    return;
                }
            }
        }

        let _ = self.tx.send(ev);
    }

    /// Registers a handler whose methods run on one dedicated callback
    /// thread. Events already queued for [`Self::poll`] stay there until
    /// [`Self::drain_backlog_to_handler`] is called. That activation step
    /// transfers the existing pull backlog before routing future events to
    /// the handler, preserving FIFO order.
    ///
    /// Replacing a handler routes future events to the new handler. Events
    /// already queued for the old handler are drained by its worker and may
    /// complete after this returns.
    pub fn set_handler(&self, handler: Arc<dyn EventHandler>) -> std::io::Result<()> {
        let worker = CallbackWorker::spawn(handler)?;
        let previous = {
            let mut callback = self
                .callback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            callback.active = false;
            callback.worker.replace(worker)
        };
        drop(previous);
        Ok(())
    }

    /// Removes the callback handler. Events pushed after this call return to
    /// the PULL queue. Events already queued for the handler continue on its
    /// worker and may complete after this returns.
    pub fn clear_handler(&self) {
        let previous = {
            let mut callback = self
                .callback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            callback.active = false;
            callback.worker.take()
        };
        drop(previous);
    }

    /// Removes the callback handler and waits for its worker to finish queued
    /// callbacks. If called on that worker itself, it detaches instead of
    /// joining the current thread.
    pub fn clear_handler_and_wait(&self) {
        let previous = {
            let mut callback = self
                .callback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            callback.active = false;
            callback.worker.take()
        };
        if let Some(worker) = previous {
            worker.stop_and_wait();
        }
    }

    /// Moves events accumulated in pull mode to the currently installed
    /// callback worker.
    /// The actor calls this after installing a handler, so events delivered
    /// before registration are not stranded in the pull queue.
    pub fn drain_backlog_to_handler(&self) -> std::io::Result<()> {
        let mut callback = self
            .callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if callback.worker.is_none() {
            return Ok(());
        }

        // Keep the callback state locked while draining and sending. Producers
        // queue into PULL until this complete backlog is enqueued, so a new
        // event cannot overtake an older queued event.
        let worker_tx = callback
            .worker
            .as_ref()
            .expect("worker was checked above")
            .tx
            .clone();
        loop {
            let event = match self.rx.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };
            match worker_tx.send(event) {
                Ok(()) => {}
                Err(error) => {
                    let failed_event = error.0;
                    callback.worker.take();
                    callback.active = false;
                    let _ = self.tx.send(failed_event);
                    while let Ok(event) = self.rx.try_recv() {
                        let _ = self.tx.send(event);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "event callback worker stopped while draining the pull queue",
                    ));
                }
            }
        }
        callback.active = true;
        Ok(())
    }

    pub fn has_handler(&self) -> bool {
        self.callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    /// Waits up to `timeout` for an event. Returns `None` on timeout.
    pub fn poll(&self, timeout: Duration) -> Option<Event> {
        if timeout.is_zero() {
            return self.rx.try_recv().ok();
        }
        self.rx.recv_timeout(timeout).ok()
    }
}

fn dispatch_event(handler: &dyn EventHandler, event: &Event) {
    match event.kind.as_str() {
        "ws_connected" => handler.on_ws_connected(event),
        "ws_disconnected" => handler.on_ws_disconnected(event),
        "ws_stopped" => handler.on_ws_stopped(event),
        "envelope_received" => handler.on_envelope_received(event),
        "receipt" => handler.on_receipt(event),
        "server_error" => {
            handler.on_server_error(event);
            let fatal = event
                .payload
                .get("fatal")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let code = event
                .payload
                .get("code")
                .and_then(serde_json::Value::as_str);
            if fatal && code != Some("flood") {
                handler.on_fatal_error(event);
            }
        }
        "presence_updated" => handler.on_presence_updated(event),
        "bot_message" => handler.on_bot_message(event),
        "channel_post" => handler.on_channel_post(event),
        "typing" => handler.on_typing(event),
        "read_receipt" => handler.on_read_receipt(event),
        "conversation_updated" => handler.on_conversation_updated(event),
        "history_request" => handler.on_history_request(event),
        "nudge" => handler.on_nudge(event),
        "nudge_result" => handler.on_nudge_result(event),
        "conversation_expired" => handler.on_conversation_expired(event),
        "scheduled_created" => handler.on_scheduled_created(event),
        "scheduled_cancelled" => handler.on_scheduled_cancelled(event),
        "folders_updated" => handler.on_folders_updated(event),
        "bot_message_edited" => handler.on_bot_message_edited(event),
        "bot_message_deleted" => handler.on_bot_message_deleted(event),
        "bot_callback_answered" => handler.on_bot_callback_answered(event),
        "poll_updated" => handler.on_poll_updated(event),
        "poll_deleted" => handler.on_poll_deleted(event),
        "call_signal" => handler.on_call_signal(event),
        "identity_changed" => handler.on_identity_changed(event),
        "webrtc_event" => dispatch_webrtc_event(handler, event),
        _ => handler.on_unhandled(event),
    }
}

fn dispatch_webrtc_event(handler: &dyn EventHandler, event: &Event) {
    match event
        .payload
        .get("event")
        .and_then(serde_json::Value::as_str)
    {
        Some("ice_candidate") => handler.on_webrtc_ice_candidate(event),
        Some("signaling_state_changed") => handler.on_webrtc_signaling_state_changed(event),
        Some("ice_connection_state_changed") => {
            handler.on_webrtc_ice_connection_state_changed(event)
        }
        Some("ice_gathering_state_changed") => handler.on_webrtc_ice_gathering_state_changed(event),
        Some("connection_state_changed") => handler.on_webrtc_connection_state_changed(event),
        Some("data_channel_opened") => handler.on_webrtc_data_channel_opened(event),
        Some("data_channel_closed") => handler.on_webrtc_data_channel_closed(event),
        Some("data_channel_message") => handler.on_webrtc_data_channel_message(event),
        Some("track_received") => handler.on_webrtc_track_received(event),
        Some("closed") => handler.on_webrtc_closed(event),
        _ => handler.on_unhandled(event),
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread::ThreadId;
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::EventQueue;
    use crate::events::types::{Event, EventHandler};

    struct CallbackRecord {
        method: &'static str,
        kind: String,
        id: Option<u64>,
        thread_id: ThreadId,
    }

    struct RecordingHandler {
        tx: Sender<CallbackRecord>,
    }

    macro_rules! record_methods {
        ($($method:ident),+ $(,)?) => {
            impl EventHandler for RecordingHandler {
                $(
                    fn $method(&self, event: &Event) {
                        let _ = self.tx.send(CallbackRecord {
                            method: stringify!($method),
                            kind: event.kind.clone(),
                            id: event.id,
                            thread_id: std::thread::current().id(),
                        });
                    }
                )+
            }
        };
    }

    record_methods!(
        on_ws_connected,
        on_ws_disconnected,
        on_ws_stopped,
        on_envelope_received,
        on_receipt,
        on_server_error,
        on_fatal_error,
        on_presence_updated,
        on_bot_message,
        on_channel_post,
        on_typing,
        on_read_receipt,
        on_conversation_updated,
        on_history_request,
        on_nudge,
        on_nudge_result,
        on_conversation_expired,
        on_scheduled_created,
        on_scheduled_cancelled,
        on_folders_updated,
        on_bot_message_edited,
        on_bot_message_deleted,
        on_bot_callback_answered,
        on_poll_updated,
        on_poll_deleted,
        on_call_signal,
        on_identity_changed,
        on_webrtc_ice_candidate,
        on_webrtc_signaling_state_changed,
        on_webrtc_ice_connection_state_changed,
        on_webrtc_ice_gathering_state_changed,
        on_webrtc_connection_state_changed,
        on_webrtc_data_channel_opened,
        on_webrtc_data_channel_closed,
        on_webrtc_data_channel_message,
        on_webrtc_track_received,
        on_webrtc_closed,
        on_unhandled,
    );

    fn event(kind: &str, id: Option<u64>, payload: Value) -> Event {
        Event {
            id,
            kind: kind.to_owned(),
            payload,
        }
    }

    fn handler_channel() -> (std::sync::Arc<RecordingHandler>, Receiver<CallbackRecord>) {
        let (tx, rx) = mpsc::channel();
        (std::sync::Arc::new(RecordingHandler { tx }), rx)
    }

    #[test]
    fn each_event_kind_uses_its_own_callback_on_the_callback_thread() {
        let queue = EventQueue::new();
        let (handler, rx) = handler_channel();
        let caller_thread = std::thread::current().id();
        let cases: Vec<(Event, &'static str)> = vec![
            (event("ws_connected", None, json!({})), "on_ws_connected"),
            (
                event("ws_disconnected", None, json!({})),
                "on_ws_disconnected",
            ),
            (event("ws_stopped", None, json!({})), "on_ws_stopped"),
            (
                event("envelope_received", Some(71), json!({"ciphertext":"aa"})),
                "on_envelope_received",
            ),
            (event("receipt", None, json!({})), "on_receipt"),
            (event("server_error", None, json!({})), "on_server_error"),
            (
                event("presence_updated", None, json!({})),
                "on_presence_updated",
            ),
            (event("bot_message", None, json!({})), "on_bot_message"),
            (event("channel_post", None, json!({})), "on_channel_post"),
            (event("typing", None, json!({})), "on_typing"),
            (event("read_receipt", None, json!({})), "on_read_receipt"),
            (
                event("conversation_updated", None, json!({})),
                "on_conversation_updated",
            ),
            (
                event("history_request", None, json!({})),
                "on_history_request",
            ),
            (event("nudge", None, json!({})), "on_nudge"),
            (event("nudge_result", None, json!({})), "on_nudge_result"),
            (
                event("conversation_expired", None, json!({})),
                "on_conversation_expired",
            ),
            (
                event("scheduled_created", None, json!({})),
                "on_scheduled_created",
            ),
            (
                event("scheduled_cancelled", None, json!({})),
                "on_scheduled_cancelled",
            ),
            (
                event("folders_updated", None, json!({})),
                "on_folders_updated",
            ),
            (
                event("bot_message_edited", None, json!({})),
                "on_bot_message_edited",
            ),
            (
                event("bot_message_deleted", None, json!({})),
                "on_bot_message_deleted",
            ),
            (
                event("bot_callback_answered", None, json!({})),
                "on_bot_callback_answered",
            ),
            (event("poll_updated", None, json!({})), "on_poll_updated"),
            (event("poll_deleted", None, json!({})), "on_poll_deleted"),
            (event("call_signal", None, json!({})), "on_call_signal"),
            (
                event("identity_changed", None, json!({})),
                "on_identity_changed",
            ),
            (
                event("webrtc_event", None, json!({"event":"ice_candidate"})),
                "on_webrtc_ice_candidate",
            ),
            (
                event(
                    "webrtc_event",
                    None,
                    json!({"event":"signaling_state_changed"}),
                ),
                "on_webrtc_signaling_state_changed",
            ),
            (
                event(
                    "webrtc_event",
                    None,
                    json!({"event":"ice_connection_state_changed"}),
                ),
                "on_webrtc_ice_connection_state_changed",
            ),
            (
                event(
                    "webrtc_event",
                    None,
                    json!({"event":"ice_gathering_state_changed"}),
                ),
                "on_webrtc_ice_gathering_state_changed",
            ),
            (
                event(
                    "webrtc_event",
                    None,
                    json!({"event":"connection_state_changed"}),
                ),
                "on_webrtc_connection_state_changed",
            ),
            (
                event("webrtc_event", None, json!({"event":"data_channel_opened"})),
                "on_webrtc_data_channel_opened",
            ),
            (
                event("webrtc_event", None, json!({"event":"data_channel_closed"})),
                "on_webrtc_data_channel_closed",
            ),
            (
                event(
                    "webrtc_event",
                    None,
                    json!({"event":"data_channel_message"}),
                ),
                "on_webrtc_data_channel_message",
            ),
            (
                event("webrtc_event", None, json!({"event":"track_received"})),
                "on_webrtc_track_received",
            ),
            (
                event("webrtc_event", None, json!({"event":"closed"})),
                "on_webrtc_closed",
            ),
            (
                event("webrtc_event", None, json!({"event":"future_webrtc_event"})),
                "on_unhandled",
            ),
            (event("future_event", None, json!({})), "on_unhandled"),
        ];

        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");
        for (event, _) in &cases {
            queue.push(event.clone());
        }

        let mut callback_thread = None;
        for (expected_event, expected_method) in cases {
            let received = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("event must reach a callback");
            assert_eq!(received.method, expected_method);
            assert_eq!(received.kind, expected_event.kind);
            assert_eq!(received.id, expected_event.id);
            assert_ne!(received.thread_id, caller_thread);
            match callback_thread {
                Some(id) => assert_eq!(received.thread_id, id, "callbacks must share one worker"),
                None => callback_thread = Some(received.thread_id),
            }
        }
        assert!(
            rx.try_recv().is_err(),
            "an event invoked more than one method"
        );
    }

    #[test]
    fn fatal_server_errors_also_dispatch_fatal_except_for_flood() {
        let queue = EventQueue::new();
        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");

        queue.push(event(
            "server_error",
            None,
            json!({"fatal":true,"code":"session_revoked"}),
        ));
        let first = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server error callback must run");
        let second = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("fatal callback must run for fatal non-flood errors");
        assert_eq!(first.method, "on_server_error");
        assert_eq!(second.method, "on_fatal_error");

        queue.push(event(
            "server_error",
            None,
            json!({"fatal":true,"code":"flood"}),
        ));
        let flood = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("flood must still reach the general error callback");
        assert_eq!(flood.method, "on_server_error");
        assert!(
            rx.try_recv().is_err(),
            "flood must not reach fatal callback"
        );
    }

    #[test]
    fn poll_is_the_fallback_without_a_handler_and_after_clear() {
        let queue = EventQueue::new();
        let first = event("receipt", None, json!({"sequence":1}));
        queue.push(first.clone());
        let pulled = queue
            .poll(Duration::ZERO)
            .expect("no-handler event must be polled");
        assert_eq!(pulled.kind, first.kind);
        assert_eq!(pulled.payload, first.payload);

        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");
        queue.push(event("presence_updated", None, json!({"online":true})));
        let callback = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("registered handler must receive the event");
        assert_eq!(callback.method, "on_presence_updated");

        queue.clear_handler();
        let durable = event("envelope_received", Some(812), json!({"ciphertext":"beef"}));
        queue.push(durable.clone());
        let pulled = queue
            .poll(Duration::ZERO)
            .expect("cleared handler restores PULL");
        assert_eq!(pulled.id, durable.id, "durable event ID must be preserved");
        assert_eq!(pulled.kind, durable.kind);
        assert_eq!(pulled.payload, durable.payload);
    }

    #[test]
    fn activation_pushes_backlog_before_events_arriving_during_registration() {
        let queue = EventQueue::new();
        queue.push(event("typing", None, json!({"sequence":1})));

        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue.push(event("receipt", Some(813), json!({"sequence":2})));
        queue
            .drain_backlog_to_handler()
            .expect("queued events must move to PUSH");

        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(first.method, "on_typing");
        assert_eq!(second.method, "on_receipt");
        assert_eq!(second.id, Some(813));
        assert!(queue.poll(Duration::ZERO).is_none());
        queue.clear_handler_and_wait();
    }

    #[test]
    fn long_pull_wait_does_not_hold_up_callback_activation() {
        let queue = std::sync::Arc::new(EventQueue::new());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let polling_queue = queue.clone();
        let poller = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            polling_queue.poll(Duration::from_secs(5))
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        let (handler, _) = handler_channel();
        queue.set_handler(handler).unwrap();
        let started = std::time::Instant::now();
        queue.drain_backlog_to_handler().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "callback activation waited behind a long pull operation"
        );
        assert!(poller.join().unwrap().is_none());
        queue.clear_handler_and_wait();
    }
}
