use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;

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
    state: Mutex<QueueState>,
}

#[derive(Default)]
struct QueueState {
    backlog: VecDeque<Event>,
    worker: Option<CallbackWorker>,
    active: bool,
}

impl EventQueue {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(QueueState::default()),
        }
    }

    pub fn push(&self, ev: Event) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if state.active {
            let Some(worker) = state.worker.as_ref() else {
                state.active = false;
                state.backlog.push_back(ev);
                return;
            };
            match worker.tx.send(ev) {
                Ok(()) => return,
                Err(error) => {
                    // If the callback thread exited unexpectedly, discard the
                    // stale registration and preserve the event for the next
                    // push handler registration.
                    state.worker.take();
                    state.active = false;
                    state.backlog.push_back(error.0);
                    return;
                }
            }
        }

        state.backlog.push_back(ev);
    }

    /// Registers a handler whose methods run on one dedicated callback
    /// thread. Events queued before registration stay in the internal push
    /// backlog until [`Self::drain_backlog_to_handler`] transfers them to the
    /// worker. Activation preserves FIFO order with future events.
    ///
    /// Replacing a handler routes future events to the new handler. Events
    /// already queued for the old handler are drained by its worker and may
    /// complete after this returns.
    pub fn set_handler(&self, handler: Arc<dyn EventHandler>) -> std::io::Result<()> {
        let worker = CallbackWorker::spawn(handler)?;
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = false;
            let previous = state.worker.replace(worker);
            previous
        };
        drop(previous);
        Ok(())
    }

    /// Removes the callback handler. Events pushed after this call are kept
    /// in the internal backlog and pushed to the next registered handler.
    /// Events already queued for the handler continue on its worker and may
    /// complete after this returns.
    pub fn clear_handler(&self) {
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = false;
            let previous = state.worker.take();
            previous
        };
        drop(previous);
    }

    /// Removes the callback handler and waits for its worker to finish queued
    /// callbacks. If called on that worker itself, it detaches instead of
    /// joining the current thread.
    pub fn clear_handler_and_wait(&self) {
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = false;
            let previous = state.worker.take();
            previous
        };
        if let Some(worker) = previous {
            worker.stop_and_wait();
        }
    }

    /// Moves events accumulated before handler activation to the currently
    /// installed callback worker. This ensures events delivered before
    /// registration are pushed after the handler is installed.
    pub fn drain_backlog_to_handler(&self) -> std::io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.worker.is_none() {
            return Ok(());
        }

        // Keep producer routing locked while draining and sending. Producers
        // append to `backlog` until every older event has been enqueued on the
        // callback worker, so live events cannot overtake replayed events.
        let worker_tx = state
            .worker
            .as_ref()
            .expect("worker was checked above")
            .tx
            .clone();
        while let Some(event) = state.backlog.pop_front() {
            match worker_tx.send(event) {
                Ok(()) => {}
                Err(error) => {
                    state.backlog.push_front(error.0);
                    state.worker.take();
                    state.active = false;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "event callback worker stopped while draining the event backlog",
                    ));
                }
            }
        }
        state.active = true;
        Ok(())
    }

    pub fn has_handler(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
}

fn dispatch_event(handler: &dyn EventHandler, event: &Event) {
    match event.kind.as_str() {
        "ws_connected" => handler.on_ws_connected(event),
        "ws_disconnected" => handler.on_ws_disconnected(event),
        "ws_stopped" => handler.on_ws_stopped(event),
        "envelope_received" => {
            if let Some(typed) = crate::crypto::receive::classify_received_envelope(event) {
                dispatch_typed_envelope(handler, &typed);
            } else {
                // Unknown payloads, decryption failures, and older encrypted
                // forms stay observable through the raw-envelope callback.
                handler.on_envelope_received(event);
            }
        }
        "message_received" => handler.on_message_received(event),
        "poll_received" => handler.on_poll_received(event),
        "message_edited" => handler.on_message_edited(event),
        "message_deleted" => handler.on_message_deleted(event),
        "message_reaction" => handler.on_message_reaction(event),
        "attachment_key_received" => handler.on_attachment_key_received(event),
        "call_signal_received" => handler.on_call_signal_received(event),
        "history_chunk_received" => handler.on_history_chunk_received(event),
        "history_complete_received" => handler.on_history_complete_received(event),
        "sender_key_received" => handler.on_sender_key_received(event),
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

fn dispatch_typed_envelope(handler: &dyn EventHandler, event: &Event) {
    match event.kind.as_str() {
        "message_received" => handler.on_message_received(event),
        "poll_received" => handler.on_poll_received(event),
        "message_edited" => handler.on_message_edited(event),
        "message_deleted" => handler.on_message_deleted(event),
        "message_reaction" => handler.on_message_reaction(event),
        "attachment_key_received" => handler.on_attachment_key_received(event),
        "call_signal_received" => handler.on_call_signal_received(event),
        "history_chunk_received" => handler.on_history_chunk_received(event),
        "history_complete_received" => handler.on_history_complete_received(event),
        "sender_key_received" => handler.on_sender_key_received(event),
        _ => handler.on_envelope_received(event),
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
        on_message_received,
        on_poll_received,
        on_message_edited,
        on_message_deleted,
        on_message_reaction,
        on_attachment_key_received,
        on_call_signal_received,
        on_history_chunk_received,
        on_history_complete_received,
        on_sender_key_received,
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
            (
                event(
                    "message_received",
                    Some(72),
                    json!({"decrypted_payload":{"kind":"message"}}),
                ),
                "on_message_received",
            ),
            (
                event(
                    "poll_received",
                    Some(73),
                    json!({"decrypted_payload":{"kind":"poll"}}),
                ),
                "on_poll_received",
            ),
            (
                event("message_edited", Some(74), json!({})),
                "on_message_edited",
            ),
            (
                event("message_deleted", Some(75), json!({})),
                "on_message_deleted",
            ),
            (
                event("message_reaction", Some(76), json!({})),
                "on_message_reaction",
            ),
            (
                event("attachment_key_received", Some(77), json!({})),
                "on_attachment_key_received",
            ),
            (
                event("call_signal_received", Some(78), json!({})),
                "on_call_signal_received",
            ),
            (
                event("history_chunk_received", Some(79), json!({})),
                "on_history_chunk_received",
            ),
            (
                event("history_complete_received", Some(80), json!({})),
                "on_history_complete_received",
            ),
            (
                event("sender_key_received", Some(81), json!({})),
                "on_sender_key_received",
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
    fn durable_decrypted_envelopes_route_semantically_without_changing_the_ack_id() {
        let queue = EventQueue::new();
        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");

        let plaintext = serde_json::to_string(&json!({
            "kind":"message", "message_id":"message-1", "text":"hello"
        }))
        .unwrap();
        queue.push(event(
            "envelope_received",
            Some(1_337),
            json!({
                "envelope_id":"envelope-1", "envelope_type":1,
                "client_timestamp":123, "plaintext_hex":hex::encode(plaintext),
                "ciphertext":"aabb"
            }),
        ));

        let received = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("typed event must arrive");
        assert_eq!(received.method, "on_message_received");
        assert_eq!(received.kind, "message_received");
        assert_eq!(received.id, Some(1_337));
        queue.clear_handler_and_wait();
    }

    #[test]
    fn legacy_rust_handlers_keep_receiving_raw_decrypted_envelopes() {
        struct LegacyOnlyHandler(Sender<(String, Option<u64>, Value)>);
        impl EventHandler for LegacyOnlyHandler {
            fn on_envelope_received(&self, event: &Event) {
                let _ = self
                    .0
                    .send((event.kind.clone(), event.id, event.payload.clone()));
            }
        }

        let queue = EventQueue::new();
        let (tx, rx) = mpsc::channel();
        queue
            .set_handler(std::sync::Arc::new(LegacyOnlyHandler(tx)))
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");
        let plaintext = serde_json::to_string(&json!({
            "kind":"message", "message_id":"m1", "text":"hello"
        }))
        .unwrap();
        queue.push(event(
            "envelope_received",
            Some(2_004),
            json!({
                "envelope_id":"e1", "envelope_type":1,
                "plaintext_hex":hex::encode(plaintext), "ciphertext":"aa"
            }),
        ));

        let (kind, id, payload) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(kind, "envelope_received");
        assert_eq!(id, Some(2_004));
        assert_eq!(payload["envelope_id"], "e1");
        assert!(payload.get("decrypted_payload").is_none());
        queue.clear_handler_and_wait();
    }

    #[test]
    fn events_wait_for_a_push_handler_before_and_after_clear() {
        let queue = EventQueue::new();
        let first = event("receipt", None, json!({"sequence":1}));
        queue.push(first.clone());
        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("callback must activate");
        let first_callback = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("event queued before registration must be pushed");
        assert_eq!(first_callback.method, "on_receipt");
        assert_eq!(first_callback.kind, first.kind);

        queue.push(event("presence_updated", None, json!({"online":true})));
        let callback = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("registered handler must receive the event");
        assert_eq!(callback.method, "on_presence_updated");

        queue.clear_handler();
        let durable = event("envelope_received", Some(812), json!({"ciphertext":"beef"}));
        queue.push(durable.clone());
        let (handler, rx) = handler_channel();
        queue
            .set_handler(handler)
            .expect("replacement callback thread must start");
        queue
            .drain_backlog_to_handler()
            .expect("replacement callback must activate");
        let callback = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("event queued after clear must be pushed after registration");
        assert_eq!(callback.method, "on_envelope_received");
        assert_eq!(callback.id, durable.id);
        assert_eq!(callback.kind, durable.kind);
        queue.clear_handler_and_wait();
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
        queue.clear_handler_and_wait();
    }
}
