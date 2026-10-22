use std::sync::{Arc, mpsc};
use std::time::Duration;

use friendshub_core::Client;
use friendshub_core::client::method_ids;
use friendshub_core::config::Config;
use friendshub_core::events::{Event, EventHandler, EventQueue};
use sqlx::Executor;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

struct Recorder(mpsc::Sender<(&'static str, Option<u64>)>);

impl EventHandler for Recorder {
    fn on_typing(&self, event: &Event) {
        let _ = self.0.send(("typing", event.id));
    }

    fn on_receipt(&self, event: &Event) {
        let _ = self.0.send(("receipt", event.id));
    }
}

#[test]
fn event_queue_pushes_to_distinct_callbacks_without_polling() {
    let queue = EventQueue::new();
    let (tx, rx) = mpsc::channel();
    queue.set_handler(Arc::new(Recorder(tx))).unwrap();
    queue.drain_backlog_to_handler().unwrap();
    queue.push(Event::ephemeral(
        "typing",
        serde_json::json!({"conversation_id":"conversation"}),
    ));
    queue.push(Event {
        id: Some(77),
        kind: "receipt".into(),
        payload: serde_json::json!({"envelope_id":"envelope"}),
    });

    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        ("typing", None)
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        ("receipt", Some(77))
    );
    queue.clear_handler_and_wait();
}

#[test]
fn safe_client_opens_database_and_calls_dispatch_without_ffi_buffers() {
    let db_path =
        std::env::temp_dir().join(format!("friendshub-core-{}.sqlite", uuid::Uuid::new_v4()));
    let config: Config = serde_json::from_value(serde_json::json!({
        "db_path": db_path,
        "api_base": "http://127.0.0.1:1",
        "ws_url": "ws://127.0.0.1:1",
        "discovery": { "enabled": false },
        "log_level": "off",
        "log_format": "text"
    }))
    .unwrap();

    let client = Client::open(config).unwrap();
    let response: serde_json::Value = client
        .call_json(method_ids::PING, &serde_json::json!({}))
        .unwrap();
    assert_eq!(response, serde_json::json!({"pong":true}));
    drop(client);
    let _ = std::fs::remove_file(db_path);
}

struct PersistedEventRecorder(mpsc::Sender<Event>);

impl EventHandler for PersistedEventRecorder {
    fn on_envelope_received(&self, event: &Event) {
        let _ = self.0.send(event.clone());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn push_registration_delivers_unacked_events_restored_from_database() {
    let db_path = std::env::temp_dir().join(format!(
        "friendshub-core-replay-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    pool.execute(
        "CREATE TABLE pending_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL)",
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO pending_events (event_type, payload, created_at) VALUES (?, ?, ?)")
        .bind("envelope_received")
        .bind(r#"{"envelope_id":"persisted-envelope","ciphertext":"aa"}"#)
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pending_events (event_type, payload, created_at) VALUES (?, ?, ?)")
        .bind("receipt")
        .bind(r#"{"envelope_id":"receipt-envelope"}"#)
        .bind(2_i64)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pending_events (event_type, payload, created_at) VALUES (?, ?, ?)")
        .bind("receipt")
        .bind(r#"{"envelope_id":"second-receipt-envelope"}"#)
        .bind(3_i64)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let config: Config = serde_json::from_value(serde_json::json!({
        "db_path": db_path,
        "api_base": "http://127.0.0.1:1",
        "ws_url": "ws://127.0.0.1:1",
        "discovery": { "enabled": false },
        "log_level": "off",
        "log_format": "text"
    }))
    .unwrap();
    let client = Client::open(config).unwrap();
    let (tx, rx) = mpsc::channel();
    client
        .set_event_handler(Arc::new(PersistedEventRecorder(tx)))
        .unwrap();

    let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(event.id, Some(1));
    assert_eq!(event.kind, "envelope_received");
    assert_eq!(event.payload["envelope_id"], "persisted-envelope");

    client.ack_event(2).unwrap();
    let ack_response: serde_json::Value = client
        .call_json(method_ids::ACK_EVENT, &serde_json::json!({"event_id":3}))
        .unwrap();
    assert_eq!(ack_response, serde_json::json!({"acked":true}));
    let verify_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let pending_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_events")
        .fetch_one(&verify_pool)
        .await
        .unwrap();
    assert_eq!(
        pending_count, 1,
        "both ACK encodings must release durable rows"
    );
    let remaining_id: i64 = sqlx::query_scalar("SELECT id FROM pending_events")
        .fetch_one(&verify_pool)
        .await
        .unwrap();
    assert_eq!(remaining_id, 1, "unacknowledged events must remain durable");
    verify_pool.close().await;

    client.clear_event_handler();
    drop(client);
    let _ = std::fs::remove_file(db_path);
}
