use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use friendshub_core::Client;
use friendshub_core::client::method_ids;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::events::{Event, EventHandler};
use friendshub_core::proto::rest::identity;
use friendshub_core::proto::{
    ClientFrame, NudgeResult, ServerFrame, ServerHello, TypingDelivery, client_frame, server_frame,
};
use prost::Message;
use serde::Serialize;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message as WebSocketMessage, accept};

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);
const SESSION_TOKEN: &str = "loopback-session-token";
const DEVICE_NUMBER: i64 = 17;
const ACCOUNT_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const CONVERSATION_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
const TYPING_ACCOUNT_ID: &str = "123e4567-e89b-12d3-a456-426614174002";

#[path = "support/http_fixture.rs"]
mod http_fixture;

use http_fixture::CapturedRequest;

#[derive(Serialize)]
struct LoginRequest {
    fh_number: String,
    password: String,
    device_number: i64,
}

#[derive(Debug, PartialEq)]
enum CallbackNotice {
    Connected(Value),
    Typing { id: Option<u64>, payload: Value },
    NudgeResult(Value),
    Unhandled(String),
}

struct RecordingHandler {
    notices: Sender<CallbackNotice>,
}

impl EventHandler for RecordingHandler {
    fn on_ws_connected(&self, event: &Event) {
        let _ = self
            .notices
            .send(CallbackNotice::Connected(event.payload.clone()));
    }

    fn on_typing(&self, event: &Event) {
        let _ = self.notices.send(CallbackNotice::Typing {
            id: event.id,
            payload: event.payload.clone(),
        });
    }

    fn on_nudge_result(&self, event: &Event) {
        let _ = self
            .notices
            .send(CallbackNotice::NudgeResult(event.payload.clone()));
    }

    fn on_unhandled(&self, event: &Event) {
        let _ = self
            .notices
            .send(CallbackNotice::Unhandled(event.kind.clone()));
    }
}

#[test]
fn websocket_typing_frame_reaches_distinct_push_callback_after_protobuf_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local HTTP/WebSocket fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || {
        let (mut login_stream, _) = listener.accept().expect("accept login request");
        let login = read_request(&mut login_stream).expect("read login request");
        assert_eq!(login.method, "POST");
        assert_eq!(login.target, "/api/v1/login");
        assert_eq!(login.header("content-type"), Some("application/x-protobuf"));
        let login = identity::LoginRequest::decode(login.body.as_slice())
            .expect("login body must use protobuf");
        assert_eq!(login.fh_number.as_deref(), Some("FH-123456"));
        assert_eq!(login.password.as_deref(), Some("fixture-password"));
        assert_eq!(login.device_number, Some(DEVICE_NUMBER));
        let login_response = identity::LoginResponse {
            kind: "session".into(),
            session_token: Some(SESSION_TOKEN.into()),
            expires_at: Some(1_900_000_000),
            challenge_token: None,
            expires_in_seconds: None,
        }
        .encode_to_vec();
        write_protobuf_response(&mut login_stream, &login_response)
            .expect("send protobuf login response");
        drop(login_stream);

        let (mut me_stream, _) = listener.accept().expect("accept /me request");
        let me = read_request(&mut me_stream).expect("read /me request");
        assert_eq!(me.method, "GET");
        assert_eq!(me.target, "/api/v1/me");
        assert_eq!(
            me.header("authorization"),
            Some("Bearer loopback-session-token")
        );
        let me_response = identity::MeResponse {
            id: ACCOUNT_ID.into(),
            user_id: 123,
            fh_number: "FH-123456".into(),
            username: "fixture-user".into(),
            avatar_url: None,
            totp_enabled: false,
            custom_status_text: None,
            custom_status_emoji: None,
            custom_status_expires_at: None,
        }
        .encode_to_vec();
        write_protobuf_response(&mut me_stream, &me_response).expect("send protobuf /me response");
        drop(me_stream);

        let (stream, _) = listener.accept().expect("accept websocket connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set WebSocket fixture read timeout");
        let mut socket = accept(stream).expect("complete WebSocket HTTP upgrade");

        let hello_message = socket.read().expect("read client protobuf Hello");
        let WebSocketMessage::Binary(hello_bytes) = hello_message else {
            panic!("expected a binary protobuf client Hello, got {hello_message:?}");
        };
        let client_frame =
            ClientFrame::decode(hello_bytes.as_ref()).expect("decode client Hello frame");
        let Some(client_frame::Kind::Hello(client_hello)) = client_frame.kind else {
            panic!("first client frame must be Hello");
        };
        assert_eq!(client_hello.session_token, SESSION_TOKEN);
        assert_eq!(client_hello.device_number, DEVICE_NUMBER as u32);
        assert_eq!(client_hello.protocol_major, 0);
        assert_eq!(client_hello.protocol_minor, 1);
        assert_eq!(client_hello.protocol_patch, 0);
        assert_eq!(client_hello.client_name, "friendshub-core");
        assert_eq!(client_hello.client_version, env!("CARGO_PKG_VERSION"));

        let server_hello = ServerFrame {
            kind: Some(server_frame::Kind::Hello(ServerHello {
                session_id: "fixture-session".into(),
                account_id: uuid_bytes(ACCOUNT_ID),
                device_number: DEVICE_NUMBER as u32,
                server_timestamp: 1_700_000_001,
                protocol_major: 0,
                protocol_minor: 1,
                protocol_patch: 0,
            })),
        };
        socket
            .send(WebSocketMessage::Binary(
                server_hello.encode_to_vec().into(),
            ))
            .expect("send server protobuf Hello");

        let typing = ServerFrame {
            kind: Some(server_frame::Kind::Typing(TypingDelivery {
                conversation_id: uuid_bytes(CONVERSATION_ID),
                account_id: uuid_bytes(TYPING_ACCOUNT_ID),
            })),
        };
        socket
            .send(WebSocketMessage::Binary(typing.encode_to_vec().into()))
            .expect("send protobuf typing frame");

        // A later recognized callback acts as a FIFO barrier: all callbacks
        // produced while handling the typing frame must be delivered before it.
        let barrier = ServerFrame {
            kind: Some(server_frame::Kind::NudgeResult(NudgeResult {
                delivered: true,
            })),
        };
        socket
            .send(WebSocketMessage::Binary(barrier.encode_to_vec().into()))
            .expect("send callback barrier frame");

        match socket.read().expect("read client WebSocket stop") {
            WebSocketMessage::Close(_) => {}
            other => panic!("expected WebSocket close after Client stop, got {other:?}"),
        }
    });

    let database_path = unique_database_path();
    let client = Client::open(Config {
        db_path: database_path.clone(),
        api_base: format!("http://{address}"),
        ws_url: format!("ws://{address}/ws"),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "error".into(),
        log_format: "text".into(),
    })
    .expect("open client against local fixture");

    let _: Value = client
        .call_json(
            method_ids::AUTH_LOGIN,
            &LoginRequest {
                fh_number: "FH-123456".into(),
                password: "fixture-password".into(),
                device_number: DEVICE_NUMBER,
            },
        )
        .expect("log in through local protobuf REST fixture");

    let (notice_tx, notice_rx) = mpsc::channel();
    client
        .set_event_handler(Arc::new(RecordingHandler { notices: notice_tx }))
        .expect("register push handler");
    let started: Value = client
        .call_json(method_ids::WS_START, &json!({}))
        .expect("start native WebSocket client");
    assert_eq!(started["started"], true);

    match receive_notice(&notice_rx) {
        CallbackNotice::Connected(payload) => {
            assert_eq!(payload["session_id"], "fixture-session");
            assert_eq!(payload["account_id"], ACCOUNT_ID);
            assert_eq!(payload["device_number"], DEVICE_NUMBER);
            assert_eq!(payload["server_timestamp"], 1_700_000_001_u64);
            assert_eq!(payload["protocol_major"], 0);
            assert_eq!(payload["protocol_minor"], 1);
            assert_eq!(payload["protocol_patch"], 0);
        }
        other => panic!("expected WebSocket connected callback, got {other:?}"),
    }
    assert_eq!(
        receive_notice(&notice_rx),
        CallbackNotice::Typing {
            id: None,
            payload: json!({
                "conversation_id": CONVERSATION_ID,
                "account_id": TYPING_ACCOUNT_ID,
            }),
        }
    );
    assert_eq!(
        receive_notice(&notice_rx),
        CallbackNotice::NudgeResult(json!({ "delivered": true })),
        "the following callback must pass the queue after all callbacks from typing"
    );
    assert!(
        notice_rx.try_recv().is_err(),
        "no callback should remain after the barrier"
    );

    let stopped: Value = client
        .call_json(method_ids::WS_STOP, &json!({}))
        .expect("stop native WebSocket client");
    assert_eq!(stopped["stopped"], true);
    client.clear_event_handler();
    drop(client);
    server.join().expect("fixture thread should not panic");
    remove_database_files(&database_path);
}

fn receive_notice(receiver: &Receiver<CallbackNotice>) -> CallbackNotice {
    receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("expected pushed event callback")
}

fn uuid_bytes(value: &str) -> Vec<u8> {
    uuid::Uuid::parse_str(value)
        .expect("fixture identifiers must be UUIDs")
        .as_bytes()
        .to_vec()
}

fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    http_fixture::read_request(stream)
}

fn write_protobuf_response(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn unique_database_path() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "friendshub-websocket-push-{}-{timestamp}-{id}.sqlite",
        std::process::id()
    ))
}

fn remove_database_files(database_path: &PathBuf) {
    for path in [
        database_path.clone(),
        PathBuf::from(format!("{}-wal", database_path.display())),
        PathBuf::from(format!("{}-shm", database_path.display())),
    ] {
        let _ = std::fs::remove_file(path);
    }
}
