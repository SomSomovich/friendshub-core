use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use friendshub_core::Client;
use friendshub_core::bot_api::{
    AnswerBotCallbackQueryInput, BotApiError, BotCallbackQueryUpdate, BotEditedMessageUpdate,
    BotMessageUpdate, BotUpdateHandler, BotUpdatesOptions,
};
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::error::{Error, Result};
use serde_json::{Value, json};

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn path_and_query(&self) -> (&str, HashMap<String, String>) {
        let (path, query) = self.target.split_once('?').unwrap_or((&self.target, ""));
        let values = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        (path, values)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Notice {
    Message {
        update_id: i64,
        message_id: String,
        text: String,
    },
    EditedMessage {
        update_id: i64,
        message_id: String,
        text: String,
    },
    CallbackQuery {
        update_id: i64,
        callback_query_id: String,
        data: String,
    },
    Offset(i64),
    Error {
        status: Option<u16>,
        code: Option<String>,
        message: String,
    },
}

struct RecordingHandler {
    notices: Sender<Notice>,
    fail_message: bool,
}

impl RecordingHandler {
    fn new(notices: Sender<Notice>) -> Self {
        Self {
            notices,
            fail_message: false,
        }
    }

    fn failing_message(notices: Sender<Notice>) -> Self {
        Self {
            notices,
            fail_message: true,
        }
    }

    fn report_error(&self, error: BotApiError) {
        let _ = self.notices.send(Notice::Error {
            status: error.status,
            code: error.code,
            message: error.message,
        });
    }
}

impl BotUpdateHandler for RecordingHandler {
    fn on_message(&self, update: BotMessageUpdate) -> Result<()> {
        self.notices
            .send(Notice::Message {
                update_id: update.update_id,
                message_id: update.data.message_id,
                text: update.data.text,
            })
            .map_err(|error| Error::Internal(error.to_string()))?;
        if self.fail_message {
            return Err(Error::Internal("message callback rejected update".into()));
        }
        Ok(())
    }

    fn on_edited_message(&self, update: BotEditedMessageUpdate) -> Result<()> {
        self.notices
            .send(Notice::EditedMessage {
                update_id: update.update_id,
                message_id: update.data.message_id,
                text: update.data.text,
            })
            .map_err(|error| Error::Internal(error.to_string()))
    }

    fn on_callback_query(&self, update: BotCallbackQueryUpdate) -> Result<()> {
        self.notices
            .send(Notice::CallbackQuery {
                update_id: update.update_id,
                callback_query_id: update.data.callback_query_id,
                data: update.data.data,
            })
            .map_err(|error| Error::Internal(error.to_string()))
    }

    fn on_error(&self, error: BotApiError) {
        self.report_error(error);
    }

    fn on_offset(&self, offset: i64) {
        let _ = self.notices.send(Notice::Offset(offset));
    }
}

#[test]
fn get_updates_routes_each_kind_in_order_and_advances_only_after_success() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut first_stream, _) = listener.accept()?;
        let first = read_request(&mut first_stream)?;
        assert_bot_authorization(&first, "bot-secret");
        let (path, query) = first.path_and_query();
        assert_eq!(first.method, "GET");
        assert_eq!(path, "/api/bot/v1/getUpdates");
        assert_eq!(query.get("offset").map(String::as_str), Some("7"));
        assert_eq!(query.get("limit").map(String::as_str), Some("500"));
        assert_eq!(query.get("timeout").map(String::as_str), Some("60"));
        assert!(first.body.is_empty());

        write_json_response(
            &mut first_stream,
            200,
            &json!({
                "updates": [
                    {
                        "update_id": 11,
                        "update_type": "message",
                        "created_at": 101,
                        "data": {
                            "message_id": "message-11",
                            "bot_id": "bot-1",
                            "account_id": "account-1",
                            "text": "hello",
                            "reply_to_message_id": null,
                            "created_at": 101
                        }
                    },
                    {
                        "update_id": 12,
                        "update_type": "edited_message",
                        "created_at": 102,
                        "data": {
                            "message_id": "message-12",
                            "bot_id": "bot-1",
                            "account_id": "account-1",
                            "text": "edited",
                            "reply_to_message_id": "message-10",
                            "created_at": 102
                        }
                    },
                    {
                        "update_id": 13,
                        "update_type": "callback_query",
                        "created_at": 103,
                        "data": {
                            "callback_query_id": "callback-13",
                            "message_id": "message-12",
                            "account_id": "account-1",
                            "data": "approve",
                            "created_at": 103
                        }
                    }
                ]
            }),
        )?;
        drop(first_stream);

        // The next request proves the cursor is the exact last successfully
        // handled update ID, with no eager increment.
        let (mut second_stream, _) = listener.accept()?;
        let second = read_request(&mut second_stream)?;
        assert_bot_authorization(&second, "bot-secret");
        let (path, query) = second.path_and_query();
        assert_eq!(path, "/api/bot/v1/getUpdates");
        assert_eq!(query.get("offset").map(String::as_str), Some("13"));
        assert_eq!(query.get("limit").map(String::as_str), Some("500"));
        assert_eq!(query.get("timeout").map(String::as_str), Some("60"));
        write_json_response(
            &mut second_stream,
            401,
            &json!({"error": "unauthorized", "message": "invalid bot token"}),
        )?;
        Ok(())
    });

    let database_path = unique_database_path();
    let client = open_client(address, &database_path);
    let (notice_tx, notice_rx) = mpsc::channel();
    let mut subscription = client
        .subscribe_bot_updates(
            "bot-secret",
            BotUpdatesOptions {
                offset: 7,
                limit: 900,
                timeout_seconds: 90,
            },
            Arc::new(RecordingHandler::new(notice_tx)),
        )
        .expect("start bot update subscription");

    assert_eq!(
        receive_notice(&notice_rx),
        Notice::Message {
            update_id: 11,
            message_id: "message-11".into(),
            text: "hello".into(),
        }
    );
    assert_eq!(receive_notice(&notice_rx), Notice::Offset(11));
    assert_eq!(
        receive_notice(&notice_rx),
        Notice::EditedMessage {
            update_id: 12,
            message_id: "message-12".into(),
            text: "edited".into(),
        }
    );
    assert_eq!(receive_notice(&notice_rx), Notice::Offset(12));
    assert_eq!(
        receive_notice(&notice_rx),
        Notice::CallbackQuery {
            update_id: 13,
            callback_query_id: "callback-13".into(),
            data: "approve".into(),
        }
    );
    assert_eq!(receive_notice(&notice_rx), Notice::Offset(13));
    match receive_notice(&notice_rx) {
        Notice::Error {
            status,
            code,
            message,
        } => {
            assert_eq!(status, Some(401));
            assert_eq!(code.as_deref(), Some("unauthorized"));
            assert!(message.contains("invalid bot token"));
        }
        other => panic!("expected HTTP error callback, got {other:?}"),
    }

    subscription.cancel().expect("stop completed subscription");
    drop(client);
    server
        .join()
        .expect("server fixture should not panic")
        .expect("serve fixture");
    remove_database_files(&database_path);
}

#[test]
fn get_updates_retries_once_after_zero_retry_after_without_changing_request() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<usize> {
        for status in [429, 401] {
            let (mut stream, _) = listener.accept()?;
            let request = read_request(&mut stream)?;
            assert_bot_authorization(&request, "retry-token");
            let (path, query) = request.path_and_query();
            assert_eq!(request.method, "GET");
            assert_eq!(path, "/api/bot/v1/getUpdates");
            assert_eq!(query.get("offset").map(String::as_str), Some("27"));
            assert_eq!(query.get("limit").map(String::as_str), Some("42"));
            assert_eq!(query.get("timeout").map(String::as_str), Some("0"));
            assert!(request.body.is_empty());

            if status == 429 {
                write_rate_limited_response(
                    &mut stream,
                    &json!({"error": "rate_limited", "message": "try again"}),
                )?;
            } else {
                write_json_response(
                    &mut stream,
                    401,
                    &json!({"error": "unauthorized", "message": "invalid retry token"}),
                )?;
            }
        }

        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match listener.accept() {
                Ok((mut unexpected, _)) => {
                    let _ = read_request(&mut unexpected);
                    return Ok(3);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(2);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    });

    let database_path = unique_database_path();
    let client = open_client(address, &database_path);
    let (notice_tx, notice_rx) = mpsc::channel();
    let mut subscription = client
        .subscribe_bot_updates(
            "retry-token",
            BotUpdatesOptions {
                offset: 27,
                limit: 42,
                timeout_seconds: 0,
            },
            Arc::new(RecordingHandler::new(notice_tx)),
        )
        .expect("start bot update subscription");

    match receive_notice(&notice_rx) {
        Notice::Error {
            status,
            code,
            message,
        } => {
            assert_eq!(status, Some(401));
            assert_eq!(code.as_deref(), Some("unauthorized"));
            assert!(message.contains("invalid retry token"));
        }
        other => panic!("expected final HTTP error callback, got {other:?}"),
    }

    subscription.cancel().expect("stop errored subscription");
    assert_eq!(
        server
            .join()
            .expect("server fixture should not panic")
            .expect("serve fixture"),
        2,
        "getUpdates should retry 429 exactly once"
    );
    drop(client);
    remove_database_files(&database_path);
}

#[test]
fn callback_failure_reports_error_without_advancing_offset_or_polling_again() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<bool> {
        let (mut stream, _) = listener.accept()?;
        let request = read_request(&mut stream)?;
        assert_bot_authorization(&request, "bot-secret");
        let (path, query) = request.path_and_query();
        assert_eq!(path, "/api/bot/v1/getUpdates");
        assert_eq!(query.get("offset").map(String::as_str), Some("4"));
        assert_eq!(query.get("limit").map(String::as_str), Some("25"));
        assert_eq!(query.get("timeout").map(String::as_str), Some("0"));
        write_json_response(
            &mut stream,
            200,
            &json!({
                "updates": [
                    {
                        "update_id": 8,
                        "update_type": "message",
                        "data": {
                            "message_id": "message-8",
                            "bot_id": "bot-1",
                            "account_id": "account-1",
                            "text": "reject me",
                            "reply_to_message_id": null,
                            "created_at": 108
                        }
                    },
                    {
                        "update_id": 9,
                        "update_type": "callback_query",
                        "data": {
                            "callback_query_id": "callback-9",
                            "message_id": "message-8",
                            "account_id": "account-1",
                            "data": "later",
                            "created_at": 109
                        }
                    }
                ]
            }),
        )?;
        drop(stream);

        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_millis(400);
        loop {
            match listener.accept() {
                Ok((mut unexpected, _)) => {
                    let _ = read_request(&mut unexpected);
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(false);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    });

    let database_path = unique_database_path();
    let client = open_client(address, &database_path);
    let (notice_tx, notice_rx) = mpsc::channel();
    let mut subscription = client
        .subscribe_bot_updates(
            "bot-secret",
            BotUpdatesOptions {
                offset: 4,
                limit: 25,
                timeout_seconds: 0,
            },
            Arc::new(RecordingHandler::failing_message(notice_tx)),
        )
        .expect("start bot update subscription");

    assert_eq!(
        receive_notice(&notice_rx),
        Notice::Message {
            update_id: 8,
            message_id: "message-8".into(),
            text: "reject me".into(),
        }
    );
    match receive_notice(&notice_rx) {
        Notice::Error {
            status,
            code: _,
            message,
        } => {
            assert_eq!(status, None);
            assert!(message.contains("message callback rejected update"));
        }
        other => panic!("expected callback failure notification, got {other:?}"),
    }
    assert!(
        notice_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "a failed callback must not emit an offset or dispatch later updates"
    );

    subscription
        .cancel()
        .expect("stop failed callback subscription");
    assert!(
        !server
            .join()
            .expect("server fixture should not panic")
            .expect("serve fixture")
    );
    drop(client);
    remove_database_files(&database_path);
}

#[test]
fn cancelling_an_in_flight_long_poll_returns_promptly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || -> io::Result<usize> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let request = read_request(&mut stream)?;
        assert_bot_authorization(&request, "bot-secret");
        let (path, query) = request.path_and_query();
        assert_eq!(path, "/api/bot/v1/getUpdates");
        assert_eq!(query.get("offset").map(String::as_str), Some("0"));
        assert_eq!(query.get("limit").map(String::as_str), Some("100"));
        assert_eq!(query.get("timeout").map(String::as_str), Some("60"));
        request_tx.send(()).expect("test should still be waiting");

        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(read) => Ok(read),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(0)
            }
            Err(error) => Err(error),
        }
    });

    let database_path = unique_database_path();
    let client = open_client(address, &database_path);
    let (notice_tx, notice_rx) = mpsc::channel();
    let mut subscription = client
        .subscribe_bot_updates(
            "bot-secret",
            BotUpdatesOptions::default(),
            Arc::new(RecordingHandler::new(notice_tx)),
        )
        .expect("start bot update subscription");
    request_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("long-poll request reached fixture");

    let started = Instant::now();
    subscription.cancel().expect("cancel long poll");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancelling an outstanding poll should not wait for the HTTP timeout"
    );
    assert!(
        notice_rx.try_recv().is_err(),
        "cancellation must not synthesize an update or error"
    );
    assert_eq!(
        server
            .join()
            .expect("server fixture should not panic")
            .expect("observe request close"),
        0,
        "cancellation should close the in-flight HTTP connection"
    );

    drop(client);
    remove_database_files(&database_path);
}

#[test]
fn answer_callback_query_sends_json_and_accepts_no_content() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let request = read_request(&mut stream)?;
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/bot/v1/answerCallbackQuery");
        assert_bot_authorization(&request, "bot-secret");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("JSON callback answer"),
            json!({
                "callback_query_id": "callback-7",
                "account_id": "account-3",
                "message_id": "message-9",
                "text": "Saved",
                "show_alert": false
            })
        );
        write_no_content_response(&mut stream)
    });

    let database_path = unique_database_path();
    let client = open_client(address, &database_path);
    client
        .answer_bot_callback_query(
            "bot-secret",
            AnswerBotCallbackQueryInput {
                callback_query_id: "callback-7".into(),
                account_id: "account-3".into(),
                message_id: "message-9".into(),
                text: Some("Saved".into()),
                show_alert: Some(false),
            },
        )
        .expect("HTTP 204 is a successful empty response");

    drop(client);
    server
        .join()
        .expect("server fixture should not panic")
        .expect("serve fixture");
    remove_database_files(&database_path);
}

fn open_client(address: std::net::SocketAddr, database_path: &PathBuf) -> Client {
    Client::open(Config {
        db_path: database_path.clone(),
        api_base: format!("http://{address}"),
        ws_url: format!("ws://{address}"),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "error".into(),
        log_format: "text".into(),
    })
    .expect("open client against local fixture")
}

fn receive_notice(receiver: &Receiver<Notice>) -> Notice {
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("expected callback notification")
}

fn assert_bot_authorization(request: &CapturedRequest, token: &str) {
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let target = request_parts.next().unwrap_or_default().to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let body_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or(0);
    let mut body = vec![0; body_length];
    reader.read_exact(&mut body)?;

    Ok(CapturedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn write_rate_limited_response(stream: &mut TcpStream, body: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write!(
        stream,
        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn write_no_content_response(stream: &mut TcpStream) -> io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    stream.flush()
}

fn unique_database_path() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "friendshub-bot-api-{}-{timestamp}-{id}.sqlite",
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
