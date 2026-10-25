use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use friendshub_core::api;
use friendshub_core::client::method_ids;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::db;
use friendshub_core::db::auth::AuthState;
use friendshub_core::proto::rest::identity;
use friendshub_core::runtime::ActorState;
use friendshub_core::transport::HttpClient;
use prost::Message;
use serde_json::{Value, json};

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[path = "support/http_fixture.rs"]
mod http_fixture;

use http_fixture::CapturedRequest;

#[path = "support/keyring.rs"]
mod keyring;

#[tokio::test(flavor = "current_thread")]
async fn authenticated_contact_wrapper_uses_protobuf_and_keeps_json_and_raw_fallbacks() {
    keyring::use_memory_keyring();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    listener
        .set_nonblocking(true)
        .expect("fixture listener should be nonblocking");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut contacts_stream, contacts) = accept_request(&listener)?;
        assert_eq!(contacts.method, "GET");
        assert_eq!(contacts.target, "/api/v1/contacts");
        assert_eq!(contacts.header("accept"), Some("application/x-protobuf"));
        assert_eq!(
            contacts.header("authorization"),
            Some("Bearer loopback-session")
        );
        assert!(
            contacts.body.is_empty(),
            "GET contacts should not carry a body"
        );

        let contacts_response = identity::ContactsResponse {
            items: vec![identity::ContactItem {
                target_account_id: "target-77".into(),
                local_username: "work".into(),
                user_id: 77,
                fh_number: "FH-000077".into(),
                username: "loopback-user".into(),
                avatar_url: Some("https://cdn.example.test/avatar.webp".into()),
            }],
        }
        .encode_to_vec();
        write_response(
            &mut contacts_stream,
            200,
            "application/x-protobuf",
            &contacts_response,
        )?;
        drop(contacts_stream);

        let (mut json_stream, json_request) = accept_request(&listener)?;
        assert_eq!(json_request.method, "POST");
        assert_eq!(json_request.target, "/api/bot/v1/answerCallbackQuery");
        assert_ne!(
            json_request.header("accept"),
            Some("application/x-protobuf"),
            "JSON fallback must not request protobuf"
        );
        assert_eq!(
            json_request.header("content-type"),
            Some("application/json")
        );
        assert_eq!(
            json_request.header("authorization"),
            Some("Bearer loopback-bot-token")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&json_request.body)
                .expect("JSON fallback request body"),
            json!({
                "callback_query_id": "callback-5",
                "account_id": "account-9",
                "message_id": "message-12",
                "text": "Saved",
                "show_alert": false
            })
        );
        write_response(&mut json_stream, 204, "application/json", b"")?;
        drop(json_stream);

        let (mut raw_stream, raw_request) = accept_request(&listener)?;
        assert_eq!(raw_request.method, "GET");
        assert_eq!(raw_request.target, "/api/v1/avatars/account-raw");
        assert_eq!(raw_request.header("accept"), Some("application/x-protobuf"));
        assert_eq!(raw_request.header("authorization"), None);
        write_response(&mut raw_stream, 200, "image/webp", b"RIFF1234WEBP")?;
        Ok(())
    });

    let database_path = unique_database_path();
    let config = Config {
        db_path: database_path.clone(),
        api_base: format!("http://{address}"),
        ws_url: format!("ws://{address}"),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    };
    let database = db::pool::open(&database_path)
        .await
        .expect("open isolated test database");
    db::migrations::MIGRATOR
        .run(&database)
        .await
        .expect("apply test database migrations");
    db::auth::store(
        &database,
        &AuthState {
            session_token: Some("loopback-session".into()),
            totp_enabled: Some(0),
            ..AuthState::default()
        },
    )
    .await
    .expect("persist authenticated session for wrapper");
    let http = HttpClient::new(&config).expect("build HTTP client");
    let state = Arc::new(ActorState::new(config, database.clone(), http));

    let contacts = api::dispatch(state.clone(), method_ids::CONTACTS_LIST, Vec::new())
        .await
        .expect("authenticated contacts wrapper should decode protobuf");
    let contacts: Value = serde_json::from_slice(&contacts).expect("contacts JSON DTO");
    assert_eq!(contacts[0]["target_account_id"], "target-77");
    assert_eq!(contacts[0]["local_username"], "work");
    assert_eq!(contacts[0]["user_id"], 77);
    assert_eq!(contacts[0]["username"], "loopback-user");
    assert_eq!(
        contacts[0]["avatar_url"],
        "https://cdn.example.test/avatar.webp"
    );

    let callback_result = api::dispatch(
        state.clone(),
        method_ids::BOT_ANSWER_CALLBACK_QUERY,
        serde_json::to_vec(&json!({
            "token": "loopback-bot-token",
            "callback_query_id": "callback-5",
            "account_id": "account-9",
            "message_id": "message-12",
            "text": "Saved",
            "show_alert": false
        }))
        .unwrap(),
    )
    .await
    .expect("JSON bot API fallback should accept an empty 204 response");
    assert_eq!(callback_result, b"null");

    let avatar = api::dispatch(
        state.clone(),
        method_ids::AVATARS_SERVE,
        br#"{"account_id":"account-raw"}"#.to_vec(),
    )
    .await
    .expect("raw avatar response should bypass protobuf decoding");
    let avatar: Value = serde_json::from_slice(&avatar).expect("avatar DTO JSON");
    assert_eq!(avatar["account_id"], "account-raw");
    assert_eq!(avatar["content_type"], "image/webp");
    use base64::Engine;
    let raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(avatar["data_base64"].as_str().expect("base64 payload"))
        .expect("avatar base64 should decode");
    assert_eq!(raw_bytes, b"RIFF1234WEBP");

    drop(state);
    database.close().await;
    server
        .join()
        .expect("loopback server thread should not panic")
        .expect("serve loopback responses");
    remove_database_files(&database_path);
}

fn accept_request(listener: &TcpListener) -> io::Result<(TcpStream, CapturedRequest)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let request = read_request(&mut stream)?;
                return Ok((stream, request));
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    http_fixture::read_request(stream)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        _ => "Test Response",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
        "friendshub-rest-protobuf-parity-{}-{timestamp}-{id}.sqlite",
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
