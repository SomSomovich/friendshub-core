use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use friendshub_core::Client;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::proto::rest::identity;
use prost::Message;
use serde::{Deserialize, Serialize};

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[path = "support/http_fixture.rs"]
mod http_fixture;

use http_fixture::CapturedRequest;

#[derive(Serialize)]
struct LoginRequest {
    fh_number: String,
    password: String,
    device_number: i64,
}

#[derive(Debug, Deserialize)]
struct LoginResult {
    kind: String,
    session_token: Option<String>,
    account: Option<Account>,
}

#[derive(Debug, Deserialize)]
struct Account {
    id: String,
    username: String,
}

#[test]
fn named_native_methods_serialize_requests_and_decode_owned_responses() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local HTTP fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut login_stream, _) = listener.accept()?;
        let login = read_request(&mut login_stream)?;
        assert_eq!(login.method, "POST");
        assert_eq!(login.target, "/api/v1/login");
        assert_eq!(login.header("content-type"), Some("application/x-protobuf"));
        let login = identity::LoginRequest::decode(login.body.as_slice())
            .expect("typed login must become protobuf HTTP request");
        assert_eq!(login.fh_number.as_deref(), Some("FH-123456"));
        assert_eq!(login.password.as_deref(), Some("fixture-password"));
        assert_eq!(login.device_number, Some(17));
        let login_response = identity::LoginResponse {
            kind: "session".into(),
            session_token: Some("typed-session-token".into()),
            expires_at: Some(1_900_000_000),
            challenge_token: None,
            expires_in_seconds: None,
        }
        .encode_to_vec();
        write_protobuf_response(&mut login_stream, &login_response)?;
        drop(login_stream);

        // Login internally fetches /me to persist the account session.
        let (mut login_me_stream, _) = listener.accept()?;
        let login_me = read_request(&mut login_me_stream)?;
        assert_eq!(login_me.method, "GET");
        assert_eq!(login_me.target, "/api/v1/me");
        assert_eq!(
            login_me.header("authorization"),
            Some("Bearer typed-session-token")
        );
        write_me_response(&mut login_me_stream, "account-from-login", "typed-user")?;
        drop(login_me_stream);

        // This request is made through the parameterless named auth_me method.
        let (mut me_stream, _) = listener.accept()?;
        let me = read_request(&mut me_stream)?;
        assert_eq!(me.method, "GET");
        assert_eq!(me.target, "/api/v1/me");
        assert!(
            me.body.is_empty(),
            "GET /me must not send an app request body"
        );
        assert_eq!(
            me.header("authorization"),
            Some("Bearer typed-session-token")
        );
        write_me_response(&mut me_stream, "account-from-me", "typed-me")
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
    .expect("open client against loopback fixture");

    let login: LoginResult = client
        .auth_login(&LoginRequest {
            fh_number: "FH-123456".into(),
            password: "fixture-password".into(),
            device_number: 17,
        })
        .expect("named auth_login should route and deserialize");
    assert_eq!(login.kind, "session");
    assert_eq!(login.session_token.as_deref(), Some("typed-session-token"));
    assert_eq!(
        login.account.as_ref().map(|account| account.id.as_str()),
        Some("account-from-login")
    );

    let account: Account = client
        .auth_me()
        .expect("parameterless auth_me should decode");
    assert_eq!(account.id, "account-from-me");
    assert_eq!(account.username, "typed-me");

    drop(client);
    server
        .join()
        .expect("fixture thread should not panic")
        .expect("serve fixture");
    remove_database_files(&database_path);
}

fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    http_fixture::read_request(stream)
}

fn write_me_response(stream: &mut TcpStream, id: &str, username: &str) -> io::Result<()> {
    let response = identity::MeResponse {
        id: id.into(),
        user_id: 42,
        fh_number: "FH-123456".into(),
        username: username.into(),
        avatar_url: None,
        totp_enabled: false,
        custom_status_text: None,
        custom_status_emoji: None,
        custom_status_expires_at: None,
    }
    .encode_to_vec();
    write_protobuf_response(stream, &response)
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
        .expect("clock after Unix epoch")
        .as_nanos();
    let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "friendshub-typed-client-{}-{timestamp}-{id}.sqlite",
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
