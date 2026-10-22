use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use friendshub_core::Client;
use friendshub_core::client::method_ids;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::proto::rest::identity;
use prost::Message;
use serde::Serialize;

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
}

#[derive(Serialize)]
struct LoginRequest {
    fh_number: String,
    password: String,
    device_number: i64,
}

#[test]
fn public_login_wrapper_uses_protobuf_http_and_decodes_protobuf_responses() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut login_stream, _) = listener.accept()?;
        let login = read_request(&mut login_stream)?;

        assert_eq!(login.method, "POST");
        assert_eq!(login.target, "/api/v1/login");
        assert_eq!(login.header("accept"), Some("application/x-protobuf"));
        assert_eq!(login.header("content-type"), Some("application/x-protobuf"));
        assert_eq!(login.header("authorization"), None);
        let decoded_login = identity::LoginRequest::decode(login.body.as_slice())
            .expect("login request must be protobuf");
        assert_eq!(decoded_login.fh_number.as_deref(), Some("FH-123456"));
        assert_eq!(decoded_login.password.as_deref(), Some("test-password"));
        assert_eq!(decoded_login.device_number, Some(17));

        let login_response = identity::LoginResponse {
            kind: "session".into(),
            session_token: Some("integration-session-token".into()),
            expires_at: Some(1_900_000_000),
            challenge_token: None,
            expires_in_seconds: None,
        }
        .encode_to_vec();
        write_protobuf_response(&mut login_stream, &login_response)?;
        drop(login_stream);

        let (mut me_stream, _) = listener.accept()?;
        let me = read_request(&mut me_stream)?;
        assert_eq!(me.method, "GET");
        assert_eq!(me.target, "/api/v1/me");
        assert_eq!(me.header("accept"), Some("application/x-protobuf"));
        assert_eq!(
            me.header("authorization"),
            Some("Bearer integration-session-token")
        );
        assert!(me.body.is_empty(), "GET /me should not carry a body");

        let me_response = identity::MeResponse {
            id: "account-abc".into(),
            user_id: 314,
            fh_number: "FH-123456".into(),
            username: "integration-user".into(),
            avatar_url: Some("https://cdn.example.test/avatar.webp".into()),
            totp_enabled: true,
            custom_status_text: Some("testing protobuf".into()),
            custom_status_emoji: Some("🧪".into()),
            custom_status_expires_at: Some(1_800_000_000),
        }
        .encode_to_vec();
        write_protobuf_response(&mut me_stream, &me_response)?;
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
        log_level: "error".into(),
        log_format: "text".into(),
    };
    let client = Client::open(config).expect("open client against local fixture");
    let result: serde_json::Value = client
        .call_json(
            method_ids::AUTH_LOGIN,
            &LoginRequest {
                fh_number: "FH-123456".into(),
                password: "test-password".into(),
                device_number: 17,
            },
        )
        .expect("login should decode protobuf responses");

    assert_eq!(result["kind"], "session");
    assert_eq!(result["session_token"], "integration-session-token");
    assert_eq!(result["expires_at"], 1_900_000_000_i64);
    assert_eq!(result["account"]["id"], "account-abc");
    assert_eq!(result["account"]["user_id"], 314);
    assert_eq!(result["account"]["username"], "integration-user");
    assert_eq!(
        result["account"]["avatar_url"],
        "https://cdn.example.test/avatar.webp"
    );
    assert_eq!(result["account"]["totp_enabled"], true);
    assert_eq!(result["account"]["custom_status_emoji"], "🧪");

    drop(client);
    server
        .join()
        .expect("fixture thread should not panic")
        .expect("serve fixture");
    remove_database_files(&database_path);
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
        "friendshub-rest-protobuf-{}-{timestamp}-{id}.sqlite",
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
