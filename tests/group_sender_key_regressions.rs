use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use friendshub_core::api;
use friendshub_core::client::method_ids;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::crypto::groups;
use friendshub_core::db;
use friendshub_core::db::auth::AuthState;
use friendshub_core::proto::rest::{chat, identity};
use friendshub_core::runtime::ActorState;
use friendshub_core::transport::HttpClient;
use prost::Message;

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn group_sender_key_apis_resolve_members_from_authenticated_server_conversation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    listener
        .set_nonblocking(true)
        .expect("fixture listener should be nonblocking");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        for request_index in 0..4 {
            let (mut stream, request) = accept_request(&listener)?;
            assert_eq!(request.method, "GET");
            assert_eq!(
                request.header("authorization"),
                Some("Bearer group-session")
            );
            assert_eq!(request.header("accept"), Some("application/x-protobuf"));

            let response = match request_index {
                0 | 2 => {
                    assert_eq!(request.target, "/api/v1/conversations/group-7");
                    chat::ConversationDetailResponse {
                        id: "group-7".into(),
                        kind: "group".into(),
                        title: Some("Test group".into()),
                        created_by: Some("account-a".into()),
                        created_at: 1,
                        updated_at: 1,
                        members: vec!["account-b".into()],
                        expires_at: None,
                        closed_at: None,
                    }
                    .encode_to_vec()
                }
                1 => {
                    assert_eq!(request.target, "/api/v1/accounts/account-b/devices");
                    identity::PublicDevicesResponse { items: Vec::new() }.encode_to_vec()
                }
                3 => {
                    assert_eq!(request.target, "/api/v1/conversations/group-7");
                    write_response(&mut stream, 503, "application/json", b"{}")?;
                    continue;
                }
                _ => unreachable!("only four requests are expected"),
            };
            write_protobuf_response(&mut stream, &response)?;
        }
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
            account_id: Some("account-a".into()),
            session_token: Some("group-session".into()),
            device_number: Some(1),
            totp_enabled: Some(0),
            ..AuthState::default()
        },
    )
    .await
    .expect("persist authenticated session");
    let http = HttpClient::new(&config).expect("build HTTP client");
    let state = std::sync::Arc::new(ActorState::new(config, database.clone(), http));

    let distribution = api::dispatch(
        state.clone(),
        method_ids::GROUPS_SEND_CREATE_DISTRIBUTION,
        br#"{"conversation_id":"group-7"}"#.to_vec(),
    )
    .await
    .expect("distribution should use the server conversation membership");
    let distribution: serde_json::Value =
        serde_json::from_slice(&distribution).expect("distribution response JSON");
    assert!(distribution["skdm_len"].as_u64().unwrap_or_default() > 0);
    assert!(distribution["envelopes"].as_array().unwrap().is_empty());

    let sent = api::dispatch(
        state.clone(),
        method_ids::GROUPS_SEND_SEND_GROUP_MESSAGE,
        br#"{"conversation_id":"group-7","plaintext_hex":"6869","sync":false}"#.to_vec(),
    )
    .await
    .expect("group send should use the server conversation membership");
    let sent: serde_json::Value = serde_json::from_slice(&sent).expect("send response JSON");
    assert!(sent["ciphertext_len"].as_u64().unwrap_or_default() > 0);
    assert!(sent["envelopes"].as_array().unwrap().is_empty());

    let distribution_id = uuid::Uuid::parse_str(
        distribution["distribution_id"]
            .as_str()
            .expect("distribution id string"),
    )
    .expect("distribution id UUID");
    let record_before_failed_membership_read: Vec<u8> = sqlx::query_scalar(
        "SELECT record FROM sender_keys WHERE sender_account_id = ? AND sender_device_number = ? AND distribution_id = ?",
    )
    .bind("account-a")
    .bind(1_i64)
    .bind(distribution_id.as_bytes().as_slice())
    .fetch_one(&database)
    .await
    .expect("sender key record after successful send");

    let failed_send = api::dispatch(
        state.clone(),
        method_ids::GROUPS_SEND_SEND_GROUP_MESSAGE,
        br#"{"conversation_id":"group-7","plaintext_hex":"6869","sync":false}"#.to_vec(),
    )
    .await;
    assert!(
        failed_send.is_err(),
        "failed membership lookup must fail the send"
    );

    let record_after_failed_membership_read: Vec<u8> = sqlx::query_scalar(
        "SELECT record FROM sender_keys WHERE sender_account_id = ? AND sender_device_number = ? AND distribution_id = ?",
    )
    .bind("account-a")
    .bind(1_i64)
    .bind(distribution_id.as_bytes().as_slice())
    .fetch_one(&database)
    .await
    .expect("sender key record after failed send");
    assert_eq!(
        record_after_failed_membership_read, record_before_failed_membership_read,
        "a failed membership lookup must not advance the sender-key ratchet"
    );

    drop(state);
    database.close().await;
    server
        .join()
        .expect("fixture thread should not panic")
        .expect("serve group conversation requests");
    remove_database_files(&database_path);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_first_use_returns_only_the_persisted_distribution_id() {
    let database_path = unique_database_path();
    let database = db::pool::open(&database_path)
        .await
        .expect("open isolated test database");
    db::migrations::MIGRATOR
        .run(&database)
        .await
        .expect("apply test database migrations");
    let config = Config {
        db_path: database_path.clone(),
        api_base: "http://127.0.0.1".into(),
        ws_url: "ws://127.0.0.1".into(),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    };
    let http = HttpClient::new(&config).expect("build HTTP client");
    let state = std::sync::Arc::new(ActorState::new(config, database.clone(), http));

    let returned = futures::future::join_all(
        (0..24).map(|_| groups::distribution_id_for(&state, "first-use-race")),
    )
    .await
    .into_iter()
    .map(|result| result.expect("distribution id lookup"))
    .collect::<Vec<_>>();
    let persisted: Vec<u8> = sqlx::query_scalar(
        "SELECT distribution_id FROM group_sender_keys WHERE conversation_id = ?",
    )
    .bind("first-use-race")
    .fetch_one(&database)
    .await
    .expect("first-use distribution ID should be persisted");
    let persisted = uuid::Uuid::from_slice(&persisted).expect("valid stored UUID");

    assert!(
        returned.iter().all(|id| *id == persisted),
        "every concurrent caller must return the persisted winner {persisted}, got {returned:?}"
    );

    drop(state);
    database.close().await;
    remove_database_files(&database_path);
}

fn accept_request(listener: &TcpListener) -> io::Result<(TcpStream, CapturedRequest)> {
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    };
    let request = read_request(&mut stream)?;
    Ok((stream, request))
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
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;

    Ok(CapturedRequest {
        method,
        target,
        headers,
    })
}

fn write_protobuf_response(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    write_response(stream, 200, "application/x-protobuf", body)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
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
        "friendshub-group-regression-{}-{timestamp}-{id}.sqlite",
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
