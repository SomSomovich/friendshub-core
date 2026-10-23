use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
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
use friendshub_core::proto::rest::{ErrorResponse, identity};
use friendshub_core::runtime::ActorState;
use friendshub_core::transport::HttpClient;
use prost::Message;
use serde_json::{Value, json};

const SESSION_TOKEN: &str = "avatar-upload-session-token";
const WEBP_BYTES: &[u8] = b"RIFF1234WEBP";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

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

#[tokio::test(flavor = "current_thread")]
async fn account_avatar_upload_uses_protobuf_storage_put_and_finalize() {
    let api_listener = loopback_listener();
    let storage_listener = loopback_listener();
    let api_address = api_listener.local_addr().expect("API fixture address");
    let storage_url = format!(
        "http://{}/object/avatar-success",
        storage_listener
            .local_addr()
            .expect("storage fixture address")
    );

    let api_server = thread::spawn(move || -> io::Result<()> {
        serve_init(
            &api_listener,
            "upload-success",
            &storage_url,
            WEBP_BYTES.len() as u64,
        )?;
        serve_finalize(
            &api_listener,
            "upload-success",
            200,
            Some("https://cdn.example.test/avatars/account.webp"),
        )
    });
    let storage_server = thread::spawn(move || -> io::Result<()> {
        serve_storage_put(&storage_listener, "/object/avatar-success", WEBP_BYTES)
    });

    let (state, database, database_path, avatar_path) = setup_state(api_address).await;
    let response = upload_avatar(&state, &avatar_path).await;
    let response: Value = serde_json::from_slice(&response).expect("avatar result JSON");
    assert_eq!(
        response["avatar_url"],
        "https://cdn.example.test/avatars/account.webp"
    );

    drop(state);
    database.close().await;
    api_server
        .join()
        .expect("API fixture thread should not panic")
        .expect("serve API protobuf exchanges");
    storage_server
        .join()
        .expect("storage fixture thread should not panic")
        .expect("serve raw storage PUT");
    remove_temp_files(&database_path, &avatar_path);
}

#[tokio::test(flavor = "current_thread")]
async fn avatar_finalize_404_restarts_init_and_storage_upload_once() {
    let api_listener = loopback_listener();
    let storage_listener = loopback_listener();
    let api_address = api_listener.local_addr().expect("API fixture address");
    let storage_address = storage_listener
        .local_addr()
        .expect("storage fixture address");
    let first_storage_url = format!("http://{storage_address}/object/expired-session");
    let second_storage_url = format!("http://{storage_address}/object/restarted-session");

    let api_server = thread::spawn(move || -> io::Result<(usize, usize)> {
        serve_init(
            &api_listener,
            "upload-expired",
            &first_storage_url,
            WEBP_BYTES.len() as u64,
        )?;
        serve_finalize(&api_listener, "upload-expired", 404, None)?;
        serve_init(
            &api_listener,
            "upload-restarted",
            &second_storage_url,
            WEBP_BYTES.len() as u64,
        )?;
        serve_finalize(
            &api_listener,
            "upload-restarted",
            200,
            Some("https://cdn.example.test/avatars/account-restarted.webp"),
        )?;
        Ok((2, 2))
    });
    let storage_server = thread::spawn(move || -> io::Result<usize> {
        serve_storage_put(&storage_listener, "/object/expired-session", WEBP_BYTES)?;
        serve_storage_put(&storage_listener, "/object/restarted-session", WEBP_BYTES)?;
        Ok(2)
    });

    let (state, database, database_path, avatar_path) = setup_state(api_address).await;
    let response = upload_avatar(&state, &avatar_path).await;
    let response: Value = serde_json::from_slice(&response).expect("avatar result JSON");
    assert_eq!(
        response["avatar_url"],
        "https://cdn.example.test/avatars/account-restarted.webp"
    );

    drop(state);
    database.close().await;
    assert_eq!(
        api_server
            .join()
            .expect("API fixture thread should not panic")
            .expect("serve API protobuf exchanges"),
        (2, 2),
        "one 404 must cause exactly one new init/finalize cycle"
    );
    assert_eq!(
        storage_server
            .join()
            .expect("storage fixture thread should not panic")
            .expect("serve raw storage PUTs"),
        2,
        "the image must be uploaded once per session"
    );
    remove_temp_files(&database_path, &avatar_path);
}

async fn setup_state(
    api_address: std::net::SocketAddr,
) -> (Arc<ActorState>, db::Db, PathBuf, PathBuf) {
    let database_path = unique_path("db", "sqlite");
    let avatar_path = unique_path("avatar", "webp");
    std::fs::write(&avatar_path, WEBP_BYTES).expect("write local WebP fixture");

    let config = Config {
        db_path: database_path.clone(),
        api_base: format!("http://{api_address}"),
        ws_url: format!("ws://{api_address}"),
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
            session_token: Some(SESSION_TOKEN.into()),
            device_number: Some(17),
            totp_enabled: Some(0),
            ..AuthState::default()
        },
    )
    .await
    .expect("persist authenticated session");
    let http = HttpClient::new(&config).expect("build HTTP client");
    let state = Arc::new(ActorState::new(config, database.clone(), http));
    (state, database, database_path, avatar_path)
}

async fn upload_avatar(state: &Arc<ActorState>, avatar_path: &PathBuf) -> Vec<u8> {
    api::dispatch(
        state.clone(),
        method_ids::AVATARS_UPLOAD,
        serde_json::to_vec(&json!({"file_path": avatar_path})).unwrap(),
    )
    .await
    .expect("account avatar flow should complete")
}

fn serve_init(
    api_listener: &TcpListener,
    upload_id: &str,
    storage_url: &str,
    expected_size: u64,
) -> io::Result<()> {
    let (mut stream, request) = accept_request(api_listener)?;
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/api/v1/avatars/me/uploads");
    assert_eq!(request.header("accept"), Some("application/x-protobuf"));
    assert_eq!(
        request.header("content-type"),
        Some("application/x-protobuf")
    );
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {SESSION_TOKEN}").as_str())
    );
    assert_eq!(request.header("x-device-number"), None);
    let body = identity::AvatarUploadInitRequest::decode(request.body.as_slice())
        .expect("init body should be protobuf");
    assert_eq!(body.size_bytes, Some(expected_size));

    let response = identity::AvatarUploadInitResponse {
        upload_id: upload_id.into(),
        size_bytes: expected_size,
        url: storage_url.into(),
    }
    .encode_to_vec();
    write_response(&mut stream, 201, "application/x-protobuf", &response)
}

fn serve_finalize(
    api_listener: &TcpListener,
    upload_id: &str,
    status: u16,
    avatar_url: Option<&str>,
) -> io::Result<()> {
    let (mut stream, request) = accept_request(api_listener)?;
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target,
        format!("/api/v1/avatars/me/uploads/{upload_id}/finalize")
    );
    assert_eq!(request.header("accept"), Some("application/x-protobuf"));
    assert_eq!(request.header("content-type"), None);
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {SESSION_TOKEN}").as_str())
    );
    assert_eq!(request.header("x-device-number"), None);
    assert!(
        request.body.is_empty(),
        "finalize route has no request body"
    );

    if status == 404 {
        let response = ErrorResponse {
            error: "not_found".into(),
            message: "avatar upload session not found".into(),
            details: None,
        }
        .encode_to_vec();
        write_response(&mut stream, status, "application/x-protobuf", &response)
    } else {
        let response = identity::AvatarUrlResponse {
            avatar_url: avatar_url
                .expect("successful finalize needs avatar URL")
                .into(),
        }
        .encode_to_vec();
        write_response(&mut stream, status, "application/x-protobuf", &response)
    }
}

fn serve_storage_put(
    storage_listener: &TcpListener,
    expected_path: &str,
    expected_body: &[u8],
) -> io::Result<()> {
    let (mut stream, request) = accept_request(storage_listener)?;
    assert_eq!(request.method, "PUT");
    assert_eq!(request.target, expected_path);
    assert_eq!(request.header("authorization"), None);
    assert_eq!(request.header("x-device-number"), None);
    assert_eq!(
        request.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(request.body, expected_body);
    write_response(&mut stream, 200, "application/octet-stream", b"")
}

fn loopback_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    listener
        .set_nonblocking(true)
        .expect("fixture listener should be nonblocking");
    listener
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

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
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

fn unique_path(prefix: &str, extension: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "friendshub-avatar-flow-{}-{prefix}-{timestamp}-{id}.{extension}",
        std::process::id()
    ))
}

fn remove_temp_files(database_path: &PathBuf, avatar_path: &PathBuf) {
    for path in [
        database_path.clone(),
        PathBuf::from(format!("{}-wal", database_path.display())),
        PathBuf::from(format!("{}-shm", database_path.display())),
        avatar_path.clone(),
    ] {
        let _ = std::fs::remove_file(path);
    }
}
