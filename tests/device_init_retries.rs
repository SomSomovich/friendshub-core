use friendshub_core::proto::rest::identity;
use friendshub_core::{
    config::Config, crypto::stores::Store, db::migrations::MIGRATOR, runtime::ActorState,
    transport::http::HttpClient,
};
use libsignal_protocol::{DeviceId, IdentityKeyPair, IdentityKeyStore, ProtocolAddress};
use prost::Message;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn database() -> SqlitePool {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    MIGRATOR.run(&db).await.unwrap();
    db
}

#[test]
fn libsignal_identity_serialization_round_trips() {
    let mut rng = signal_rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let decoded = friendshub_core::crypto::stores::decode_identity_key_pair(&identity.serialize())
        .expect("libsignal identity key pair should deserialize from its own serialization");
    assert_eq!(decoded.serialize(), identity.serialize());
}

async fn actor_state_with_api(db: SqlitePool, api_base: &str) -> ActorState {
    let config = Config::from_json(
        &serde_json::to_vec(&serde_json::json!({
            "db_path": ":memory:",
            "api_base": api_base,
            "ws_url": "ws://127.0.0.1:1",
            "discovery": { "enabled": false },
            "log_level": "off",
            "log_format": "text"
        }))
        .unwrap(),
    )
    .unwrap();
    let http = HttpClient::new(&config).unwrap();
    ActorState::new(config, db, http)
}

async fn actor_state(db: SqlitePool) -> ActorState {
    actor_state_with_api(db, "http://127.0.0.1:1").await
}

async fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 8192];
    let (header_end, content_length) = loop {
        let count = stream.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "request closed before headers were complete");
        data.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&data[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (header_end, content_length);
        }
    };
    let request_line =
        std::str::from_utf8(&data[..data.windows(2).position(|w| w == b"\r\n").unwrap()])
            .unwrap()
            .to_string();
    let body_start = header_end + 4;
    let body_end = body_start + content_length;
    while data.len() < body_end {
        let count = stream.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "request body was truncated");
        data.extend_from_slice(&chunk[..count]);
    }
    (request_line, data[body_start..body_end].to_vec())
}

async fn send_http_response(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn device_status_counts_only_unused_kyber_one_time_keys() {
    let db = database().await;
    sqlx::query(
        "INSERT INTO identity_state (id, key_pair, registration_id, next_prekey_id) VALUES (1, ?, 7, 1)",
    )
    .bind(vec![0_u8; 65])
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO device_init_state
             (id, stage, device_name, device_id, device_number)
         VALUES (1, 'complete', 'test', 'test-device', 1)",
    )
    .execute(&db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (1, ?, 0, 'last_resort'), (2, ?, 0, 'one_time'), (3, ?, 1, 'one_time')")
        .bind(vec![1_u8])
        .bind(vec![2_u8])
        .bind(vec![3_u8])
        .execute(&db)
        .await
        .unwrap();
    let state = actor_state(db).await;

    let response: serde_json::Value = serde_json::from_slice(
        &friendshub_core::api::device_init::status(&std::sync::Arc::new(state), Vec::new())
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(response["kyber_one_time_prekeys"], 1);
}

#[tokio::test]
async fn identity_key_change_warning_failure_keeps_old_trust_record() {
    let db = database().await;
    let address = ProtocolAddress::new("peer-account".to_string(), DeviceId::new(1).unwrap());
    let mut rng = signal_rand::rng();
    let old = IdentityKeyPair::generate(&mut rng).identity_key().clone();
    let new = loop {
        let candidate = IdentityKeyPair::generate(&mut rng).identity_key().clone();
        if candidate != old {
            break candidate;
        }
    };
    let mut store = Store::new(db.clone());
    store.save_identity(&address, &old).await.unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_identity_change BEFORE INSERT ON identity_changes BEGIN SELECT RAISE(ABORT, 'injected warning persistence failure'); END",
    )
    .execute(&db)
    .await
    .unwrap();

    assert!(store.save_identity(&address, &new).await.is_err());

    let trusted = store.get_identity(&address).await.unwrap().unwrap();
    assert_eq!(trusted, old);
    let warnings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_changes")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(warnings, 0);
}

#[tokio::test]
async fn failed_device_registration_remains_retryable() {
    let db = database().await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, updated_at) VALUES (1, 'valid-for-local-mock', 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state(db.clone()).await;

    assert!(
        friendshub_core::crypto::init::initialize(&state, "desktop")
            .await
            .is_err()
    );
    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    let retry_error = friendshub_core::crypto::init::initialize(&state, "desktop")
        .await
        .unwrap_err()
        .to_string();
    assert!(!retry_error.contains("already initialized"));

    let stage: String = sqlx::query_scalar("SELECT stage FROM device_init_state WHERE id = 1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stage, "registration_pending");
}

async fn seed_legacy_identity(db: &SqlitePool, next_prekey_id: i64) -> String {
    let mut rng = signal_rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let identity_key_pub = hex::encode(identity.identity_key().serialize());
    sqlx::query(
        "INSERT INTO identity_state (id, key_pair, registration_id, next_prekey_id) VALUES (1, ?, 7, ?)",
    )
    .bind(identity.serialize().to_vec())
    .bind(next_prekey_id)
    .execute(db)
    .await
    .unwrap();
    identity_key_pub
}

fn legacy_device(identity_key_pub: String) -> identity::DeviceItem {
    identity::DeviceItem {
        id: "legacy-device".into(),
        device_number: 2,
        name: "old install".into(),
        registration_id: 7,
        identity_key_pub,
        created_at: 1,
        last_seen_at: None,
    }
}

#[tokio::test]
async fn legacy_registered_device_with_remote_prekeys_is_migrated_as_complete() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    let identity_key_pub = seed_legacy_identity(&db, 301).await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, device_number, updated_at) VALUES (1, 'mock-session', 2, 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;
    let remote = legacy_device(identity_key_pub);

    let server = tokio::spawn(async move {
        for expected_path in [
            "GET /api/v1/devices HTTP/1.1",
            "GET /api/v1/devices/me/prekeys/status HTTP/1.1",
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (request_line, _) = read_http_request(&mut stream).await;
            assert_eq!(request_line, expected_path);
            let response = match expected_path {
                "GET /api/v1/devices HTTP/1.1" => identity::DevicesResponse {
                    items: vec![remote.clone()],
                }
                .encode_to_vec(),
                _ => identity::PrekeyStatusResponse {
                    one_time_available: 42,
                    kyber_one_time_available: 21,
                    has_signed_prekey: true,
                    has_kyber_last_resort: true,
                }
                .encode_to_vec(),
            };
            send_http_response(&mut stream, "200 OK", &response).await;
        }
    });

    assert!(
        friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    let stage: Option<String> =
        sqlx::query_scalar("SELECT stage FROM device_init_state WHERE id = 1")
            .fetch_optional(&db)
            .await
            .unwrap();
    assert_eq!(stage.as_deref(), Some("complete"));
    let next_prekey_id: i64 =
        sqlx::query_scalar("SELECT next_prekey_id FROM identity_state WHERE id = 1")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        next_prekey_id, 301,
        "a complete remote install is not rotated"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn legacy_registration_response_loss_recovers_null_device_number_for_exact_match() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    let identity_key_pub = seed_legacy_identity(&db, 301).await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, updated_at) VALUES (1, 'mock-session', 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;
    let remote = legacy_device(identity_key_pub);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "GET /api/v1/devices HTTP/1.1");
        let devices = identity::DevicesResponse {
            items: vec![remote],
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &devices).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(
            request_line,
            "GET /api/v1/devices/me/prekeys/status HTTP/1.1"
        );
        let status = identity::PrekeyStatusResponse {
            one_time_available: 0,
            kyber_one_time_available: 0,
            has_signed_prekey: false,
            has_kyber_last_resort: false,
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &status).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, body) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "POST /api/v1/devices/me/prekeys HTTP/1.1");
        let upload = identity::UploadPrekeysRequest::decode(body.as_slice()).unwrap();
        assert_eq!(upload.one_time_prekeys.len(), 100);
        assert_eq!(upload.kyber_one_time_prekeys.len(), 100);
        assert!(upload.one_time_prekeys[0].id.unwrap() >= 301);
        assert!(upload.kyber_one_time_prekeys[0].id.unwrap() >= 301);
        let response = identity::UploadPrekeysResponse {
            one_time_inserted: 100,
            kyber_one_time_inserted: 100,
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &response).await;
    });

    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap(),
        "an exact server-side registration match with unpublished prekeys resumes initialization"
    );
    let initialized = friendshub_core::crypto::init::initialize(&state, "recovered desktop")
        .await
        .unwrap();
    assert_eq!(initialized.device_id, "legacy-device");
    assert_eq!(initialized.one_time_prekeys, 100);
    assert_eq!(initialized.kyber_one_time_prekeys, 100);
    let device_number: Option<i64> =
        sqlx::query_scalar("SELECT device_number FROM auth_state WHERE id = 1")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(device_number, Some(2));
    let stage: String = sqlx::query_scalar("SELECT stage FROM device_init_state WHERE id = 1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stage, "complete");
    assert!(
        friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn legacy_null_device_number_with_multiple_devices_fails_closed_before_status() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    let identity_key_pub = seed_legacy_identity(&db, 301).await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, updated_at) VALUES (1, 'mock-session', 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;
    let mut other_device = legacy_device("another-identity-key".into());
    other_device.id = "other-device".into();
    other_device.device_number = 1;
    other_device.registration_id = 12;
    let devices = identity::DevicesResponse {
        items: vec![legacy_device(identity_key_pub), other_device],
    }
    .encode_to_vec();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "GET /api/v1/devices HTTP/1.1");
        send_http_response(&mut stream, "200 OK", &devices).await;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "ambiguous session ownership must not request another device's prekey status"
        );
    });

    let error = friendshub_core::crypto::init::is_initialized(&state)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("cannot be safely recovered from 2 active devices"));
    let device_number: Option<i64> =
        sqlx::query_scalar("SELECT device_number FROM auth_state WHERE id = 1")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(device_number, None);
    let progress_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_init_state")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(progress_count, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn legacy_local_prekeys_are_not_treated_as_published_when_remote_pool_is_empty() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    let identity_key_pub = seed_legacy_identity(&db, 500).await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, device_number, updated_at) VALUES (1, 'mock-session', 2, 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    for id in 1..=100_i64 {
        sqlx::query("INSERT INTO pre_keys (prekey_id, record) VALUES (?, ?)")
            .bind(id)
            .bind(vec![id as u8])
            .execute(&db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (?, ?, 0, 'one_time')",
        )
        .bind(1000 + id)
        .bind(vec![id as u8])
        .execute(&db)
        .await
        .unwrap();
    }
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;
    let remote = legacy_device(identity_key_pub);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "GET /api/v1/devices HTTP/1.1");
        let devices = identity::DevicesResponse {
            items: vec![remote],
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &devices).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(
            request_line,
            "GET /api/v1/devices/me/prekeys/status HTTP/1.1"
        );
        let status = identity::PrekeyStatusResponse {
            one_time_available: 0,
            kyber_one_time_available: 0,
            has_signed_prekey: false,
            has_kyber_last_resort: false,
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &status).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, body) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "POST /api/v1/devices/me/prekeys HTTP/1.1");
        let upload = identity::UploadPrekeysRequest::decode(body.as_slice()).unwrap();
        let first_one_time_id = upload.one_time_prekeys[0].id.unwrap();
        let first_kyber_id = upload.kyber_one_time_prekeys[0].id.unwrap();
        let response = identity::UploadPrekeysResponse {
            one_time_inserted: upload.one_time_prekeys.len() as u64,
            kyber_one_time_inserted: upload.kyber_one_time_prekeys.len() as u64,
        }
        .encode_to_vec();
        send_http_response(&mut stream, "200 OK", &response).await;
        (
            upload.one_time_prekeys.len(),
            upload.kyber_one_time_prekeys.len(),
            first_one_time_id,
            first_kyber_id,
        )
    });

    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap(),
        "a registered device with no published prekeys is incomplete"
    );
    let result = friendshub_core::crypto::init::initialize(&state, "legacy device")
        .await
        .unwrap();
    assert_eq!(result.device_id, "legacy-device");
    assert_eq!(result.one_time_prekeys, 100);
    assert_eq!(result.kyber_one_time_prekeys, 100);
    let (otk_count, kyber_count, first_otk_id, first_kyber_id) = server.await.unwrap();
    assert_eq!(otk_count, 100);
    assert_eq!(kyber_count, 100);
    assert!(first_otk_id >= 500, "old local ids are not republished");
    assert!(first_kyber_id >= 500, "old local ids are not republished");
    assert!(
        friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn legacy_registration_failure_persists_retryable_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    let identity_key_pub = seed_legacy_identity(&db, 1).await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, device_number, updated_at) VALUES (1, 'mock-session', 2, 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, _) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "GET /api/v1/devices HTTP/1.1");
        let devices = identity::DevicesResponse { items: Vec::new() }.encode_to_vec();
        send_http_response(&mut stream, "200 OK", &devices).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (request_line, body) = read_http_request(&mut stream).await;
        assert_eq!(request_line, "POST /api/v1/devices HTTP/1.1");
        let request = identity::RegisterDeviceRequest::decode(body.as_slice()).unwrap();
        assert_eq!(request.name.as_deref(), Some("recovered desktop"));
        assert_eq!(request.registration_id, Some(7));
        assert_eq!(
            request.identity_key_pub.as_deref(),
            Some(identity_key_pub.as_str())
        );
        send_http_response(
            &mut stream,
            "503 Service Unavailable",
            b"temporarily offline",
        )
        .await;
    });

    let error = friendshub_core::crypto::init::initialize(&state, "recovered desktop")
        .await
        .unwrap_err();
    assert!(
        !error.to_string().contains("already initialized"),
        "legacy rows without registration must be allowed to retry"
    );
    let stage: Option<String> =
        sqlx::query_scalar("SELECT stage FROM device_init_state WHERE id = 1")
            .fetch_optional(&db)
            .await
            .unwrap();
    assert_eq!(stage.as_deref(), Some("registration_pending"));
    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn initialize_reuses_registered_device_and_retries_same_prekey_batch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let db = database().await;
    sqlx::query(
        "INSERT INTO auth_state (id, session_token, updated_at) VALUES (1, 'mock-session', 0)",
    )
    .execute(&db)
    .await
    .unwrap();
    let state = actor_state_with_api(db.clone(), &format!("http://{address}")).await;

    let server = tokio::spawn(async move {
        let mut registered: Option<identity::DeviceItem> = None;
        let mut prekey_uploads = Vec::new();
        for request_number in 0..5 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (request_line, body) = read_http_request(&mut stream).await;
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap();
            let path = parts.next().unwrap();
            match (method, path) {
                ("GET", "/api/v1/devices") => {
                    let response = identity::DevicesResponse {
                        items: registered.clone().into_iter().collect(),
                    }
                    .encode_to_vec();
                    send_http_response(&mut stream, "200 OK", &response).await;
                }
                ("POST", "/api/v1/devices") => {
                    let request = identity::RegisterDeviceRequest::decode(body.as_slice()).unwrap();
                    registered = Some(identity::DeviceItem {
                        id: "device-resumed".into(),
                        device_number: 3,
                        name: request.name.unwrap_or_default(),
                        registration_id: request.registration_id.unwrap_or_default(),
                        identity_key_pub: request.identity_key_pub.unwrap_or_default(),
                        created_at: 1,
                        last_seen_at: None,
                    });
                    // Model a committed registration whose response was lost.
                    send_http_response(&mut stream, "500 Internal Server Error", b"lost response")
                        .await;
                }
                ("POST", "/api/v1/devices/me/prekeys") => {
                    prekey_uploads
                        .push(identity::UploadPrekeysRequest::decode(body.as_slice()).unwrap());
                    if request_number == 3 {
                        // Model a server-side commit followed by a failed response.
                        send_http_response(
                            &mut stream,
                            "500 Internal Server Error",
                            b"lost response",
                        )
                        .await;
                    } else {
                        let response = identity::UploadPrekeysResponse {
                            one_time_inserted: 100,
                            kyber_one_time_inserted: 100,
                        }
                        .encode_to_vec();
                        send_http_response(&mut stream, "200 OK", &response).await;
                    }
                }
                _ => panic!("unexpected mock request: {request_line}"),
            }
        }
        prekey_uploads
    });

    assert!(
        friendshub_core::crypto::init::initialize(&state, "desktop")
            .await
            .is_err()
    );
    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    assert!(
        friendshub_core::crypto::init::initialize(&state, "desktop")
            .await
            .is_err()
    );
    assert!(
        !friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    let result = friendshub_core::crypto::init::initialize(&state, "renamed device")
        .await
        .unwrap();

    assert_eq!(result.device_id, "device-resumed");
    assert_eq!(result.device_number, 3);
    assert_eq!(result.one_time_prekeys, 100);
    assert_eq!(result.kyber_one_time_prekeys, 100);
    assert!(
        friendshub_core::crypto::init::is_initialized(&state)
            .await
            .unwrap()
    );
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_init_pending_prekeys")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(pending, 0);
    let device_number: i64 =
        sqlx::query_scalar("SELECT device_number FROM auth_state WHERE id = 1")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(device_number, 3);
    let uploads = server.await.unwrap();
    assert_eq!(uploads.len(), 2);
    assert_eq!(
        uploads[0], uploads[1],
        "retry must publish the same committed key batch"
    );
    assert_eq!(uploads[0].one_time_prekeys.len(), 100);
    assert_eq!(uploads[0].kyber_one_time_prekeys.len(), 100);
}
