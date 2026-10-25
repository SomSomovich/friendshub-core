use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use friendshub_core::api;
use friendshub_core::client::method_ids;
use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::db;
use friendshub_core::db::auth::AuthState;
use friendshub_core::proto::rest::chat;
use friendshub_core::runtime::ActorState;
use friendshub_core::transport::HttpClient;
use prost::Message;

#[path = "support/http_fixture.rs"]
mod http_fixture;

#[path = "support/keyring.rs"]
mod keyring;

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);
const CONVERSATION_ID: &str = "11111111-1111-4111-8111-111111111111";
const LOCAL_ACCOUNT_ID: &str = "22222222-2222-4222-8222-222222222222";
const PEER_ACCOUNT_ID: &str = "33333333-3333-4333-8333-333333333333";

#[tokio::test(flavor = "current_thread")]
async fn history_replay_fetches_stages_commits_and_isolates_decrypt_failure() {
    keyring::use_memory_keyring();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local REST fixture");
    listener
        .set_nonblocking(true)
        .expect("fixture listener should be nonblocking");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || -> io::Result<()> {
        for (index, envelope_type) in [99, 2].into_iter().enumerate() {
            let (mut stream, request) = accept_request(&listener)?;
            assert_eq!(request.method, "GET");
            assert!(request.body.is_empty());
            assert!(request.target.starts_with(&format!(
                "/api/v1/conversations/{CONVERSATION_ID}/envelopes"
            )));
            assert_eq!(
                request.header("authorization"),
                Some("Bearer replay-session")
            );
            assert_eq!(request.header("accept"), Some("application/x-protobuf"));
            let response = chat::EnvelopeHistoryResponse {
                items: vec![chat::EnvelopeHistoryItem {
                    envelope_id: format!("{index:08x}-1111-4111-8111-111111111111"),
                    sender_account_id: PEER_ACCOUNT_ID.into(),
                    sender_device_number: 7,
                    recipient_device_number: 4,
                    envelope_type,
                    is_prekey_message: false,
                    ciphertext: "00".into(),
                    client_timestamp: 1_700_000_000,
                    server_timestamp: 1_700_000_001 + index as i64,
                    conversation_id: Some(CONVERSATION_ID.into()),
                }],
            }
            .encode_to_vec();
            write_protobuf_response(&mut stream, &response)?;
        }
        Ok(())
    });

    let database_path = unique_database_path();
    let config = Config {
        db_path: database_path.clone(),
        api_base: format!("http://{address}"),
        ws_url: format!("ws://{address}/ws"),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    };
    let database = db::pool::open(&database_path)
        .await
        .expect("open encrypted test database");
    db::migrations::MIGRATOR
        .run(&database)
        .await
        .expect("apply schema migrations");
    db::auth::store(
        &database,
        &AuthState {
            account_id: Some(LOCAL_ACCOUNT_ID.into()),
            session_token: Some("replay-session".into()),
            device_number: Some(4),
            totp_enabled: Some(0),
            ..AuthState::default()
        },
    )
    .await
    .expect("persist authenticated session");
    sqlx::query(
        "INSERT INTO sessions (account_id, device_number, record, updated_at) VALUES (?, 7, X'010203', 1)",
    )
    .bind(PEER_ACCOUNT_ID)
    .execute(&database)
    .await
    .expect("seed an unchanged Signal session");
    let http = HttpClient::new(&config).expect("build HTTP client");
    let state = Arc::new(ActorState::new(config.clone(), database.clone(), http));

    let request = serde_json::json!({
        "conversationId": CONVERSATION_ID,
        "limit": 200,
        "knownEnvelopeIds": ["44444444-4444-4444-8444-444444444444"],
        "knownMessageIds": []
    });
    let page = api::dispatch(
        state.clone(),
        method_ids::HISTORY_REPLAY_BEGIN_CONVERSATION_PAGE,
        serde_json::to_vec(&request).unwrap(),
    )
    .await
    .expect("unknown envelope types should produce a replay page");
    let page: serde_json::Value = serde_json::from_slice(&page).unwrap();
    assert_eq!(page["ignored"], 1);
    assert_eq!(page["cursor"]["before"], 1_700_000_001);
    assert_eq!(
        page["cursor"]["beforeId"],
        "00000000-1111-4111-8111-111111111111"
    );
    assert_eq!(page["hasOlder"], false);
    assert_eq!(page["processedEnvelopeIds"], serde_json::json!([]));
    assert_eq!(page["rollback"]["messageIds"], serde_json::json!([]));
    let replay_token = page["replayToken"].as_str().expect("replay token");

    let token_payload = serde_json::json!({ "replayToken": replay_token });
    drop(state);

    let reopened_database = db::pool::open(&database_path)
        .await
        .expect("reopen encrypted test database with staged page");
    db::migrations::MIGRATOR
        .run(&reopened_database)
        .await
        .expect("load current schema after restart");
    let reopened_http = HttpClient::new(&config).expect("rebuild HTTP client after restart");
    let reopened_state = Arc::new(ActorState::new(
        config.clone(),
        reopened_database.clone(),
        reopened_http,
    ));
    let committed = api::dispatch(
        reopened_state.clone(),
        method_ids::HISTORY_REPLAY_COMMIT,
        serde_json::to_vec(&token_payload).unwrap(),
    )
    .await
    .expect("commit staged history page");
    let committed: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(committed["committed"], true);
    assert_eq!(committed["conflict"], false);

    drop(reopened_state);
    reopened_database.close().await;

    let receipt_database = db::pool::open(&database_path)
        .await
        .expect("reopen encrypted test database with commit receipt");
    db::migrations::MIGRATOR
        .run(&receipt_database)
        .await
        .expect("load current schema for receipt retry");
    let receipt_http = HttpClient::new(&config).expect("rebuild HTTP client for receipt retry");
    let receipt_state = Arc::new(ActorState::new(
        config.clone(),
        receipt_database.clone(),
        receipt_http,
    ));
    let repeated = api::dispatch(
        receipt_state.clone(),
        method_ids::HISTORY_REPLAY_COMMIT,
        serde_json::to_vec(&token_payload).unwrap(),
    )
    .await
    .expect("retry a commit whose response may have been lost");
    let repeated: serde_json::Value = serde_json::from_slice(&repeated).unwrap();
    assert_eq!(repeated["committed"], true);
    assert_eq!(repeated["alreadyCommitted"], true);

    let failure = api::dispatch(
        receipt_state.clone(),
        method_ids::HISTORY_REPLAY_BEGIN_CONVERSATION_PAGE,
        serde_json::to_vec(&request).unwrap(),
    )
    .await;
    assert!(
        failure.is_err(),
        "invalid Signal ciphertext must reject the page"
    );
    let session: Vec<u8> =
        sqlx::query_scalar("SELECT record FROM sessions WHERE account_id=? AND device_number=7")
            .bind(PEER_ACCOUNT_ID)
            .fetch_one(&database)
            .await
            .expect("live Signal session remains present");
    assert_eq!(session, [1, 2, 3]);

    drop(receipt_state);
    receipt_database.close().await;
    database.close().await;
    server
        .join()
        .expect("fixture thread should not panic")
        .expect("serve history replay pages");
    remove_database_files(&database_path);
}

fn accept_request(
    listener: &TcpListener,
) -> io::Result<(TcpStream, http_fixture::CapturedRequest)> {
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    };
    let request = http_fixture::read_request(&mut stream)?;
    Ok((stream, request))
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
        "friendshub-history-replay-{}-{timestamp}-{id}.sqlite",
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
