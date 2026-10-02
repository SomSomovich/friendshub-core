//! Integration smoke tests. Nothing here touches the network; the goal is to
//! prove the crate links as a library, the public types are reachable, and
//! the pieces that can be exercised in isolation behave.

use friendshub_core::config::Config;

#[test]
fn config_parses_minimal_json() {
    let raw = br#"{"api_base":"https://example.com","ws_url":"wss://example.com/ws","db_path":"/tmp/x.db"}"#;
    let cfg = Config::from_json(raw).expect("config must parse");
    assert_eq!(cfg.api_base, "https://example.com");
    assert_eq!(cfg.ws_url, "wss://example.com/ws");
}

#[test]
fn config_rejects_missing_required_fields() {
    let raw = br#"{"api_base":"","ws_url":"wss://x/ws","db_path":"/tmp/x.db"}"#;
    assert!(Config::from_json(raw).is_err());
}

#[test]
fn config_rejects_invalid_json() {
    assert!(Config::from_json(b"not json").is_err());
}

#[test]
fn abi_version_is_one() {
    assert_eq!(friendshub_core::ffi::ABI_VERSION, 1);
}

#[test]
fn error_json_is_valid_json() {
    let e = friendshub_core::error::Error::Config("oops".into());
    let s = e.to_json();
    let v: serde_json::Value = serde_json::from_str(&s).expect("error body must be json");
    assert_eq!(v["code"], "config");
    assert!(v["message"].as_str().unwrap().contains("oops"));
}
