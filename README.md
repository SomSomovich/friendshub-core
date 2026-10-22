# friendshub-core

Core client library for FriendsHub.

Everything between the UI and the server: transport (HTTP + WS), auth,
Signal end-to-end encryption, protobuf framing over the WebSocket, S3
attachment handling, and WebRTC.

The library builds as an `rlib`, `cdylib`, and `staticlib`. Rust consumers can
use the safe [`Client`] facade and type-specific [`EventHandler`] callbacks;
other languages can use the C ABI in `include/friendshub_core.h`.

```rust,no_run
use friendshub_core::{Client, client::method_ids};
use serde_json::Value;

let config = friendshub_core::config::Config::from_json(br#"{"db_path":"/tmp/friendshub-core.db"}"#)?;
let client = Client::open(config)?;
let version: Value = client.call_json(method_ids::VERSION, &serde_json::json!({}))?;
# Ok::<(), friendshub_core::error::Error>(())
```

Incoming events are pushed to a registered handler on a library-owned worker.
Without a handler, callers can continue using `Client::poll_event` or
`fh_poll_event`.

## License

AGPL-3.0-only.

## Building

cargo build --release

## C header

cbindgen --config cbindgen.toml --crate friendshub-core --output include/friendshub_core.h
