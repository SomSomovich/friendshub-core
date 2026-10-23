# friendshub-core

Core client library for FriendsHub.

Everything between the UI and the server: transport (HTTP + WS), auth,
Signal end-to-end encryption, protobuf framing over the WebSocket, S3
attachment handling, and WebRTC.

The library builds as an `rlib`, `cdylib`, and `staticlib`. Rust consumers can
use the safe [`Client`] facade and type-specific [`EventHandler`] callbacks;
other languages can use the C ABI in `include/friendshub_core.h`. REST requests
use the shared protobuf codec. Push events are delivered through registered
callbacks, with durable events acknowledged explicitly after handling.

```rust,no_run
use friendshub_core::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct LoginRequest {
    fh_number: String,
    password: String,
    device_number: u32,
}

#[derive(Deserialize)]
struct LoginResponse {
    session_token: Option<String>,
}

let config = friendshub_core::config::Config::from_json(br#"{"db_path":"/tmp/friendshub-core.db"}"#)?;
let client = Client::open(config)?;
let login: LoginResponse = client.auth_login(&LoginRequest {
    fh_number: "FH-123456".into(),
    password: "secret".into(),
    device_number: 1,
})?;
let _account: serde_json::Value = client.auth_me()?;
# Ok::<(), friendshub_core::error::Error>(())
```

The typed facade exposes named methods for the REST, WebSocket, and RTC
dispatcher operations; request and response types are application-defined
Serde types. The lower-level `call_json` and `call_bytes` methods remain
available for custom or newly added operations.

Incoming events are pushed to a registered handler on a library-owned worker.
Register an `EventHandler` with `Client::set_event_handler` before starting
the websocket. Events produced before registration are queued internally and
pushed when the handler is installed; durable events are restored after a
restart until acknowledged with `Client::ack_event`. There is no public event
pull/next-event API.

The C ABI also uses callbacks for results: the response bytes are borrowed only
for the duration of the callback, then released by the library. C callers do
not free library-owned result buffers.

## License

AGPL-3.0-only.

## Building

The default command builds the native core only:

```sh
cargo build --release
```

The repository workspace keeps `friendshub-core` as its default member, so
this command does not try to build the browser binding.

The helper script provides explicit release builds:

```sh
./scripts/build.sh native  # Native release; Apple targets use cargo-zigbuild
./scripts/build.sh wasm    # Browser-ready wasm-bindgen package
./scripts/build.sh all     # Native first, then browser WASM
```

By default the native helper targets the host triple reported by `rustc`;
override it with `NATIVE_TARGET` to cross-compile. Apple targets use
`cargo-zigbuild` and require Zig (`cargo install cargo-zigbuild`); all other
targets use ordinary `cargo build --release`. Install the corresponding Rust
target with `rustup target add` before cross-compiling.

For the browser binding, install `wasm-pack` (for example,
`cargo install wasm-pack`) and the Rust target with
`rustup target add wasm32-unknown-unknown`. The WASM command runs
`wasm-pack build bindings/wasm --target web --release`, so it compiles the
binding and generates the browser ES module glue and package metadata. The
ready-to-import package is written to `target/wasm-browser/`. `all` runs this
step only after the native `cargo zigbuild` release succeeds.

## C header

cbindgen --config cbindgen.toml --crate friendshub-core --output include/friendshub_core.h
