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
Register an `EventHandler` with `Client::set_event_handler` before starting
the websocket. Events produced before registration are queued internally and
pushed when the handler is installed; durable events are restored after a
restart until acknowledged.

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
