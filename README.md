# friendshub-core

Core client library for FriendsHub.

Everything between the UI and the server: transport (HTTP + WS), auth,
Signal end-to-end encryption, protobuf framing over the WebSocket, S3
attachment handling, and WebRTC.

The library is a cdylib + staticlib with a single, flat C ABI. Any
language with C FFI support can drive it.

## License

AGPL-3.0-only.

## Building

cargo build --release

## C header

cbindgen --config cbindgen.toml --crate friendshub-core --output include/friendshub_core.h
