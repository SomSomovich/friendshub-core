# FriendsHub browser binding

This crate exposes the shared REST protobuf route codec, browser WebSocket
push client, and browser WebRTC media manager through `wasm-bindgen`.
JavaScript passes ordinary WEB camelCase objects. The binding validates
inputs, copies request data into Rust-owned protobuf messages, and creates
fresh JavaScript event values for callbacks.

## BrowserRestClient

`new BrowserRestClient(apiBase)` accepts the API origin or `/api/v1` URL used
by WEB. `request(method, path, body, bearer, signal, responseType)` handles
registered protobuf routes and the existing JSON exceptions. Use
`request_raw(method, path, body, contentType, bearer, signal, responseType)`
for registered binary uploads; a browser `Blob` can be passed through as the
body without first copying the complete file into Rust memory. Set the
optional device header with `set_device_number(number)` and adjust the total
Fetch deadline with `set_timeout_ms(milliseconds)`. Pass `null` for optional
arguments. `responseType` is `"json"` by default or `"bytes"` for binary
responses. First-party API errors reject with an object containing `code`,
`status`, `message`, and `body`.

Bearer credentials and the device header are only attached to requests for the
configured API origin; absolute storage URLs do not receive them. Requests use
the same route codec as the native library, including protobuf, JSON, and raw
upload/download exceptions.

## BrowserPushClient

```js
const push = new BrowserPushClient('wss://api.example.test/ws')
push.set_on_delivery((delivery) => {
  // delivery.envelopes is the WEB fh.EnvelopeDelivery shape.
})
await push.start(sessionToken, deviceNumber)
```

`new BrowserPushClient(url)` accepts `ws://`, `wss://`, `http://`, or
`https://` URLs. HTTP schemes are mapped to WS schemes. Relative paths resolve
against the current page URL.

`start(sessionToken, deviceNumber)` sends a binary protobuf `ClientHello` with
the WEB identity (`friendshub-web` version `0.1.0`, protocol `0.1.0`). It
resolves with the first `ServerHello` object and rejects when the initial
connection fails. Initial failures do not reconnect. After a successful hello,
connection loss reconnects after 1, 2, 4, 8, 16, then 30 seconds; a successful
hello resets that delay. The server hello deadline is 10 seconds after open,
the overall connect deadline is 30 seconds, and keepalive pings are sent every
30 seconds.

Each server event handled by the WEB client has its own callback setter. The
callback receives that protobuf submessage as a camelCase JavaScript object.
Protobuf `bytes` fields are `Uint8Array`; `int64` and `uint64` fields are plain
JavaScript numbers, as in the WEB client's `toPlainNumber` conversion. Optional
fields are `null` when absent. The event callbacks are:

`set_on_hello`, `set_on_delivery`, `set_on_receipt`, `set_on_pong`,
`set_on_server_error`, `set_on_presence`, `set_on_bot_message`,
`set_on_channel_post`, `set_on_typing`, `set_on_read_receipt`,
`set_on_conversation_updated`, `set_on_history_request_relay`, `set_on_nudge`,
`set_on_nudge_result`, `set_on_conversation_expired`,
`set_on_scheduled_created`, `set_on_scheduled_cancelled`,
`set_on_folders_updated`, `set_on_bot_message_edited`,
`set_on_bot_message_deleted`, `set_on_bot_callback_answered`,
`set_on_poll_updated`, and `set_on_poll_deleted`. WEB does not dispatch the
plaintext `ServerFrame.callSignal` event, so this binding ignores it; call
signaling is carried inside Signal-encrypted envelopes.

Lifecycle and failure callbacks are separate: `set_on_connected` receives the
ServerHello shape; `set_on_disconnected` receives `{ reason, final }`;
`set_on_stopped` receives `{ reason }`; transport, protocol, fatal-server, and
callback failures go to `set_on_transport_error`, `set_on_protocol_error`,
`set_on_fatal_error`, and `set_on_callback_error` respectively. Error objects
contain `code` and `message` fields.

Outgoing methods are:

- `upload_envelopes(envelopes)` accepts an array of WEB camelCase Envelope
  objects: `envelopeId`, `senderAccountId`, and `recipientAccountId` are UUID
  strings; `senderDeviceNumber` and `recipientDeviceNumber` are non-zero u32
  numbers; `envelopeType` is 1–15 except 8; `isPrekeyMessage` and `senderIsBot`
  are booleans; `ciphertext` is hex and at most 64 KiB; `clientTimestamp` is a
  safe integer; `conversationId` is a UUID string or `null`; optional `sendAt`
  is a safe integer and defaults to 0. Frames are split at 128 envelopes and
  the 256 KiB protobuf limit.
- `ack_envelopes(envelopeIds)` accepts UUID strings and sends acknowledgements
  in groups of 128.
- `send_typing(conversationId)` and
  `send_nudge(conversationId, targetAccountId)` accept UUID strings.
- `request_history(targetDeviceNumber, conversationIds)` accepts a non-zero
  u32 device number and at most 200 conversation UUID strings.
- Call signaling follows the current WEB contract and belongs in Signal-
  encrypted envelopes; this binding does not send or dispatch plaintext
  `CallSignal` frames.

`close()` stops reconnecting and resolves when the socket closes or after the
two-second close deadline. Dropping the Rust client detaches listeners, cancels
all timers and closes its socket. All listener and timer closures are deferred
for release if they are currently executing.

## BrowserRtcManager

`BrowserRtcManager` owns browser peer connections and local/remote tracks.
Register callbacks with `set_on_local_stream`, `set_on_remote_stream`,
`set_on_ice_candidate`, `set_on_connected`, `set_on_failed`, and
`set_on_remote_video`. Each callback is specific to that event; stream
callbacks receive `(call_id, stream)`, ICE receives `(call_id, candidate)`,
connected receives `call_id`, failed receives `(call_id, detail)`, and remote
video receives `call_id`.

`create_offer(call_id, iceServers, withVideo)` acquires local media and returns
the local SDP. `accept_offer(call_id, iceServers, remoteSdp)` creates and
returns an answer; `accept_answer(call_id, remoteSdp)` applies an answer.
Exchange local ICE candidates from `set_on_ice_candidate` with
`add_remote_candidate(call_id, candidate)`. Candidates received before their
peer connection or remote description are queued and applied in arrival order.
Use `set_audio_enabled`, `set_video_enabled`, `switch_camera`,
`local_stream`, `remote_stream`, and `close_call` for media controls and
lifecycle. Dropping the manager closes remaining calls and releases tracks.

The application still handles Signal encryption and carries call signaling
inside encrypted envelopes, as the current WEB client does. Browser UI,
IndexedDB/outbox, service workers, and notification permission/delivery remain
application responsibilities.

## Checks

Run host-side validation with:

```sh
cargo test -p friendshub-core-wasm --lib
```

Compile for a browser with `wasm32-unknown-unknown` installed:

```sh
cargo check -p friendshub-core-wasm --target wasm32-unknown-unknown
```

The repository-level release helper also provides `./scripts/build.sh wasm`
and `./scripts/build.sh all`; see the root README for toolchain requirements.
