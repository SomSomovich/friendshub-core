# FriendsHub browser binding

This crate exposes the WEB REST operations, protobuf browser WebSocket push,
Signal Protocol operations, and browser WebRTC/call orchestration through
`wasm-bindgen`. JavaScript passes WEB camelCase objects. The binding validates
inputs, converts REST requests to protobuf in Rust, owns Signal state in Rust,
and creates fresh JavaScript event values for callbacks. UI, IndexedDB,
service workers, and notification permission/delivery remain in WEB.

## BrowserApi

`new BrowserApi(apiBase)` exposes named operations corresponding to the direct
REST calls in `friendshubWEB/src/api`. It covers 183 exported operations,
including session/device management, conversations, attachments, groups,
channels, bots, profile/search, calls, WebRTC ICE server discovery, and the
root health and Prometheus metrics endpoints. `getHealth()` returns JSON;
`getMetrics()` returns Prometheus text. Pass the same camelCase fields used by
WEB; route construction, query aliases, protobuf conversion, binary uploads,
idempotency headers, and device-header policy are handled by the binding.

```js
const api = new BrowserApi('https://api.example.test/api/v1')
const session = await api.login({ fhNumber, password, deviceNumber })
api.setSession(session.sessionToken, session.deviceNumber)
const account = await api.getMe()
```

Unauthenticated operations do not receive session credentials or a device
number. Absolute presigned storage URLs never receive bearer, device, or
operation-specific headers, even when they share the API origin. The lower-
level `BrowserRestClient` remains available for custom routes and binary
response handling.

## BrowserRestClient

`new BrowserRestClient(apiBase)` accepts the API origin or `/api/v1` URL used
by WEB. `request(method, path, body, bearer, signal, responseType)` handles
registered protobuf routes, JSON endpoints, and Prometheus metrics. Use
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

`start(sessionToken, deviceNumber, signal?)` sends a binary protobuf
`ClientHello` with the WEB identity (`friendshub-web` version `0.1.0`, protocol
`0.1.0`). It resolves with the first normalized connected event. Transient
initial connection failures are retried after 1, 2, 4, 8, 16, then 30 seconds;
the 30-second delay remains capped, and a successful `ServerHello` resets the
backoff. A fatal server error, `close()`, dropping the client, or an aborted
optional `AbortSignal` stops retries and rejects a still-pending start. The
server hello deadline is 10 seconds after open, the overall connect deadline is
30 seconds per attempt, and keepalive pings are sent every 30 seconds.

Each server event handled by the WEB client has its own callback setter. The
callback receives a normalized camelCase object matching the WEB event layer,
not a raw protobuf submessage. UUID byte fields are lowercase UUID strings;
envelope ciphertext is lowercase hex; poll `encryptedMeta` is base64. Empty
optional envelope conversation IDs become `null`. `int64` and `uint64` values
are plain JavaScript numbers. Optional fields are `null` when absent. The
`hello` and `connected` callbacks receive `{ sessionId, accountId, deviceNumber,
serverTimestamp }`; protocol version fields stay internal. Delivery receives
`{ envelopes }`, where each envelope uses the WEB camelCase keys and normalized
UUID/ciphertext values. Receipt IDs are UUID strings, with server timestamps in
the matching order. `set_on_pong` receives the echoed `clientTimestamp` as a
number, matching the WEB transport handler. A malformed envelope or receipt ID
is skipped individually and reported through `set_on_protocol_error`;
malformed UUIDs in other events cause that event to be skipped and reported
there. The event callbacks are:

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

Lifecycle and failure callbacks are separate: `set_on_disconnected` receives
`{ reason, final }`; `set_on_stopped` receives `{ reason }`;
`set_on_server_error` receives `{ code, message, fatal, reference }`, with
blank references normalized to `null`; `set_on_fatal_error` receives
`{ code, message }`. Transport, protocol, and callback failures go to
`set_on_transport_error`, `set_on_protocol_error`, and
`set_on_callback_error` respectively. Diagnostic error objects contain `code`
and `message` fields.

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

## Signal Protocol

The crate exports WEB's Signal operations for identity and prekey management,
session establishment, pairwise encrypt/decrypt, sender-key group messages,
identity-change tracking, and snapshot/restore. `BrowserApi.encryptForDevice`
combines the session check, authenticated prekey-bundle request, session setup,
and pairwise encryption for one peer device. `BrowserApi.buildMessagePayload`
constructs the established WEB message payload contract. Both use the same
in-memory Rust Signal store exposed by the low-level operations. Persist
`snapshot()` through WEB's existing IndexedDB layer and call `restore()` on
startup; call `reset()` to release one account's Rust-side state. No Signal
private key or store buffer needs to be freed by JavaScript.

Attachment key generation and chunk sealing/opening use the core's shared
ChaCha20-Poly1305 implementation. The browser binding keeps the existing JSON
key shape and `Uint8Array` chunk boundary.

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

`BrowserCallManager` coordinates one active call, ICE-server retrieval, SDP
offer/answer ordering, encrypted-envelope signal sends, ICE buffering, and
call end/failure callbacks. Its adapters connect the manager to the existing
REST, Signal, and push objects; the application supplies those dependencies,
not the call-state machine. Use `set_finished_incoming_check` to connect WEB's
IndexedDB-backed duplicate-call check, and persist ended incoming calls from
`set_on_call_ended`. Call signaling uses Signal-encrypted envelope types 10–14
and never plaintext `CallSignal` frames.

Browser UI, IndexedDB/outbox persistence, service workers, and notification
permission/delivery remain application responsibilities.

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
