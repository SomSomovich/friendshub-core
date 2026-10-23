# Events

The library pushes events to a registered callback handler on a dedicated
worker thread. Rust consumers register an `EventHandler` with
`Client::set_event_handler`; C consumers register individual slots through
`fh_set_event_callbacks`. Each event kind has its own callback, and callbacks
are the only event delivery interface. Events produced before a handler is
installed, or while it is cleared, wait in the library's in-memory delivery
backlog and are pushed when the next handler is registered. Durable events
left unacknowledged in SQLite are restored when the client opens, so the next
handler registration pushes them again.

Callbacks run serially on the library-owned worker, not on the websocket or
actor thread. A callback may call back into the client. Rust event references
and C `FhEventView.event_json` bytes are borrowed for the callback duration;
the library allocates and releases the payload. C callers keep `user_data`
valid until callbacks have drained after unregister/destroy.

During callback activation, new events are queued behind earlier events until
the library has transferred the backlog to the callback worker. This keeps
event order stable. Ephemeral events waiting in memory are lost if the process
exits before they are pushed; durable events are replayed from SQLite.

## Durable vs ephemeral

An event carries `id`. If the field is present, the event is **durable**:
the library has persisted it and will not forget it until the consumer calls
`fh_ack_event(handle, id)`. If the field is absent, the event is **ephemeral**:
it exists only in memory and is gone after callback delivery.

### Why durable events exist

The Signal ratchet is irreversible: once an envelope is decrypted, the key
that produced it is gone. If the process died between decrypt and the
consumer persisting the plaintext, the message would be lost forever.
Durable events close that gap: the library writes the decrypted payload to
its own database before handing it to the consumer, and only forgets it on
ack.

A consumer that crashes before acking gets the same event again after a
restart. The library does not re-decrypt: the plaintext is already stored.

## Event kinds

| Kind | Durable | Payload |
|---|---|---|
| `ws_connected` | no | session/account IDs, device number, server timestamp and negotiated protocol version |
| `ws_disconnected` | no | `{"reason":"...","final":bool}`; `final` is false while reconnecting |
| `ws_stopped` | no | `{}` |
| `envelope_received` | yes | decrypted and persisted envelope; see below |
| `receipt` | no | delivery receipt |
| `server_error` | no | `{"code":"...","message":"...","fatal":bool,"reference":string|null}` |
| `fatal_error` callback | no | same `server_error` event, additionally sent to `on_fatal_error` when fatal except `flood` |
| `typing` | no | conversation, account, and typing state |
| `read_receipt` | no | conversation and read marker |
| `conversation_updated` | no | updated conversation metadata |
| `history_request` | no | requested conversation history cursor |
| `nudge` | no | incoming nudge |
| `nudge_result` | no | response to an outgoing nudge |
| `conversation_expired` | no | conversation expiration notice |
| `scheduled_created` | no | scheduled envelope created |
| `scheduled_cancelled` | no | scheduled envelope cancelled |
| `folders_updated` | no | folder state changed |
| `presence_updated` | no | account_id, is_online, last_seen, custom status |
| `bot_message` | no | bot_id, text, reply_to_message_id, created_at |
| `bot_message_edited` | no | edited bot message |
| `bot_message_deleted` | no | deleted bot message |
| `bot_callback_answered` | no | callback query ID, optional text/message ID and `show_alert` |
| `channel_post` | no | post_id, channel_id, author, text, attachments, reply |
| `poll_updated` | no | poll data changed |
| `poll_deleted` | no | poll removed |
| `call_signal` | no | call IDs, peer device, signal kind and base64 payload |
| `identity_changed` | no | peer identity key changed |
| `webrtc_event` | no | see below |

WebRTC callbacks have distinct methods for each subtype (`ice_candidate`,
state changes, data-channel open/close/message, remote track, and close). The
C ABI exposes matching `on_webrtc_*` slots.

### `envelope_received`

The base payload carries the envelope as it arrived. On top of that the
library adds the results of its own processing:

```json
{
  "id": 42,
  "kind": "envelope_received",
  "payload": {
    "envelope_id": "uuid",
    "sender_account_id": "uuid",
    "sender_device_number": 2,
    "recipient_account_id": "uuid",
    "recipient_device_number": 1,
    "envelope_type": 1,
    "is_prekey_message": true,
    "ciphertext": "hex",
    "client_timestamp": 1234567890,
    "conversation_id": "uuid or null",
    "sender_is_bot": false,

    "plaintext_hex": "hex or null",
    "group": false,
    "distribution": false,
    "decrypt_error": "message or absent"
  }
}
```

| Field | Meaning |
|---|---|
| `plaintext_hex` | the decrypted bytes, hex-encoded. Absent or null when the library could not decrypt. |
| `group` | true when the ciphertext was a SenderKeyMessage and was decrypted through the group path |
| `distribution` | true when the envelope was a sender key distribution. No plaintext: the distribution has been stored and the payload only confirms it. |
| `decrypt_error` | when present, why decryption failed. The ciphertext is still delivered. |

**Acking `envelope_received`** does two things: the durable row is removed,
and a receipt is sent to the sender over the websocket.
The receipt is best effort. If it cannot be sent, the local row is still
released because the consumer has already acknowledged handling the payload;
the server may redeliver the envelope, so consumers should deduplicate by
`envelope_id`.

### `webrtc_event`

The `event` field discriminates:

- `ice_candidate` - a local candidate, to be forwarded to the peer through
  the signaling channel. `candidate` is the W3C `RTCIceCandidateInit` shape.
- `signaling_state_changed`, `ice_connection_state_changed`,
  `ice_gathering_state_changed`, `connection_state_changed` - state strings.
- `data_channel_opened`, `data_channel_closed` - label plus call_id.
- `data_channel_message` - label plus base64 data and a flag for text vs binary.
- `track_received` - a remote media track arrived.
- `closed` - the peer connection was closed.

## Callback pattern

Register the Rust handler or C callback table before starting the websocket.
For C, `event_id == 0` marks an ephemeral event; a nonzero ID must be passed
to `fh_ack_event` after the application has safely handled the payload. The
callback's JSON bytes must not be retained after it returns. Clearing the
handler pauses delivery; registering another handler pushes queued events in
order.

Do not ack before the payload is safely stored. If the process dies between
ack and a successful write, the event is gone.

