# Events

The library produces events that a consumer reads with `fh_poll_event`.

| Return | Out buffer | Meaning |
|---|---|---|
| 0 | empty | no event within the timeout |
| 0 | JSON event | an event was returned |
| non-zero | JSON error | the poll failed (handle closed, internal error) |

## Durable vs ephemeral

An event carries `id`. If the field is present, the event is **durable**:
the library has persisted it and will not forget it until the consumer calls
`fh_ack_event(handle, id)`. If the field is absent, the event is **ephemeral**:
it existed only in memory and is gone once read.

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
| `ws_connected` | no | `{"device_number":N}` |
| `ws_disconnected` | no | `{"reason":"..."}` |
| `ws_stopped` | no | `{}` |
| `server_error` | no | `{"code":"...","message":"...","fatal":bool}` |
| `presence_updated` | no | account_id, is_online, last_seen, custom status |
| `bot_message` | no | bot_id, text, reply_to_message_id, created_at |
| `channel_post` | no | post_id, channel_id, author, text, attachments, reply |
| `webrtc_event` | no | see below |
| `envelope_received` | yes | see below |

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

## Polling pattern

1. Call `fh_poll_event(handle, 5000, &out)`.
2. Non-zero return: treat as error and back off.
3. Empty buffer: the timeout expired; loop again.
4. Otherwise parse the JSON, dispatch on `kind`, and - if `id` is present -
   call `fh_ack_event(handle, id)` once the payload has been persisted or
   otherwise handled.
5. Call `fh_buffer_free(&out)` before the next iteration.

Do not ack before the payload is safely stored. If the process dies between
ack and a successful write, the event is gone.

