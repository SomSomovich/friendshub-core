# FriendsHub Core - C ABI reference

Everything a consumer needs: the eight entry points, the JSON shape of a
configuration, the full method id table, and worked examples.

## Entry points

```c
uint32_t fh_abi_version(void);
const char* fh_abi_string(void);

int32_t fh_init(
    const uint8_t* config_json, size_t config_len,
    FhHandle** out_handle, FhBuffer* out);

void fh_destroy(FhHandle* handle);

int32_t fh_call(
    FhHandle* handle, uint32_t method_id,
    const uint8_t* req, size_t req_len, FhBuffer* out);

int32_t fh_poll_event(
    FhHandle* handle, uint32_t timeout_ms, FhBuffer* out);

int32_t fh_ack_event(FhHandle* handle, uint64_t event_id);

void fh_buffer_free(FhBuffer* buf);
```

Every function returns `int32_t`: 0 on success, non-zero on failure. On
failure the out buffer carries a JSON `{ "code": "...", "message": "..." }`.
On success it carries the method-specific JSON response.

Every successful call that fills an out buffer must be followed by
`fh_buffer_free`. Forgetting this leaks one Vec per call.

## Configuration

`fh_init` takes a JSON object:

```json
{
  "api_base": "https://api.fh.somuch-system.su",
  "ws_url":   "wss://api.fh.somuch-system.su/ws",
  "db_path":  "/home/user/.friendshub/core.db",
  "log_level": "info"
}
```

`db_path` is created if missing; its parent directory must exist. One handle
owns one account: separate accounts get separate handles and separate DBs.

## Method ID table

IDs are grouped by namespace. New methods are added at the end of a range,
so existing IDs never move.

| Range | Area |
|---|---|
| `0x0000_xxxx` | service (ping, version, poll_event, ack_event) |
| `0x0001_xxxx` | auth |
| `0x0002_xxxx` | contacts, blocks |
| `0x0003_xxxx` | conversations |
| `0x0004_xxxx` | messages and crypto |
| `0x0005_xxxx` | devices, prekeys |
| `0x0006_xxxx` | attachments |
| `0x0007_xxxx` | avatars |
| `0x0008_xxxx` | bots |
| `0x0009_xxxx` | channels and channel posts |
| `0x000A_xxxx` | groups and group messaging |
| `0x000B_xxxx` | invites |
| `0x000C_xxxx` | call history |
| `0x000D_xxxx` | profile, presence |
| `0x000E_xxxx` | account deletion |
| `0x000F_xxxx` | sessions |
| `0x0010_xxxx` | handles |
| `0x0011_xxxx` | TURN credentials |
| `0x0012_xxxx` | WebRTC calls |
| `0x00FF_xxxx` | websocket lifecycle |

### Service

| ID | Request | Response |
|---|---|---|
| `0x0000_0001` | (empty) | `{"pong":true}` |
| `0x0000_0002` | (empty) | server version, urls, ws state |
| `0x0000_0003` | (usually via fh_poll_event) | next event or empty |
| `0x0000_0004` | `{"event_id": N}` | `{"acked":true}` |

### Auth

| ID | Request | Notes |
|---|---|---|
| `0x0001_0001` | `{"password":"..."}` | register, no auth |
| `0x0001_0002` | `{"fh_number":"...","password":"...","device_number":1}` | login |
| `0x0001_0003` | `{"challenge_token":"...","code":"...","device_number":1}` | 2FA login |
| `0x0001_0004` | (empty) | logout, clears local auth |
| `0x0001_0005` | (empty) | current profile |

### Device initialization (required once after first login)

| ID | Request | Notes |
|---|---|---|
| `0x0005_0004` | `{"name":"Desktop"}` | generate identity, register device, upload 100 prekeys |
| `0x0005_0005` | (empty) | status: initialized?, prekey counts |
| `0x0005_0015` | (empty) | top up prekeys if the pool is low |

### Websocket

| ID | Request | Notes |
|---|---|---|
| `0x00FF_0001` | (empty) | start the connect loop |
| `0x00FF_0002` | (empty) | stop the loop |
| `0x00FF_0003` | envelope JSON | send one envelope |

### Messages (Signal Protocol)

| ID | Request | Notes |
|---|---|---|
| `0x0004_0001` | `{"recipient_account_id":"...","device_number":N,"bundle":{...}}` | establish a session explicitly |
| `0x0004_0002` | `{"recipient_account_id":"...","device_number":N,"plaintext_hex":"..."}` | low-level single-device encrypt |
| `0x0004_0003` | envelope JSON | decrypt a raw envelope |
| `0x0004_0004` | see below | high-level send (multi-device + sync) |

`0x0004_0004` request:

```json
{
  "recipient_account_id": "uuid",
  "plaintext_hex": "68656c6c6f",
  "conversation_id": "uuid",
  "device_number": 1,
  "refresh_devices": false,
  "sync": true
}
```

When `device_number` is present the message goes only to that device. When
absent it goes to every active device of the recipient. When `sync` is true
(default) a copy is also sent to the caller's other devices under
`ENVELOPE_TYPE_SYNC`, so the conversation stays in step across devices.

Response:

```json
{
  "envelopes": [
    { "device_number": 1, "envelope_id": "uuid", "is_prekey_message": true, "ciphertext_len": 248 }
  ],
  "device_errors": [],
  "sync_envelopes": [
    { "device_number": 2, "envelope_id": "uuid", "is_prekey_message": true, "ciphertext_len": 251 }
  ],
  "sync_errors": []
}
```

### Group messaging

Group messages use Sender Keys: one encryption per outgoing message, and the
same ciphertext is broadcast to every member device. That is what makes a
group message cost O(1) in encryption, not O(members).

| ID | Request | Notes |
|---|---|---|
| `0x000A_0020` | `{"conversation_id":"uuid","rotate":false}` | generate or rotate this device's sender key, distribute to all members |
| `0x000A_0021` | `{"conversation_id":"uuid","plaintext_hex":"..."}` | encrypt once for the group, fan out |

Both return `{ "envelopes": [...], "device_errors": [...] }` (or with
`distribution_id` / `ciphertext_len` prefixes). Per-device failures do not
abort the batch.

See `group-calls.md` for the flow in context.

### Attachments (encrypted)

Files are sealed locally with ChaCha20-Poly1305 before upload. The server
stores opaque ciphertext; the key travels to the recipient through a Signal
envelope with `envelope_type = 9` (`ENVELOPE_TYPE_ATTACHMENT_KEY`).

| ID | Request | Notes |
|---|---|---|
| `0x0006_0001` | `{"file_path":"/abs/path","conversation_id":"uuid"}` | seal locally, upload sealed chunks, return `key_hex` + `base_nonce_hex` |
| `0x0006_0002` | `{"attachment_id":"...","output_path":"...","key_hex":"...","base_nonce_hex":"..."}` | download sealed chunks, open, write plaintext |
| `0x0006_0003` | `{"id":"uuid"}` | take a reference |
| `0x0006_0004` | `{"id":"uuid"}` | drop a reference; blob deleted when last claim goes |
| `0x0006_0005` | `{"total_size":123456}` | chunk layout recommendation |
| `0x0006_0006` | `{"recipient_account_id":"...","attachment_id":"...","key_hex":"...","base_nonce_hex":"..."}` | forward the key to every device of the recipient |

### WebRTC calls

| ID | Request | Notes |
|---|---|---|
| `0x0011_0001` | (empty) | TURN credentials from the server |
| `0x0012_0001..0007` | see below | low-level: create/accept, apply answer, ICE, channels, close, list |
| `0x0012_0010` | `{"recipient_account_id":"...","call_id":"..."}` | create an offer and send it as a call envelope |
| `0x0012_0011` | `{"recipient_account_id":"...","call_id":"...","remote_sdp":"..."}` | accept a remote offer and send the answer |
| `0x0012_0012` | `{"recipient_account_id":"...","call_id":"...","candidate":{...}}` | add a remote candidate locally, forward to the peer |
| `0x0012_0013` | `{"recipient_account_id":"...","call_id":"..."}` | close locally and send a hangup |
| `0x0012_0014` | `{"recipient_account_id":"...","call_id":"..."}` | send a reject (the callee declined) |

The low-level 0x0012_0001..0007 variants exist for callers that want to
drive signaling themselves. New code should use the 0x0012_0010..0014
variants, which package the SDP into a Signal-encrypted envelope and send it
through the websocket without the caller having to touch envelope bytes.

See `group-calls.md` for a worked call flow.

