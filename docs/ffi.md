# FriendsHub Core — C ABI reference

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
On success, it carries the method-specific JSON response.

**Every successful call that fills an out buffer must be followed by
`fh_buffer_free`.** Forgetting this leaks one Vec per call.

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

IDs are grouped by namespace. New methods are added at the end of a range, so
existing IDs never move.

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
| `0x000A_xxxx` | groups |
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

Login response:

```json
{
  "kind": "session",
  "session_token": "...",
  "expires_at": 1234567890,
  "account": { "id": "...", "user_id": 1, "fh_number": "FH1234567", "username": "..." }
}
```

or, when 2FA is enabled:

```json
{ "kind": "totp_required", "challenge_token": "...", "expires_in_seconds": 300 }
```

### Device initialization (required once after first login)

| ID | Request | Notes |
|---|---|---|
| `0x0005_0004` | `{"name":"Desktop"}` | generate identity, register device, upload 100 prekeys |
| `0x0005_0005` | (empty) | status: initialized?, prekey counts |
| `0x0005_0015` | (empty) | top up prekeys if the pool is low |

`initialize` response:

```json
{
  "device_id": "uuid",
  "device_number": 1,
  "registration_id": 12345,
  "one_time_prekeys": 100,
  "kyber_one_time_prekeys": 100
}
```

### Websocket

| ID | Request | Notes |
|---|---|---|
| `0x00FF_0001` | (empty) | start the connect loop |
| `0x00FF_0002` | (empty) | stop the loop |
| `0x00FF_0003` | envelope JSON | send one envelope |

The websocket runs in the background after start. Inbound traffic is pushed
into the event queue and picked up via `fh_poll_event`.

### Messages (Signal Protocol)

| ID | Request | Response |
|---|---|---|
| `0x0004_0001` | `{"recipient_account_id":"...","device_number":N,"bundle":{...}}` | `{"ok":true}` |
| `0x0004_0002` | `{"recipient_account_id":"...","device_number":N,"plaintext_hex":"..."}` | `{"ciphertext_hex":"...","is_prekey_message":bool,"envelope_type":1}` |
| `0x0004_0003` | envelope JSON | `{"plaintext_hex":"..."}` |
| `0x0004_0004` | see below | see below |

`0x0004_0004` is the high-level send. Use it unless you need to drive
session management yourself through `0x0004_0001` and `0x0004_0002`.

Request:

```json
{
  "recipient_account_id": "uuid",
  "plaintext_hex": "68656c6c6f",
  "conversation_id": "uuid",      // optional
  "device_number": 1,              // optional; omit to send to all devices
  "refresh_devices": false         // optional; bypass the device cache
}
```

When `device_number` is present, the message goes only to that device.
When it is absent, it goes to **every active device** of the recipient,
each encrypted separately for that device. Device lists are cached for
`CACHE_TTL_SECS` (five minutes); set `refresh_devices: true` to bypass the
cache, for example right after learning that the recipient added a device.

Response:

```json
{
  "envelopes": [
    { "device_number": 1, "envelope_id": "uuid", "is_prekey_message": true, "ciphertext_len": 248 },
    { "device_number": 2, "envelope_id": "uuid", "is_prekey_message": true, "ciphertext_len": 251 }
  ],
  "device_errors": [
    { "device_number": 3, "error": "bundle fetch failed: 404" }
  ]
}
```

A device that fails does not abort the whole send. The caller decides what
to do with the partial result. To retry only the failed devices, call again
with `device_number` set to one of them and the same `plaintext_hex`.

A response with an empty `envelopes` array and a non-empty `device_errors`
array means nothing was sent. This is not an error return: the per-device
detail is more useful than a single string.

### Attachments

| ID | Request | Notes |
|---|---|---|
| `0x0006_0001` | `{"file_path":"/abs/path","conversation_id":"uuid","kind":"attachment"}` | full upload: read file, allocate, PUT to S3, finalize |
| `0x0006_0002` | `{"attachment_id":"uuid","output_path":"/abs/path"}` | download, write to disk |
| `0x0006_0003` | `{"id":"uuid"}` | take a reference |
| `0x0006_0004` | `{"id":"uuid"}` | drop a reference; deletes the blob when the last is gone |
| `0x0006_0005` | `{"total_size":123456}` | chunk layout recommendation |

### Avatars

| ID | Request | Notes |
|---|---|---|
| `0x0007_0001` | `{"file_path":"/abs/path.webp"}` | WebP only; server checks magic bytes |
| `0x0007_0002` | (empty) | delete own avatar |
| `0x0007_0003` | `{"account_id":"uuid"}` | public fetch, base64 in response |

### WebRTC calls

| ID | Request | Response |
|---|---|---|
| `0x0012_0001` | `{"call_id":"..."}` | `{"call_id":"...","sdp":"..."}` |
| `0x0012_0002` | `{"call_id":"...","remote_sdp":"..."}` | `{"call_id":"...","sdp":"..."}` |
| `0x0012_0003` | `{"call_id":"...","remote_sdp":"..."}` | `{"ok":true}` |
| `0x0012_0004` | `{"call_id":"...","candidate":{...}}` | `{"ok":true}` |
| `0x0012_0005` | `{"call_id":"...","label":"data"}` | `{"ok":true}` |
| `0x0012_0006` | `{"call_id":"..."}` | `{"ok":true}` |
| `0x0012_0007` | (empty) | list of active call ids |

Signaling goes through the websocket as envelopes; use envelope_type 10..14
for offer, answer, ICE, hangup, reject respectively. See the enum in the
proto file for the exact numbering.

## Events

See `docs/events.md`.

