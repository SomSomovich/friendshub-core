# FriendsHub Core - C ABI reference

Everything a consumer needs: the entry points, the JSON shape of a
configuration, the full method id table, and worked examples.

## Entry points

```c
uint32_t fh_abi_version(void);
const char* fh_abi_string(void);

int32_t fh_android_init(void* java_vm, void* application_context_global_ref);

int32_t fh_init(
    const uint8_t* config_json, size_t config_len,
    struct FH_FhHandle** out_handle,
    FH_FhResultCallback callback, void* user_data);

void fh_destroy(struct FH_FhHandle* handle);

int32_t fh_call(
    struct FH_FhHandle* handle, uint32_t method_id,
    const uint8_t* req, size_t req_len,
    FH_FhResultCallback callback, void* user_data);

int32_t fh_ack_event(struct FH_FhHandle* handle, uint64_t event_id);

int32_t fh_set_event_callbacks(
    struct FH_FhHandle* handle, const struct FH_FhEventCallbacks* callbacks, void* user_data);
```

`fh_init` and `fh_call` invoke `FH_FhResultCallback` synchronously on the
calling thread with the status and a read-only result pointer. The pointer is
valid only until the callback returns; the library releases its backing
allocation automatically. Consumers never receive or release a library-owned
result buffer. A callback may parse or consume the bytes immediately; keeping
the result after returning requires an application-owned copy.

`fh_set_event_callbacks` installs one optional callback per event kind. Pass
`NULL` for `callbacks` to clear the handler. Events produced until another
handler is registered are queued internally and pushed to that handler.
Callbacks run serially on the library-owned worker thread and may reenter
`fh_call`. Each receives an `FhEventView`; its JSON pointer is borrowed until
the callback returns, so the consumer never allocates or frees event payload
memory. Keep `user_data` alive until callbacks drain during clear or destroy.

For `fh_call`, the callback receives `status == 0` on success and a non-zero
status on failure. Its bytes contain the method-specific response or JSON
error object (`{"code":"...","message":"..."}`). `fh_init` returns an
empty result on success and a JSON error object on failure. A zero-length
result is passed as `data == NULL` and `data_len == 0`. The callback must not
unwind across the C ABI boundary and must not retain or free the borrowed
result.

`config_json` and `req` are input borrows: the caller keeps them readable for
the duration of the function call. The library deserializes configuration and
copies request bytes into library-owned storage before the call returns; the
caller may then reuse or release its input storage.

## Android application context

Before calling `fh_init` or Rust `Client::open` on Android, the host must call
`fh_android_init(java_vm, application_context_global_ref)`. Obtain `JavaVM*`
with JNI `GetJavaVM`; obtain the application context with
`Context.getApplicationContext()`, then create a global reference using
`JNIEnv::NewGlobalRef`. Pass that global reference, never a local reference or
an Activity. Both pointers must remain valid for the process lifetime; the
host owns the reference and must not call `DeleteGlobalRef` while core can run.
The host must let this bridge exclusively manage `ndk-context` initialization
and must not initialize/release that crate independently.

The bridge is synchronous and serializes initialization against core startup.
It returns `0` on success, `-1` on invalid arguments, JNI failure, or conflicting
initialization, and `-2` on native platforms other than Android. It is available
on every native target without changing ABI version 3 or existing layouts.
Repeated registration of the same Java application context is idempotent only
before any successful core open, including different global references to the
same object. After a successful core open, every initialization call returns an
error, including registration of the same context. A different context is
always rejected, including before the first core open. Core startup requires
registration; a failed startup does not mark a handle as successfully opened,
and dropping its guard releases the in-progress reservation before retrying.
Core never transfers database key bytes to the host.

## Native database encryption

The library encrypts every native SQLite page with SQLCipher and stores the
random 256-bit database key in the platform secure credential store. The host
continues to supply only `db_path`; it does not allocate, pass, or free key
material. Native startup requires the relevant system store: Linux Secret
Service must be available in the user's session, macOS uses Keychain, iOS uses
protected storage, Windows uses Credential Manager, and Android uses Keystore
after the context bridge above has been initialized. An unavailable or locked
store causes startup to return an error; there is no plaintext fallback.

The library creates a new database as SQLCipher from its first page. Existing
plaintext SQLite files are rejected unchanged on every native platform. There
is no import, conversion, or plaintext fallback; point the client at a new
database path if a plaintext file already exists. Existing encrypted or
otherwise unrecognized files require their matching secure-store key and are
never replaced when that key is missing or invalid.

The secure-store key is identified by the normalized database path. Moving or
renaming the database, changing OS accounts, or moving it to another device
requires a future explicit re-key/import operation. Logout leaves the key in
the secure store. The library cannot promise forensic erasure of plaintext
data retained in backups, filesystem snapshots, copy-on-write storage, or
flash media.

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
| `0x0000_xxxx` | service (ping, version, ack_event, event callback activation) |
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
| `0x0013_xxxx` | conversation history, pins, polls, folders, scheduled messages, search, poll encryption |
| `0x00FF_xxxx` | websocket lifecycle |

### Service

| ID | Request | Response |
|---|---|---|
| `0x0000_0001` | (empty) | `{"pong":true}` |
| `0x0000_0002` | (empty) | server version, urls, ws state |
| `0x0000_0004` | `{"event_id": N}` | `{"acked":true}` |
| `0x0000_0005` | internal | activates PUSH delivery and drains queued events; called by the client facades |

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
| `0x00FF_0004` | typing JSON | send typing state |
| `0x00FF_0005` | nudge JSON | send a nudge |
| `0x00FF_0006` | history request JSON | request conversation history |
| `0x00FF_0007` | `{"timeout_ms":5000}` or empty | send a protobuf ping and return round-trip milliseconds |
| `0x00FF_0008` | `SendHistoryRequest` JSON | answer a history request by fragmenting caller-owned durable records, encrypting them as own-device `SYNC` envelopes, and submitting them over the active websocket |

`ws_send_history` accepts the records already stored by the caller. The core
validates the target device and conversations, chunks each item into the shared
history wire format, and reports submitted chunks. `complete` means the local
websocket accepted every chunk; it does not mean the server acknowledged the
transfer. See `src/api/history_sync.rs` for the typed request/response fields.

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

### Encrypted polls

These methods keep poll metadata and option text encrypted with the
conversation Sender Key, while the existing `chat_extras_poll_*` methods
continue to operate on the server's poll records and votes.

| ID | Typed Rust method | Request | Response |
|---|---|---|---|
| `0x0013_0020` | `poll_crypto_create_conversation_poll` | `{"conversation_id":"uuid","metadata":{"title":"...","description":"...","options":[{"id":"...","text":"..."}]},"settings":{"poll_type":"regular","allows_multiple":false,"allows_revoting":false,"allows_user_options":false,"open_period_seconds":null,"correct_option_id":null}}` | `{"item":{...},"metadata":{...},"history_synced":true}` |
| `0x0013_0021` | `poll_crypto_encrypt_poll_payload` | `{"conversation_id":"uuid","payload":{"text":"..."}}` | JSON string containing standard-base64 Sender Key ciphertext |
| `0x0013_0022` | `poll_crypto_encrypt_poll_option` | `{"conversation_id":"uuid","text":"..."}` | JSON string containing standard-base64 Sender Key ciphertext for `{"text":"..."}` |
| `0x0013_0023` | `poll_crypto_decrypt_poll_payload` | `{"sender_account_id":"uuid","sender_device_number":1,"encrypted_meta":"base64"}` | Decrypted JSON value |

Poll creation encrypts metadata, creates the authoritative server poll, then
sends its poll-ID-linked encrypted history copy to conversation members and
the caller's other devices. A successful REST poll remains the result even if
the later websocket history-copy send fails; in that case `history_synced` is
`false`. It reports that the websocket accepted the send queue, not that the
server has delivered or acknowledged every envelope.

### Encrypted history replay

History replay fetches the WEB-compatible conversation or Saved Messages page
inside the library and decrypts it against an isolated copy of Signal state.
The live ratchet state is not changed until the host has durably saved the page
and calls `history_replay_commit` with the returned token.

| ID | Typed Rust method | Request | Response |
|---|---|---|---|
| `0x0013_0030` | `history_replay_begin_conversation_page` | `{"conversationId":"uuid","before":123,"beforeId":"uuid","limit":200,"knownEnvelopeIds":[],"knownMessageIds":[]}` | staged replay page with `messages`, `attachmentKeys`, `processedEnvelopeIds`, `existingMessageIds`, rollback keys, `cursor`, `hasOlder`, and `replayToken` |
| `0x0013_0031` | `history_replay_begin_saved_page` | `{"before":123,"beforeId":"uuid","limit":100,"knownEnvelopeIds":[],"knownMessageIds":[]}` | same staged replay page for the current device's Saved Messages |
| `0x0013_0032` | `history_replay_commit` | `{"replayToken":"uuid"}` | `{"committed":true,"conflict":false,"alreadyCommitted":false}` |
| `0x0013_0033` | `history_replay_discard` | `{"replayToken":"uuid"}` | `{"discarded":true}` (false for an unknown or expired token) |

`knownEnvelopeIds` is the host's bounded set of already stored envelope UUIDs;
IDs outside the fetched page are ignored. `knownMessageIds` contains logical
message IDs already stored in that conversation. The core still stages decryption for an existing logical message
and returns its ID in `existingMessageIds`, but omits it from `messages` so the
host can preserve local edits and reactions. Conversation pages default to 200
rows and Saved Messages pages to 100; `cursor` and `hasOlder` follow the WEB
pagination contract. The host must persist the page and progress before
committing the replay token. A successful commit is idempotent if the response
is lost.

For native clients, pending snapshots and commit receipts are stored in the
encrypted SQLCipher database. The ratchet update and receipt are committed in
one SQLite transaction, so a process restart between commit and response does
not lose the result. A pending stage survives restart for five minutes; a
commit receipt is also retained for five minutes. At most four pages can be
pending per database.

### Native history transfer storage

Native history transfer stores incomplete chunks, imported message records,
attachment keys, and replay cursors in the account SQLCipher database.
`history_sync_receive_chunk` is called with authenticated envelope metadata
and a decoded history chunk; callers acknowledge the durable envelope only
after this method succeeds. It validates the own-device identity, assembles the
WEB wire format, and stores complete records before returning. Attachment keys
are written to the existing encrypted attachment-key table in the same
transaction.

| ID | Typed Rust method | Request | Response |
|---|---|---|---|
| `0x0013_0040` | `history_sync_receive_chunk` | authenticated envelope metadata plus `decrypted_payload` history chunk | assembly progress and completed durable item, when available |
| `0x0013_0041` | `history_sync_list_items` | `{"conversation_id":"uuid","limit":5000}` | imported message items from SQLCipher |
| `0x0013_0042` | `history_sync_respond_request` | `{"from_device_number":2,"conversation_ids":["uuid"]}` | WEB-compatible send result; partial queue submission is reported with `complete:false` |
| `0x0013_0043` | `history_sync_load_local_page` | `{"conversation_id":"uuid","older":false}` | imported message count and `hasOlder` state |

`history_sync_respond_request` verifies the target is another active account
device and excludes channel conversations. It replays server history page by
page, persists each page and attachment keys before committing the replay
token, and then sends the account's durable history items over the core
WebSocket. `history_sync_load_local_page` uses the same persist-before-commit
ordering for history on the current device. A failed replay commit rolls back
only records introduced by that page.

If native commit returns `conflict: true`, another crypto operation changed
the live state. The host must atomically roll back only this page using
`rollback.messageIds`, `rollback.attachmentIds`, and
`rollback.progressEnvelopeIds`, restore any pre-existing attachment records it
updated, reload crypto state, and retry the page. Keep the replay token with
the page's rollback journal until commit succeeds or the page is rolled back.
If the token is unknown or expired, roll back that journaled page before
fetching and replaying it again. Do not merge the staged ratchet state. If the
host abandons a page before saving it, call discard.

The browser WASM workflow keeps staged snapshots and receipts in the current
WASM instance's memory (15-minute token lifetime; at most 32 pending pages).
Its `commitHistoryReplayWorkflow` callback must atomically compare
`baseSignalSnapshot`, persist the page, attachment keys, progress IDs,
`signalSnapshot`, and a durable receipt keyed by `replayToken` in IndexedDB.
On a conflict before any writes, return
`{ committed: false, conflict: true }`. If the host saved the page separately,
the callback must remove only that token's page and progress in its rollback
phase and return `{ rolledBack: true }`. Keep a host-side journal for pending
tokens across page reloads: if WASM reports an unknown or expired token, use
that journal to roll back an uncommitted page, or use the durable receipt to
recognize a transaction that already committed. A page reload destroys
in-memory WASM stages regardless of the token's remaining lifetime.

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
| `0x0006_0007` | `{"attachment_id":"...","key_hex":"...","base_nonce_hex":"...","conversation_id":"..."}` | save key material in the encrypted account database; identical saves are idempotent and conflicting values are rejected |
| `0x0006_0008` | `{"attachment_id":"..."}` | return the saved key record, or JSON `null` |
| `0x0006_0009` | `{"attachment_id":"..."}` | remove the saved key record; return `{"deleted":true/false}` |

The `conversation_id` field for key storage is optional and may be `null`.
The local key record never leaves the encrypted account database except when
the client explicitly uses it to decrypt or forward the attachment key.

### Community avatars

| ID | Request | Notes |
|---|---|---|
| `0x0007_000A` | `{"conversation_id":"..."}` | fetch a group's public avatar as `{conversation_id, content_type, data_base64}` |
| `0x0007_000B` | `{"conversation_id":"..."}` | fetch a channel's public avatar as `{conversation_id, content_type, data_base64}` |

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

