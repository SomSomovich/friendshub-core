# Group messaging and calls, end to end

A worked view of how the harder features fit together. Read this after
`ffi.md`; it explains the sequencing, not the individual endpoints.

## Groups

### Setting up a group conversation

1. Create the group with `0x000A_0001`. The response carries a
   `conversation_id`.
2. Call `0x000A_0020` with that id. This generates this device's sender key
   for the conversation and sends a `SenderKeyDistributionMessage` to every
   device of every member.
3. Members who join later need their own distribution. The simplest policy is
   to call `0x000A_0020` again after every membership change. The `rotate`
   flag decides whether the distribution id stays the same (idempotent
   re-send) or changes (rekey after a removal).

A rekey is what stops a removed device from reading new messages: it holds
a copy of the old sender keys, but nothing encrypted under the new ones.
The server does not enforce this; the client calls `rotate: true` on its way
out of the removal handler.

### Sending

`0x000A_0021` encrypts once and fans the single ciphertext out to every
member device. That is the difference from `0x0004_0004`, which encrypts
per-device. For a two-person conversation the two are equivalent in cost;
for a fifty-person group the sender key path is fifty times cheaper.

### Receiving

Incoming group traffic arrives as ordinary `envelope_received` events. The
payload tells the two interesting cases apart:

- `distribution: true` - a member sent their sender key. No action needed
  beyond persisting the event; the library already stored the key.
- `group: true` with a `plaintext_hex` - a group message, decrypted through
  the sender key path.

### What is not handled

- **Own-device sync for groups.** A sender's own other devices do not receive
  a copy of a group message through a dedicated mechanism. If they are members
  of the conversation they receive the same fanout; if they are not, they do
  not. This matches the protocol but is worth knowing.
- **Automatic rekey on membership change.** The library exposes `rotate`, but
  deciding when to call it is the caller's policy.

## Calls

### Placing a call

1. Pick a `call_id`. Any unique string; a UUID is fine.
2. Call `0x0012_0010` with the peer's account id and the call id.
   This creates a peer connection, produces an SDP offer, and sends it to
   the peer through a `CALL_OFFER` envelope. The response includes the local
   SDP as a sanity check.
3. As ICE candidates gather, `webrtc_event` with `event: "ice_candidate"`
   arrives in the event queue. Forward each one with `0x0012_0012`; the
   library both adds it locally (it knows it already) and sends it to the
   peer.
4. The peer's answer arrives as an envelope. Call `0x0012_0003` with the
   remote SDP to apply it.

### Answering a call

1. A `CALL_OFFER` envelope arrives. Its plaintext is JSON with `call_id`
   and `sdp`.
2. Call `0x0012_0011` with the peer's account id, the call id, and the
   remote SDP. This creates the peer connection, applies the offer, produces
   an answer, and sends it back through a `CALL_ANSWER` envelope.
3. Forward ICE candidates as they appear, same as above.

### Hanging up

`0x0012_0013` closes the local peer connection and sends a `CALL_HANGUP`.
The peer sees the envelope; whether they had a local connection or not, they
can act on it.

### Rejecting

`0x0012_0014` sends a `CALL_REJECT`. Use it on the callee side before
answering; there is no local peer connection to close.

### Envelope types used

| Type | Meaning |
|---|---|
| 10 | `CALL_OFFER` |
| 11 | `CALL_ANSWER` |
| 12 | `CALL_ICE` |
| 13 | `CALL_HANGUP` |
| 14 | `CALL_REJECT` |

These ride the same encrypted envelope channel as everything else: a call
offer is Signal-encrypted for every device of the peer, and each device
decrypts it with the session it already has. There is no separate signaling
socket.

