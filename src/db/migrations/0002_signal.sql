-- Signal Protocol state. All blobs use libsignal's own serialization format.

-- The identity key pair and the local registration id are singletons; the
-- table is row-locked to id = 1 so a second insert cannot silently create
-- a divergent identity.
CREATE TABLE IF NOT EXISTS identity_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_pair        BLOB NOT NULL,
    registration_id INTEGER NOT NULL,
    next_prekey_id  INTEGER NOT NULL DEFAULT 1
);

-- Per-peer identity keys, indexed by the full address (account + device).
CREATE TABLE IF NOT EXISTS peer_identities (
    account_id    TEXT NOT NULL,
    device_number INTEGER NOT NULL,
    identity_key  BLOB NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, device_number)
);

CREATE TABLE IF NOT EXISTS pre_keys (
    prekey_id INTEGER PRIMARY KEY,
    record    BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_pre_keys (
    prekey_id INTEGER PRIMARY KEY,
    record    BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    prekey_id INTEGER PRIMARY KEY,
    record    BLOB NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    account_id    TEXT NOT NULL,
    device_number INTEGER NOT NULL,
    record        BLOB NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, device_number)
);

CREATE TABLE IF NOT EXISTS sender_keys (
    sender_account_id    TEXT NOT NULL,
    sender_device_number INTEGER NOT NULL,
    distribution_id      BLOB NOT NULL,
    record               BLOB NOT NULL,
    updated_at           INTEGER NOT NULL,
    PRIMARY KEY (sender_account_id, sender_device_number, distribution_id)
);

-- Device lists for peers, refreshed on demand. Multi-device fanout needs to
-- know every device of the recipient; the server exposes one endpoint per
-- account, so caching avoids a call per message.
CREATE TABLE IF NOT EXISTS device_cache (
    account_id   TEXT PRIMARY KEY,
    devices_json TEXT NOT NULL,
    fetched_at   INTEGER NOT NULL
);
