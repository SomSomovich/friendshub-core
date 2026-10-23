-- Durable device-initialization progress and retryable prekey publication.
-- Existing identity rows predate these stages. A missing device_init_state row
-- requires runtime reconciliation against the server before it can be treated
-- as complete, because older initialization persisted identity before upload.
CREATE TABLE IF NOT EXISTS device_init_state (
    id                         INTEGER PRIMARY KEY CHECK (id = 1),
    stage                      TEXT NOT NULL CHECK (stage IN ('registration_pending', 'prekeys_pending', 'complete')),
    device_name                TEXT NOT NULL,
    device_id                  TEXT,
    device_number              INTEGER,
    initial_otk_count          INTEGER NOT NULL DEFAULT 0,
    initial_kyber_otk_count    INTEGER NOT NULL DEFAULT 0
);

-- Only one durable upload can be pending: prekey generation is serialized and
-- every caller must flush this row before allocating another key range.
CREATE TABLE IF NOT EXISTS device_init_pending_prekeys (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    payload                  TEXT NOT NULL,
    one_time_count           INTEGER NOT NULL,
    kyber_one_time_count     INTEGER NOT NULL,
    purpose                  TEXT NOT NULL CHECK (purpose IN ('initial', 'replenish'))
);

-- Distinguish Kyber one-time keys from the separately uploaded last-resort
-- key. In the pre-discriminator schema, each generator batch allocated its
-- signed prekey immediately before the corresponding last-resort key.
ALTER TABLE kyber_pre_keys
    ADD COLUMN key_kind TEXT NOT NULL DEFAULT 'one_time'
    CHECK (key_kind IN ('one_time', 'last_resort'));

UPDATE kyber_pre_keys
   SET key_kind = 'last_resort'
 WHERE EXISTS (
       SELECT 1 FROM signed_pre_keys
        WHERE signed_pre_keys.prekey_id + 1 = kyber_pre_keys.prekey_id
   );
