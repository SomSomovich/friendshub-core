-- Native imported history is account data and stays inside SQLCipher.
CREATE TABLE IF NOT EXISTS native_history_items (
    transfer_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    item_kind TEXT NOT NULL CHECK (item_kind IN ('message', 'attachment', 'complete')),
    item_id TEXT NOT NULL,
    source_device_number INTEGER NOT NULL,
    item_json TEXT NOT NULL,
    stored_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (transfer_id, conversation_id, item_kind, item_id)
);

CREATE INDEX IF NOT EXISTS idx_native_history_items_conversation
    ON native_history_items (conversation_id, stored_at, item_kind);

CREATE TABLE IF NOT EXISTS native_history_fragments (
    source_device_number INTEGER NOT NULL,
    transfer_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    item_kind TEXT NOT NULL CHECK (item_kind IN ('message', 'attachment', 'complete')),
    item_id TEXT NOT NULL,
    part_index INTEGER NOT NULL CHECK (part_index >= 0),
    part_count INTEGER NOT NULL CHECK (part_count > 0),
    chunk_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (source_device_number, transfer_id, conversation_id, item_kind, item_id, part_index)
);

CREATE INDEX IF NOT EXISTS idx_native_history_fragments_updated_at
    ON native_history_fragments (updated_at);

CREATE TABLE IF NOT EXISTS native_history_processed_envelopes (
    conversation_id TEXT NOT NULL,
    envelope_id TEXT NOT NULL,
    stored_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (conversation_id, envelope_id)
);

CREATE TABLE IF NOT EXISTS native_history_cursors (
    conversation_id TEXT PRIMARY KEY NOT NULL,
    before_timestamp INTEGER,
    before_id TEXT,
    has_older INTEGER NOT NULL CHECK (has_older IN (0, 1)),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
