-- Staged Signal snapshots and commit receipts survive native library restarts.
-- The database is always opened through SQLCipher, so these serialized
-- snapshots remain encrypted at rest with the rest of the crypto state.
CREATE TABLE IF NOT EXISTS history_replay_stages (
    replay_token   TEXT PRIMARY KEY NOT NULL,
    base_snapshot  TEXT NOT NULL,
    staged_snapshot TEXT NOT NULL,
    expires_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_replay_stages_expires_at
    ON history_replay_stages (expires_at);

CREATE TABLE IF NOT EXISTS history_replay_receipts (
    replay_token TEXT PRIMARY KEY NOT NULL,
    outcome      INTEGER NOT NULL CHECK (outcome IN (0, 1)),
    expires_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_replay_receipts_expires_at
    ON history_replay_receipts (expires_at);
