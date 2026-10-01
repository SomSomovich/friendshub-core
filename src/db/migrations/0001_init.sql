-- auth_state is a singleton row: id is always 1.
CREATE TABLE IF NOT EXISTS auth_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    account_id      TEXT,
    session_id      TEXT,
    session_token   TEXT,
    device_number   INTEGER,
    fh_number       TEXT,
    expires_at      INTEGER,
    updated_at      INTEGER NOT NULL
);

-- Durable events waiting for fh_ack_event.
CREATE TABLE IF NOT EXISTS pending_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
