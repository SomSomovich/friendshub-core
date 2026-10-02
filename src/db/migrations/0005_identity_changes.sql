-- Records every time a peer's identity key changed since it was first seen.
--
-- The identity key of a device is supposed to be immutable. A change means
-- either that device re-registered (legitimate but rare) or that someone is
-- trying to impersonate it. The library does not silently accept the new
-- key; it stores the change and surfaces it as an event so the UI can ask
-- the user.
CREATE TABLE IF NOT EXISTS identity_changes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id     TEXT NOT NULL,
    device_number  INTEGER NOT NULL,
    old_key        BLOB NOT NULL,
    new_key        BLOB NOT NULL,
    changed_at     INTEGER NOT NULL,
    notified       INTEGER NOT NULL DEFAULT 0
);
