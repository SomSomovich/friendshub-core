-- Attachment keys are required to reopen decrypted files after restart.
-- The whole account database is SQLCipher-encrypted; records therefore stay
-- scoped to the account and disappear with its local database.
CREATE TABLE IF NOT EXISTS attachment_keys (
    attachment_id   TEXT PRIMARY KEY NOT NULL CHECK (length(attachment_id) = 36),
    key_hex         TEXT NOT NULL CHECK (length(key_hex) = 64),
    base_nonce_hex  TEXT NOT NULL CHECK (length(base_nonce_hex) = 8),
    conversation_id TEXT,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);
