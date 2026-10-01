-- Sender-key distribution mapping. The SenderKeyRecord itself lives in the
-- `sender_keys` table, keyed by (sender, distribution id); this table only
-- remembers which distribution id a conversation is using, so the next
-- outgoing group message knows which record to encrypt under.
CREATE TABLE IF NOT EXISTS group_sender_keys (
    conversation_id TEXT PRIMARY KEY,
    distribution_id BLOB NOT NULL,
    created_at      INTEGER NOT NULL
);
