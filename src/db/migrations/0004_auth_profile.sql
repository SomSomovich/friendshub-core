-- Profile fields carried alongside the session token. They are populated
-- from the /me response at login, so a UI that opens the database can show
-- the account's own name, avatar, and status without a second round trip.

ALTER TABLE auth_state ADD COLUMN username TEXT;
ALTER TABLE auth_state ADD COLUMN avatar_url TEXT;
ALTER TABLE auth_state ADD COLUMN custom_status_text TEXT;
ALTER TABLE auth_state ADD COLUMN custom_status_emoji TEXT;
ALTER TABLE auth_state ADD COLUMN custom_status_expires_at INTEGER;
ALTER TABLE auth_state ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
