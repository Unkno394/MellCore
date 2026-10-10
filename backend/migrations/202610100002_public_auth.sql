-- Additive upgrade: preserve IDs, password hashes, roles, profiles and history.
ALTER TABLE roles DROP CONSTRAINT roles_name_check;
ALTER TABLE roles ADD CONSTRAINT roles_name_check CHECK (name IN ('admin', 'viewer', 'user'));
INSERT INTO roles(name) VALUES ('user');

ALTER TABLE users ADD COLUMN name TEXT;
UPDATE users SET name = username;
ALTER TABLE users ALTER COLUMN name SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_name_check CHECK (octet_length(name) BETWEEN 1 AND 128);
-- Legacy accounts need an explicit email assignment; never fabricate addresses.
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD CONSTRAINT users_email_check CHECK (
    email IS NULL OR (email = lower(btrim(email)) AND octet_length(email) BETWEEN 3 AND 254 AND email LIKE '%@%')
);
CREATE UNIQUE INDEX users_email_unique ON users(email) WHERE email IS NOT NULL;

-- Old cookie sessions remain intact for migration/audit, but API no longer accepts them.
CREATE TABLE access_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX access_tokens_user ON access_tokens(user_id);
CREATE INDEX access_tokens_expiry ON access_tokens(expires_at);

CREATE TABLE password_resets (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX password_resets_expiry ON password_resets(expires_at);
