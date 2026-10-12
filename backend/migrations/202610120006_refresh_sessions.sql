CREATE TABLE refresh_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX refresh_sessions_user ON refresh_sessions(user_id);
CREATE INDEX refresh_sessions_expiry ON refresh_sessions(expires_at);
ALTER TABLE access_tokens ADD COLUMN refresh_session_id UUID REFERENCES refresh_sessions(id) ON DELETE CASCADE;
CREATE INDEX access_tokens_refresh_session ON access_tokens(refresh_session_id);
