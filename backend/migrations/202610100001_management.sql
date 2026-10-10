CREATE TABLE roles (
    name TEXT PRIMARY KEY CHECK (name IN ('admin', 'viewer'))
);
INSERT INTO roles(name) VALUES ('admin'), ('viewer');

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_.-]{3,64}$'),
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL REFERENCES roles(name),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX users_active_admins ON users(id) WHERE role = 'admin' AND is_active;

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    csrf_hash BYTEA NOT NULL CHECK (octet_length(csrf_hash) = 32),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE trap_profiles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 128),
    description TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 4096),
    level TEXT NOT NULL CHECK (level IN ('low', 'medium')),
    honeypot_type TEXT NOT NULL CHECK (honeypot_type ~ '^[a-z0-9_.-]{1,128}$'),
    service_type TEXT NOT NULL CHECK (service_type ~ '^[a-z0-9_.-]{1,128}$'),
    config JSONB NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    object_id UUID NOT NULL,
    request_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_object_history ON audit_logs(object_id, created_at, id);
CREATE INDEX audit_actor_history ON audit_logs(actor_id, created_at, id);
