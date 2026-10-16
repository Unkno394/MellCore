ALTER TABLE audit_logs
    ADD COLUMN details JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(details) = 'object');

INSERT INTO rbac_permissions(key, category, description)
VALUES ('audit.view', 'audit', 'View security and role audit history');

INSERT INTO rbac_role_permissions(role_id, permission_key)
VALUES
    ('00000000-0000-4000-8000-000000000001', 'audit.view'),
    ('00000000-0000-4000-8000-000000000002', 'audit.view');

CREATE TABLE user_invitations (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL CHECK (length(btrim(email)) BETWEEN 3 AND 320),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    accepted_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (NOT (accepted_at IS NOT NULL AND revoked_at IS NOT NULL)),
    CHECK ((accepted_at IS NULL) = (accepted_user_id IS NULL))
);

CREATE UNIQUE INDEX user_invitations_pending_email
    ON user_invitations(lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX user_invitations_created_at
    ON user_invitations(created_at DESC, id DESC);
CREATE INDEX user_invitations_expiry
    ON user_invitations(expires_at)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE user_invitation_roles (
    invitation_id UUID NOT NULL REFERENCES user_invitations(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE RESTRICT,
    PRIMARY KEY(invitation_id, role_id)
);
