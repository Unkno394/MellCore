-- Additive RBAC authorization.  The legacy users.role column is intentionally
-- retained so existing clients, bootstrap tooling and stored accounts remain
-- compatible while authorization is evaluated from the tables below.
CREATE TABLE rbac_permissions (
    key TEXT PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{2,63}$'),
    category TEXT NOT NULL CHECK (category ~ '^[a-z][a-z0-9_]{1,31}$'),
    description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 256)
);

CREATE TABLE rbac_roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 80),
    description TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 2048),
    system_key TEXT UNIQUE CHECK (system_key IS NULL OR system_key IN ('owner','admin','analyst','operator','viewer')),
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (is_system = (system_key IS NOT NULL))
);
CREATE UNIQUE INDEX rbac_roles_name_unique ON rbac_roles (lower(btrim(name)));

CREATE TABLE rbac_role_permissions (
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES rbac_permissions(key) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_key)
);
CREATE INDEX rbac_role_permissions_permission ON rbac_role_permissions(permission_key, role_id);

CREATE TABLE user_role_assignments (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE RESTRICT,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_role_assignments_role ON user_role_assignments(role_id, user_id);

INSERT INTO rbac_permissions(key, category, description) VALUES
 ('traps.view','traps','View traps'), ('traps.create','traps','Create traps'),
 ('traps.edit','traps','Edit traps'), ('traps.start','traps','Start traps'),
 ('traps.stop','traps','Stop traps'), ('traps.reset','traps','Reset traps'),
 ('traps.delete','traps','Delete traps'),
 ('servers.view','servers','View servers and agents'), ('servers.connect','servers','Connect servers and agents'),
 ('servers.manage','servers','Manage servers and agents'), ('servers.disconnect','servers','Disconnect servers and agents'),
 ('attacks.view','attacks','View attacks'), ('attacks.analyze','attacks','Analyze attacks'),
 ('attacks.export','attacks','Export attacks'),
 ('telemetry.view','telemetry','View logs and telemetry'), ('telemetry.export','telemetry','Export logs and telemetry'),
 ('graph.view','graph','View attack graph'), ('graph.manage','graph','Manage attack graph'),
 ('profiles.view','profiles','View profiles and decoys'), ('profiles.create','profiles','Create profiles and decoys'),
 ('profiles.edit','profiles','Edit profiles and decoys'), ('profiles.delete','profiles','Delete profiles and decoys'),
 ('users.view','users','View users'), ('users.manage','users','Manage users'),
 ('users.assign_roles','users','Assign roles to users'),
 ('roles.view','roles','View roles'), ('roles.create','roles','Create roles'),
 ('roles.edit','roles','Edit roles'), ('roles.delete','roles','Delete roles'),
 ('settings.view','settings','View platform settings'), ('settings.change','settings','Change platform settings');

INSERT INTO rbac_roles(id,name,description,system_key,is_system) VALUES
 ('00000000-0000-4000-8000-000000000001','Owner','Full platform ownership','owner',true),
 ('00000000-0000-4000-8000-000000000002','Admin','Platform administration without ownership transfer','admin',true),
 ('00000000-0000-4000-8000-000000000003','Analyst','Attack analysis, telemetry and graph review','analyst',true),
 ('00000000-0000-4000-8000-000000000004','Operator','Operate owned servers, traps and profiles','operator',true),
 ('00000000-0000-4000-8000-000000000005','Viewer','Read-only access to owned resources','viewer',true);

-- Owner is the only role that can transfer ownership or alter platform settings.
INSERT INTO rbac_role_permissions(role_id, permission_key)
SELECT '00000000-0000-4000-8000-000000000001', key FROM rbac_permissions;
INSERT INTO rbac_role_permissions(role_id, permission_key)
SELECT '00000000-0000-4000-8000-000000000002', key FROM rbac_permissions
WHERE key NOT IN ('users.assign_roles','roles.delete','settings.change');
-- Administrators may assign roles, but the API forbids Owner transfer and any
-- role containing permissions outside the administrator's own effective set.
INSERT INTO rbac_role_permissions(role_id, permission_key)
VALUES ('00000000-0000-4000-8000-000000000002','users.assign_roles');
INSERT INTO rbac_role_permissions(role_id, permission_key) VALUES
 ('00000000-0000-4000-8000-000000000003','traps.view'),
 ('00000000-0000-4000-8000-000000000003','servers.view'),
 ('00000000-0000-4000-8000-000000000003','attacks.view'),
 ('00000000-0000-4000-8000-000000000003','attacks.analyze'),
 ('00000000-0000-4000-8000-000000000003','attacks.export'),
 ('00000000-0000-4000-8000-000000000003','telemetry.view'),
 ('00000000-0000-4000-8000-000000000003','telemetry.export'),
 ('00000000-0000-4000-8000-000000000003','graph.view'),
 ('00000000-0000-4000-8000-000000000003','graph.manage'),
 ('00000000-0000-4000-8000-000000000003','profiles.view');
INSERT INTO rbac_role_permissions(role_id, permission_key) VALUES
 ('00000000-0000-4000-8000-000000000004','traps.view'), ('00000000-0000-4000-8000-000000000004','traps.create'),
 ('00000000-0000-4000-8000-000000000004','traps.edit'), ('00000000-0000-4000-8000-000000000004','traps.start'),
 ('00000000-0000-4000-8000-000000000004','traps.stop'), ('00000000-0000-4000-8000-000000000004','traps.reset'),
 ('00000000-0000-4000-8000-000000000004','traps.delete'),
 ('00000000-0000-4000-8000-000000000004','servers.view'), ('00000000-0000-4000-8000-000000000004','servers.connect'),
 ('00000000-0000-4000-8000-000000000004','servers.manage'), ('00000000-0000-4000-8000-000000000004','servers.disconnect'),
 ('00000000-0000-4000-8000-000000000004','attacks.view'), ('00000000-0000-4000-8000-000000000004','attacks.analyze'),
 ('00000000-0000-4000-8000-000000000004','telemetry.view'), ('00000000-0000-4000-8000-000000000004','graph.view'),
 ('00000000-0000-4000-8000-000000000004','profiles.view'), ('00000000-0000-4000-8000-000000000004','profiles.create'),
 ('00000000-0000-4000-8000-000000000004','profiles.edit');
INSERT INTO rbac_role_permissions(role_id, permission_key) VALUES
 ('00000000-0000-4000-8000-000000000005','traps.view'),
 ('00000000-0000-4000-8000-000000000005','servers.view'),
 ('00000000-0000-4000-8000-000000000005','attacks.view'),
 ('00000000-0000-4000-8000-000000000005','telemetry.view'),
 ('00000000-0000-4000-8000-000000000005','graph.view'),
 ('00000000-0000-4000-8000-000000000005','profiles.view'),
 ('00000000-0000-4000-8000-000000000005','settings.view');

-- Preserve historical behaviour: administrators become owners, read-only users
-- remain viewers and normal registered users retain operator capabilities.
INSERT INTO user_role_assignments(user_id, role_id, assigned_by)
SELECT id, CASE role
    WHEN 'admin' THEN '00000000-0000-4000-8000-000000000001'::uuid
    WHEN 'viewer' THEN '00000000-0000-4000-8000-000000000005'::uuid
    ELSE '00000000-0000-4000-8000-000000000004'::uuid END, id
FROM users;
