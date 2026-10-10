-- Extend the existing registry; no existing tables or data are replaced.
CREATE TABLE servers (
    server_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    host TEXT NOT NULL CHECK (octet_length(host) BETWEEN 1 AND 253),
    ssh_port INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_user TEXT NOT NULL CHECK (ssh_user ~ '^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$'),
    credential_ref UUID,
    dispatcher_port INTEGER CHECK (dispatcher_port BETWEEN 1 AND 65535),
    settings JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(settings)='object'),
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','online','offline','error')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id,user_id)
);
CREATE INDEX servers_owner_page ON servers(user_id,server_id);

CREATE TABLE traps (
    trap_id UUID PRIMARY KEY,
    server_id UUID NOT NULL,
    user_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    profile_id UUID NOT NULL REFERENCES trap_profiles(id) ON DELETE RESTRICT,
    profile_version BIGINT NOT NULL CHECK (profile_version > 0),
    profile_snapshot JSONB NOT NULL CHECK (jsonb_typeof(profile_snapshot)='object'),
    config JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config)='object'),
    effective_config JSONB NOT NULL CHECK (jsonb_typeof(effective_config)='object'),
    desired_state TEXT NOT NULL DEFAULT 'stopped' CHECK (desired_state IN ('running','stopped')),
    actual_state TEXT NOT NULL DEFAULT 'unknown' CHECK (actual_state IN ('unknown','installing','running','stopped','failed','removed')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (server_id,user_id) REFERENCES servers(server_id,user_id) ON DELETE RESTRICT,
    UNIQUE (trap_id,server_id,user_id)
);
CREATE INDEX traps_owner_page ON traps(user_id,trap_id);
CREATE INDEX traps_server_page ON traps(server_id,trap_id);
CREATE INDEX traps_profile ON traps(profile_id);

-- One reservation per protocol/host port for the entire registered server.
-- All interfaces are conservatively treated as one bind address.
CREATE TABLE server_ports (
    server_id UUID NOT NULL,
    user_id UUID NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
    host_port INTEGER NOT NULL CHECK (host_port BETWEEN 1 AND 65535),
    purpose TEXT NOT NULL CHECK (purpose IN ('ssh','dispatcher','trap')),
    trap_id UUID,
    target_port INTEGER CHECK (target_port BETWEEN 1 AND 65535),
    route_mode TEXT CHECK (route_mode IN ('direct','dispatcher_backend')),
    PRIMARY KEY (server_id,transport,host_port),
    FOREIGN KEY (server_id,user_id) REFERENCES servers(server_id,user_id) ON DELETE CASCADE,
    FOREIGN KEY (trap_id,server_id,user_id) REFERENCES traps(trap_id,server_id,user_id) ON DELETE CASCADE,
    CHECK (
        (purpose IN ('ssh','dispatcher') AND transport='tcp' AND trap_id IS NULL AND target_port IS NULL AND route_mode IS NULL)
        OR (purpose='trap' AND trap_id IS NOT NULL AND target_port IS NOT NULL AND route_mode IS NOT NULL)
    ),
    CHECK (route_mode IS DISTINCT FROM 'dispatcher_backend' OR transport='tcp')
);
CREATE UNIQUE INDEX server_ports_system_kind ON server_ports(server_id,purpose) WHERE purpose IN ('ssh','dispatcher');
CREATE INDEX server_ports_trap ON server_ports(trap_id);
