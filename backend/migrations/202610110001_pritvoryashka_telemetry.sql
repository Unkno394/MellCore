-- Register the native Middle Interaction SSH honeypot without changing Low profiles.
INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config)
SELECT '70726974-766f-4279-8000-000000000001', 'Pritvoryashka',
       'Native Rust Middle Interaction SSH honeypot with isolated VFS and adaptive deception.',
       'medium', 'pritvoryashka', 'ssh', '{}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM trap_profiles WHERE honeypot_type='pritvoryashka');

CREATE TABLE telemetry_batches (
    batch_id UUID PRIMARY KEY,
    agent_id UUID NOT NULL,
    server_id UUID NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    batch_hash BYTEA NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count > 0),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX telemetry_batches_server_received ON telemetry_batches(server_id,received_at);

CREATE UNIQUE INDEX traps_telemetry_identity ON traps(trap_id,server_id);

CREATE TABLE attack_events (
    event_id UUID PRIMARY KEY,
    batch_id UUID NOT NULL REFERENCES telemetry_batches(batch_id) ON DELETE RESTRICT,
    agent_id UUID NOT NULL,
    server_id UUID NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    trap_id UUID NOT NULL,
    session_id TEXT CHECK (session_id IS NULL OR octet_length(session_id) BETWEEN 1 AND 256),
    sequence_no BIGINT CHECK (sequence_no IS NULL OR sequence_no > 0),
    event_type TEXT NOT NULL CHECK (octet_length(event_type) BETWEEN 1 AND 128),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    source_ip TEXT,
    source_port INTEGER CHECK (source_port BETWEEN 0 AND 65535),
    destination_port INTEGER CHECK (destination_port BETWEEN 0 AND 65535),
    protocol TEXT NOT NULL,
    service_type TEXT NOT NULL,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object'),
    metadata JSONB NOT NULL CHECK (jsonb_typeof(metadata)='object'),
    event_hash BYTEA NOT NULL,
    FOREIGN KEY (trap_id,server_id) REFERENCES traps(trap_id,server_id) ON DELETE RESTRICT
);
CREATE INDEX attack_events_session_order ON attack_events(trap_id,session_id,sequence_no,occurred_at);
CREATE INDEX attack_events_expires ON attack_events(expires_at);
CREATE INDEX attack_events_type_time ON attack_events(event_type,occurred_at);
