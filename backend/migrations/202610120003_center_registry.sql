-- The management tables remain the canonical registry for panel and Center traps.
CREATE TABLE center_agent_servers (
    agent_id UUID PRIMARY KEY,
    server_id UUID NOT NULL UNIQUE REFERENCES servers(server_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE center_agent_traps (
    trap_id UUID PRIMARY KEY REFERENCES traps(trap_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES center_agent_servers(agent_id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'provisioning' CHECK (state IN ('provisioning','running','removed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX center_agent_traps_agent ON center_agent_traps(agent_id,trap_id);
