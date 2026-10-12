CREATE TABLE trap_action_jobs (
    action_id UUID PRIMARY KEY,
    trap_id UUID NOT NULL REFERENCES traps(trap_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES center_agent_servers(agent_id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (action IN ('start','stop','restart','remove')),
    command_ids UUID[] NOT NULL CHECK (cardinality(command_ids) BETWEEN 1 AND 2),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','succeeded','failed')),
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX trap_action_jobs_trap_recent ON trap_action_jobs(trap_id, created_at DESC);
