CREATE TABLE server_action_jobs (
    action_id UUID PRIMARY KEY,
    server_id UUID NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('reboot')),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'succeeded', 'failed')),
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX server_action_jobs_server_created ON server_action_jobs(server_id, created_at DESC);
