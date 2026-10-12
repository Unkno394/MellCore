CREATE TABLE server_bootstrap_jobs (
    server_id UUID PRIMARY KEY REFERENCES servers(server_id) ON DELETE CASCADE,
    job_id UUID NOT NULL UNIQUE,
    agent_id UUID NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','succeeded','failed')),
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
