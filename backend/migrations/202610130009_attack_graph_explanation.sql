ALTER TABLE attack_graph_progress
    ADD COLUMN node_evidence JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(node_evidence) = 'object');
