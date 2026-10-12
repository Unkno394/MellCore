-- Small, versioned knowledge graph. Runtime matching loads only the relevant
-- outgoing edges and stores per-session progress in PostgreSQL.
CREATE TABLE attack_techniques (
    technique_id UUID PRIMARY KEY,
    technique_key TEXT NOT NULL UNIQUE CHECK (technique_key ~ '^[a-z0-9_.-]{1,128}$'),
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 160),
    description TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 4096),
    status TEXT NOT NULL DEFAULT 'known' CHECK (status IN ('known','review')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attack_graph_nodes (
    node_id UUID PRIMARY KEY,
    technique_id UUID NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE CASCADE,
    node_key TEXT NOT NULL CHECK (node_key ~ '^[a-z0-9_.-]{1,128}$'),
    action_kind TEXT NOT NULL CHECK (octet_length(action_kind) BETWEEN 1 AND 128),
    resource_class TEXT NOT NULL DEFAULT '*',
    expected_outcome TEXT NOT NULL DEFAULT '*',
    evidence_level TEXT NOT NULL DEFAULT 'attempt' CHECK (evidence_level IN ('attempt','confirmed')),
    UNIQUE (technique_id,node_key)
);
CREATE INDEX attack_graph_nodes_action ON attack_graph_nodes(action_kind,resource_class);

CREATE TABLE attack_graph_edges (
    from_node UUID NOT NULL REFERENCES attack_graph_nodes(node_id) ON DELETE CASCADE,
    to_node UUID NOT NULL REFERENCES attack_graph_nodes(node_id) ON DELETE CASCADE,
    PRIMARY KEY (from_node,to_node),
    CHECK (from_node <> to_node)
);
CREATE INDEX attack_graph_edges_to ON attack_graph_edges(to_node);

CREATE TABLE normalized_attack_actions (
    event_id UUID PRIMARY KEY REFERENCES attack_events(event_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    server_id UUID NOT NULL,
    trap_id UUID NOT NULL,
    session_key TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    process_class TEXT NOT NULL,
    resource_class TEXT NOT NULL,
    outcome TEXT NOT NULL,
    environment JSONB NOT NULL CHECK (jsonb_typeof(environment)='object'),
    normalized_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX normalized_actions_session ON normalized_attack_actions(agent_id,trap_id,session_key,normalized_at);
CREATE INDEX normalized_actions_kind ON normalized_attack_actions(action_kind,resource_class,normalized_at);

CREATE TABLE attack_graph_progress (
    agent_id UUID NOT NULL,
    trap_id UUID NOT NULL,
    session_key TEXT NOT NULL,
    technique_id UUID NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE CASCADE,
    active_nodes UUID[] NOT NULL DEFAULT '{}',
    evidence_event_ids UUID[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('candidate','attempt','confirmed')),
    similarity REAL NOT NULL CHECK (similarity BETWEEN 0 AND 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id,trap_id,session_key,technique_id)
);
CREATE INDEX attack_graph_progress_recent ON attack_graph_progress(updated_at DESC);

CREATE TABLE attack_graph_proposals (
    proposal_id UUID PRIMARY KEY,
    action_kind TEXT NOT NULL,
    process_class TEXT NOT NULL,
    resource_class TEXT NOT NULL,
    outcome TEXT NOT NULL,
    sample_event_id UUID NOT NULL REFERENCES attack_events(event_id) ON DELETE RESTRICT,
    evidence_count BIGINT NOT NULL DEFAULT 1 CHECK (evidence_count > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected')),
    suggested_technique UUID REFERENCES attack_techniques(technique_id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (action_kind,process_class,resource_class,outcome)
);

-- A deliberately conservative starter pattern: actions can differ, but a
-- confirmed escape is emitted only by an independently confirmed host event.
INSERT INTO attack_techniques(technique_id,technique_key,name,description,status) VALUES
 ('d0c0a001-1000-4000-8000-000000000001','container.escape','Container isolation escape','Possible access to host-sensitive resources followed by execution in host context. Similarity is a lead, never proof of compromise.','known');

INSERT INTO attack_graph_nodes(node_id,technique_id,node_key,action_kind,resource_class,expected_outcome,evidence_level) VALUES
 ('d0c0a001-2000-4000-8000-000000000001','d0c0a001-1000-4000-8000-000000000001','runtime_control','process.command','container_runtime','*','attempt'),
 ('d0c0a001-2000-4000-8000-000000000002','d0c0a001-1000-4000-8000-000000000001','host_resource','filesystem.access','host_sensitive','*','attempt'),
 ('d0c0a001-2000-4000-8000-000000000003','d0c0a001-1000-4000-8000-000000000001','namespace_change','process.command','namespace_tool','*','attempt'),
 ('d0c0a001-2000-4000-8000-000000000004','d0c0a001-1000-4000-8000-000000000001','host_context','boundary.host_exec','*','*','attempt'),
 ('d0c0a001-2000-4000-8000-000000000005','d0c0a001-1000-4000-8000-000000000001','confirmed_escape','boundary.escape_confirmed','*','confirmed','confirmed'),
 ('d0c0a001-2000-4000-8000-000000000006','d0c0a001-1000-4000-8000-000000000001','namespace_mismatch','boundary.namespace_mismatch','*','*','attempt');

INSERT INTO attack_graph_edges(from_node,to_node) VALUES
 ('d0c0a001-2000-4000-8000-000000000001','d0c0a001-2000-4000-8000-000000000002'),
 ('d0c0a001-2000-4000-8000-000000000001','d0c0a001-2000-4000-8000-000000000003'),
 ('d0c0a001-2000-4000-8000-000000000002','d0c0a001-2000-4000-8000-000000000003'),
 ('d0c0a001-2000-4000-8000-000000000002','d0c0a001-2000-4000-8000-000000000004'),
 ('d0c0a001-2000-4000-8000-000000000003','d0c0a001-2000-4000-8000-000000000004'),
 ('d0c0a001-2000-4000-8000-000000000002','d0c0a001-2000-4000-8000-000000000006'),
 ('d0c0a001-2000-4000-8000-000000000003','d0c0a001-2000-4000-8000-000000000006'),
 ('d0c0a001-2000-4000-8000-000000000006','d0c0a001-2000-4000-8000-000000000004'),
 ('d0c0a001-2000-4000-8000-000000000004','d0c0a001-2000-4000-8000-000000000005');
