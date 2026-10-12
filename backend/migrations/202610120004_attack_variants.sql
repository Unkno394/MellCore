-- Match semantic process classes as well as actions/resources/outcomes. An
-- approved new node may be constrained to a process class; old nodes are wildcards.
ALTER TABLE attack_graph_nodes ADD COLUMN process_class TEXT NOT NULL DEFAULT '*'
    CHECK (octet_length(process_class) BETWEEN 1 AND 256);

-- Different observable variants of a runtime-control attempt. None of these
-- nodes proves host compromise; only separately validated escape evidence does.
INSERT INTO attack_techniques(technique_id,technique_key,name,description,status) VALUES
 ('d0c0a002-1000-4000-8000-000000000001','container.runtime_socket','Container runtime socket access','Attempt or successful open of a container runtime socket from a Low/Middle trap. Access is not proof of host escape.','known'),
 ('d0c0a003-1000-4000-8000-000000000001','container.outbound_connect','Unexpected trap outbound connection','Observed outbound connect by a Low/Middle trap process. Destination is unresolved; review before containment.','known');

INSERT INTO attack_graph_nodes(node_id,technique_id,node_key,action_kind,resource_class,expected_outcome,evidence_level) VALUES
 ('d0c0a002-2000-4000-8000-000000000001','d0c0a002-1000-4000-8000-000000000001','socket_open_attempt','resource.open','container_runtime','*','attempt'),
 ('d0c0a002-2000-4000-8000-000000000002','d0c0a002-1000-4000-8000-000000000001','socket_open_succeeded','resource.open','container_runtime','succeeded','attempt'),
 ('d0c0a002-2000-4000-8000-000000000003','d0c0a002-1000-4000-8000-000000000001','host_context_observed','boundary.host_exec','*','*','attempt'),
 ('d0c0a003-2000-4000-8000-000000000001','d0c0a003-1000-4000-8000-000000000001','outbound_connect','network.connect','network_unspecified','*','attempt');

INSERT INTO attack_graph_edges(technique_id,from_node,to_node) VALUES
 ('d0c0a002-1000-4000-8000-000000000001','d0c0a002-2000-4000-8000-000000000001','d0c0a002-2000-4000-8000-000000000002'),
 ('d0c0a002-1000-4000-8000-000000000001','d0c0a002-2000-4000-8000-000000000002','d0c0a002-2000-4000-8000-000000000003');
