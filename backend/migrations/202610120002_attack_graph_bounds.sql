ALTER TABLE attack_graph_progress ADD COLUMN last_occurred_at TIMESTAMPTZ;
-- Old progress used PID-only scopes and mixed simulated and host evidence.
-- Keep raw events; discard only derived progress so it cannot confirm a host incident.
DELETE FROM attack_graph_progress;
ALTER TABLE attack_graph_progress ADD CONSTRAINT attack_graph_active_bound CHECK (cardinality(active_nodes)<=128);
ALTER TABLE attack_graph_progress ADD CONSTRAINT attack_graph_evidence_bound CHECK (cardinality(evidence_event_ids)<=64);
ALTER TABLE attack_graph_nodes ADD CONSTRAINT attack_graph_node_identity UNIQUE (technique_id,node_id);
ALTER TABLE attack_graph_edges ADD COLUMN technique_id UUID;
UPDATE attack_graph_edges e SET technique_id=n.technique_id FROM attack_graph_nodes n WHERE n.node_id=e.from_node;
ALTER TABLE attack_graph_edges ALTER COLUMN technique_id SET NOT NULL;
ALTER TABLE attack_graph_edges ADD CONSTRAINT graph_edge_from_technique FOREIGN KEY(technique_id,from_node) REFERENCES attack_graph_nodes(technique_id,node_id) ON DELETE CASCADE;
ALTER TABLE attack_graph_edges ADD CONSTRAINT graph_edge_to_technique FOREIGN KEY(technique_id,to_node) REFERENCES attack_graph_nodes(technique_id,node_id) ON DELETE CASCADE;
-- A proposed pattern can outlive its representative raw event. Retention must
-- not be blocked by a review queue entry.
ALTER TABLE attack_graph_proposals DROP CONSTRAINT attack_graph_proposals_sample_event_id_fkey;
ALTER TABLE attack_graph_proposals ALTER COLUMN sample_event_id DROP NOT NULL;
ALTER TABLE attack_graph_proposals ADD CONSTRAINT attack_graph_proposals_sample_event_id_fkey
    FOREIGN KEY(sample_event_id) REFERENCES attack_events(event_id) ON DELETE SET NULL;
