ALTER TABLE attack_graph_proposals ADD COLUMN reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE attack_graph_proposals ADD COLUMN reviewed_at TIMESTAMPTZ;
ALTER TABLE attack_graph_proposals ADD COLUMN accepted_node_id UUID REFERENCES attack_graph_nodes(node_id) ON DELETE SET NULL;
