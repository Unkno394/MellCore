ALTER TABLE servers
    ADD COLUMN host_inventory JSONB
        CHECK (host_inventory IS NULL OR jsonb_typeof(host_inventory) = 'object'),
    ADD COLUMN inventory_updated_at TIMESTAMPTZ;

CREATE INDEX servers_inventory_freshness
    ON servers(inventory_updated_at)
    WHERE inventory_updated_at IS NOT NULL;
