-- Keep historical events after an operator removes their server or trap.
-- Detached records remain stored for audit, but are no longer listed under a live resource.
ALTER TABLE telemetry_batches
    DROP CONSTRAINT telemetry_batches_server_id_fkey,
    ALTER COLUMN server_id DROP NOT NULL;
ALTER TABLE telemetry_batches
    ADD CONSTRAINT telemetry_batches_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE SET NULL;

ALTER TABLE attack_events
    DROP CONSTRAINT attack_events_server_id_fkey,
    DROP CONSTRAINT attack_events_trap_id_server_id_fkey,
    ALTER COLUMN server_id DROP NOT NULL,
    ALTER COLUMN trap_id DROP NOT NULL;
ALTER TABLE attack_events
    ADD CONSTRAINT attack_events_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE SET NULL,
    ADD CONSTRAINT attack_events_trap_id_server_id_fkey
    FOREIGN KEY (trap_id, server_id) REFERENCES traps(trap_id, server_id) ON DELETE SET NULL;
