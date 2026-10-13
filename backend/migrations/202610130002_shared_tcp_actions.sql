ALTER TABLE trap_action_jobs
    DROP CONSTRAINT trap_action_jobs_action_check;
ALTER TABLE trap_action_jobs
    ADD CONSTRAINT trap_action_jobs_action_check
    CHECK (action IN ('start','stop','restart','remove','share_port'));
ALTER TABLE trap_action_jobs
    ADD COLUMN dispatcher_plan JSONB;
ALTER TABLE trap_action_jobs
    DROP CONSTRAINT trap_action_jobs_command_ids_check;
ALTER TABLE trap_action_jobs
    ADD CONSTRAINT trap_action_jobs_command_ids_check
    CHECK (cardinality(command_ids) BETWEEN 1 AND 3);

ALTER TABLE server_ports
    ADD COLUMN weight INTEGER CHECK (weight BETWEEN 1 AND 100);
