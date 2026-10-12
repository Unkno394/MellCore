ALTER TABLE trap_profiles
    ADD COLUMN resources JSONB NOT NULL DEFAULT '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb;

UPDATE trap_profiles
SET resources = CASE level
    WHEN 'medium' THEN '{"cpu_cores":1.0,"memory_mb":512,"pids":256}'::jsonb
    ELSE '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb
END;

ALTER TABLE trap_profiles
    ADD CONSTRAINT trap_profiles_resources_valid CHECK (
        jsonb_typeof(resources) = 'object'
        AND jsonb_typeof(resources->'cpu_cores') = 'number'
        AND jsonb_typeof(resources->'memory_mb') = 'number'
        AND jsonb_typeof(resources->'pids') = 'number'
        AND (resources->>'cpu_cores')::numeric >= 0.05
        AND (resources->>'memory_mb')::integer >= 32
        AND (resources->>'pids')::integer >= 16
        AND CASE level
            WHEN 'low' THEN (resources->>'cpu_cores')::numeric <= 0.5
                AND (resources->>'memory_mb')::integer <= 128
                AND (resources->>'pids')::integer <= 64
            ELSE (resources->>'cpu_cores')::numeric <= 1.0
                AND (resources->>'memory_mb')::integer <= 512
                AND (resources->>'pids')::integer <= 256
        END
    );

ALTER TABLE traps
    ADD COLUMN resources JSONB NOT NULL DEFAULT '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb;

UPDATE traps
SET resources = CASE profile_snapshot->>'level'
    WHEN 'medium' THEN '{"cpu_cores":1.0,"memory_mb":512,"pids":256}'::jsonb
    ELSE '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb
END;

ALTER TABLE traps
    ADD CONSTRAINT traps_resources_valid CHECK (
        jsonb_typeof(resources) = 'object'
        AND jsonb_typeof(resources->'cpu_cores') = 'number'
        AND jsonb_typeof(resources->'memory_mb') = 'number'
        AND jsonb_typeof(resources->'pids') = 'number'
        AND (resources->>'cpu_cores')::numeric >= 0.05
        AND (resources->>'memory_mb')::integer >= 32
        AND (resources->>'pids')::integer >= 16
        AND CASE profile_snapshot->>'level'
            WHEN 'medium' THEN (resources->>'cpu_cores')::numeric <= 1.0
                AND (resources->>'memory_mb')::integer <= 512
                AND (resources->>'pids')::integer <= 256
            ELSE (resources->>'cpu_cores')::numeric <= 0.5
                AND (resources->>'memory_mb')::integer <= 128
                AND (resources->>'pids')::integer <= 64
        END
    );
