ALTER TABLE trap_profiles DROP CONSTRAINT trap_profiles_level_check;
ALTER TABLE trap_profiles
    ADD CONSTRAINT trap_profiles_level_check CHECK (level IN ('low', 'medium', 'high'));

ALTER TABLE trap_profiles DROP CONSTRAINT trap_profiles_resources_valid;
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
            WHEN 'medium' THEN (resources->>'cpu_cores')::numeric <= 1.0
                AND (resources->>'memory_mb')::integer <= 512
                AND (resources->>'pids')::integer <= 256
            ELSE (resources->>'cpu_cores')::numeric <= 2.0
                AND (resources->>'memory_mb')::integer <= 2048
                AND (resources->>'pids')::integer <= 512
        END
    );

ALTER TABLE traps DROP CONSTRAINT traps_resources_valid;
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
            WHEN 'low' THEN (resources->>'cpu_cores')::numeric <= 0.5
                AND (resources->>'memory_mb')::integer <= 128
                AND (resources->>'pids')::integer <= 64
            WHEN 'medium' THEN (resources->>'cpu_cores')::numeric <= 1.0
                AND (resources->>'memory_mb')::integer <= 512
                AND (resources->>'pids')::integer <= 256
            ELSE (resources->>'cpu_cores')::numeric <= 2.0
                AND (resources->>'memory_mb')::integer <= 2048
                AND (resources->>'pids')::integer <= 512
        END
    );

INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config,resources)
SELECT '64656269-616e-4000-8000-000000000012', 'Debian 12 High SSH',
       'Debian 12 KVM/libvirt High Interaction SSH honeypot with guest audit telemetry.',
       'high', 'high-debian-ssh', 'ssh', '{}'::jsonb,
       '{"cpu_cores":2.0,"memory_mb":2048,"pids":512}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM trap_profiles WHERE honeypot_type='high-debian-ssh');
