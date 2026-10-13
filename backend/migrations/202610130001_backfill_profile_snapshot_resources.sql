-- Older trap snapshots predate per-tier Docker defaults. Keep them readable by the new backend
-- and make their displayed profile defaults match their interaction tier.
UPDATE traps
SET profile_snapshot = jsonb_set(
    profile_snapshot,
    '{resources}',
    CASE profile_snapshot->>'level'
        WHEN 'medium' THEN '{"cpu_cores":1.0,"memory_mb":512,"pids":256}'::jsonb
        ELSE '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb
    END,
    true
)
WHERE NOT (profile_snapshot ? 'resources');
