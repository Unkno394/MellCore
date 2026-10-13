ALTER TABLE trap_profiles
    DROP CONSTRAINT trap_profiles_level_check,
    ADD CONSTRAINT trap_profiles_level_check CHECK (level IN ('low', 'medium', 'high'));

INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config,resources)
SELECT '6b6f7a79-6176-4b61-8000-000000000003', 'high_ubuntu_ssh',
       'High interaction SSH honeypot running in an isolated Ubuntu virtual machine.',
       'high', 'high_ubuntu_ssh', 'ssh', '{}'::jsonb,
       '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM trap_profiles WHERE honeypot_type='high_ubuntu_ssh');
