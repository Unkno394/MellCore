INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config,resources)
VALUES
    ('6b6f7a79-6176-4b61-8000-000000000007', 'Windows Server 2022 · High',
     'Изолированная Windows Server 2022 VM с прямым RDP-доступом через агент.',
     'high', 'high_vm', 'rdp', '{"os_profile":"windows_rdp"}'::jsonb,
     '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb)
ON CONFLICT (id) DO NOTHING;
