UPDATE trap_profiles
SET name='Ubuntu 24.04 · High',
    description='Изолированная Ubuntu Server 24.04 VM с прямым SSH-доступом.',
    honeypot_type='high_vm',
    config='{"os_profile":"ubuntu_ssh"}'::jsonb,
    version=version+1,
    updated_at=now()
WHERE id='6b6f7a79-6176-4b61-8000-000000000003'
  AND honeypot_type='high_ubuntu_ssh' AND level='high';

INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config,resources)
VALUES
    ('6b6f7a79-6176-4b61-8000-000000000005', 'Debian 12 · High',
     'Изолированная Debian 12 VM с прямым SSH-доступом.',
     'high', 'high_vm', 'ssh', '{"os_profile":"debian_ssh"}'::jsonb,
     '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb),
    ('6b6f7a79-6176-4b61-8000-000000000006', 'Arch Linux · High',
     'Изолированная Arch Linux VM с прямым SSH-доступом.',
     'high', 'high_vm', 'ssh', '{"os_profile":"arch_linux_ssh"}'::jsonb,
     '{"cpu_cores":0.5,"memory_mb":128,"pids":64}'::jsonb)
ON CONFLICT (id) DO NOTHING;
