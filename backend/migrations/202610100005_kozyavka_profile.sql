-- Add the existing standalone SSH banner honeypot to the shared catalog.
-- Preserve any previously configured kozyavka profile; never deploy a process.
INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config)
SELECT '6b6f7a79-6176-4b61-8000-000000000001', 'kozyavka',
       'Standalone Low SSH banner honeypot: sends a banner and closes the connection.',
       'low', 'kozyavka', 'ssh',
       '{"bind_address":"127.0.0.1","banner":"SSH-2.0-OpenSSH_9.6"}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM trap_profiles WHERE honeypot_type='kozyavka');
