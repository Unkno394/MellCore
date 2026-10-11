-- A direct trap owns an external port. Dispatcher members share that external port and own
-- distinct loopback target ports instead. The listener itself is represented by purpose=dispatcher.
ALTER TABLE server_ports DROP CONSTRAINT server_ports_pkey;

CREATE UNIQUE INDEX server_ports_external_listener_unique
ON server_ports(server_id, transport, host_port)
WHERE route_mode IS DISTINCT FROM 'dispatcher_backend';

CREATE UNIQUE INDEX server_ports_dispatcher_member_unique
ON server_ports(server_id, trap_id, transport, host_port)
WHERE route_mode = 'dispatcher_backend';

CREATE UNIQUE INDEX server_ports_dispatcher_target_unique
ON server_ports(server_id, transport, target_port)
WHERE route_mode = 'dispatcher_backend';
