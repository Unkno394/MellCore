# Production Hysteria edge

`server.yaml.example` is the public Hysteria 2 edge configuration. Run Hysteria on the Center host,
with UDP/443 open. The Center Kazik receiver remains private on `127.0.0.1:44000`; the Hysteria
server forwards the agent's SOCKS5 UDP association there.

Start the Center with all three values below. They make its first SSH bootstrap upload the already
verified Hysteria binary, then return the endpoint and SNI to an agent during one-time registration:

```sh
HF_HYSTERIA_BINARY=/secure/artifacts/hysteria \
HF_HYSTERIA_SERVER=hysteria.example.com:443 \
HF_HYSTERIA_SNI=hysteria.example.com \
hf-center --agent-binary /secure/artifacts/hf-agent --public-center-url https://center.example.com
```

The agent writes `/etc/honeyforge/hysteria-client.yaml` mode `0600` and enables
`hf-hysteria-client.service`. Its client config does not set `tls.insecure`, so the SNI certificate
must be valid. Each registration creates a distinct credential; Hysteria calls the loopback Center
endpoint to validate it.

For the temporary Control Plane bridge, configure `HF_CONTROL_TOKEN` on the Center. The panel may
queue a validated `AgentCommand` at `POST /v1/agents/{agent_id}/commands` with that value in
`x-honeyforge-control-token`. The Center delivers the oldest queued command on the next agent
heartbeat and retries it until `Applied` or `Duplicate ACK`; the agent executes through one bounded
Tokio worker queue and returns its result through the durable packet outbox. This endpoint returns
404 when no control token is configured; it is not a replacement for panel user/session auth.

This is the current boundary: credentials and queued Center commands are held in memory. Persisting
them, explicit revocation, and force-closing an already authenticated Hysteria session still need a
durable control-plane store and Hysteria session-control integration. Do not represent this template
as revocation-complete production deployment yet.
