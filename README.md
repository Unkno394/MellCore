# HoneyForge core

Initial Rust workspace for the center-to-agent enrollment path.

- `hf-core`: ports and protocol-independent domain contracts.
- `hf-center`: HTTP control-plane skeleton, one-time enrollment-token issuer, and bootstrap adapter boundary.
- `hf-agent`: registration client using the transport port.
- `honeypots/pritvoryashka`: native Rust Middle Interaction SSH honeypot with an isolated virtual shell and telemetry.
- `hf-core::math`: domain-independent ratios, percentages, Jaccard similarity and overlapping subsequence matching.

Build the agent for the VPS target, then run the center:

```sh
cargo build --release -p hf-agent
HF_AGENT_BINARY=target/release/hf-agent \
HF_PUBLIC_CENTER_URL=https://center.example.org \
cargo run -p hf-center -- --listen 127.0.0.1:8080
```

`POST /v1/agents/bootstrap` accepts a hostname, IPv4, or raw IPv6 address in `host`, optional `ssh_port`, `ssh_user`, and a mandatory `known_host_sha256` in OpenSSH form, e.g. `SHA256:...`. Exactly one authentication method is required: `ssh_password`, or `ssh_private_key` containing a PEM private key (plus optional `ssh_key_passphrase`). The center verifies the host-key fingerprint before authentication, SCP uploads the selected agent binary, and creates a root-owned systemd service. The password/private key exists only for the request and is neither logged nor persisted.

The supplied agent binary must be built for the target VPS architecture. The HTTP registration transport is a development adapter; the next transport adapter is Hysteria 2 UDP forwarding with TLS certificate validation. Before deployment, artifact authenticity must also be checked with a detached signature or trusted release manifest (the host-key check alone does not authenticate a local binary).

After registration the agent stays alive under `hf-agent.service`. It stores its identity and transport credential with mode `0600` below `/var/lib/honeyforge` and will not consume the enrollment token a second time after restart. Its Compose service creates one isolated project directory per future trap at `/var/lib/honeyforge/traps/<trap-id>/`; recipes and `docker compose up` are intentionally not enabled until signed trap recipes are available.
