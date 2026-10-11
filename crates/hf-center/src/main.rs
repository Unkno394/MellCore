use std::{
    collections::HashMap,
    io::{Write, copy},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine as _;
use clap::Parser;
use hf_core::{
    AgentCommand, AgentRegistration, BootstrapScript, CoreError, HighUbuntuDeployment,
    RemoteBootstrap, SshBootstrapTarget,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::Session;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "HF_CENTER_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Statically built hf-agent artifact to upload during first installation.
    #[arg(long, env = "HF_AGENT_BINARY")]
    agent_binary: PathBuf,
    /// OCI/Docker archive of a prebuilt honeyforge-low image. This avoids compiling it on a VPS.
    #[arg(long, env = "HF_KOZYAVKA_IMAGE_ARCHIVE")]
    kozyavka_image_archive: Option<PathBuf>,
    /// Statically built Dispatcher artifact. Required before a VPS can host shared-port groups.
    #[arg(long, env = "HF_DISPATCHER_BINARY")]
    dispatcher_binary: Option<PathBuf>,
    /// Tar.gz with `high-ubuntu-ssh`; copied to a VPS during bootstrap for later High commands.
    #[arg(long, env = "HF_HIGH_UBUNTU_RECIPE_ARCHIVE")]
    high_ubuntu_recipe_archive: Option<PathBuf>,
    /// HTTPS URL agents use after first installation. This is not the SSH address.
    #[arg(long, env = "HF_PUBLIC_CENTER_URL")]
    public_center_url: String,
}

#[derive(Clone)]
struct AppState {
    enrollment_tokens: Arc<Mutex<HashMap<String, Uuid>>>,
    bootstrapper: Arc<dyn RemoteBootstrap>,
    public_center_url: Arc<str>,
}

#[derive(Debug, Deserialize)]
struct BootstrapRequest {
    host: String,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    ssh_user: String,
    /// Used only for this request. Exactly one of password or private key is required.
    ssh_password: Option<String>,
    /// PEM private key. Send this over the panel's HTTPS connection only; never store or log it.
    ssh_private_key: Option<String>,
    /// Optional passphrase for `ssh_private_key`.
    ssh_key_passphrase: Option<String>,
    /// OpenSSH-style server host-key fingerprint: `SHA256:<base64-without-padding>`.
    known_host_sha256: String,
    /// Optional first trap, deployed by the newly installed agent without a second SSH session.
    initial_high_ubuntu: Option<InitialHighUbuntuRequest>,
}

#[derive(Debug, Deserialize)]
struct InitialHighUbuntuRequest {
    /// Optional absolute path of a custom QCOW2 image. Omit it to use the agent-managed
    /// official Ubuntu 24.04 cloud image.
    #[serde(default)]
    base_image: Option<String>,
    external_ssh_port: u16,
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    agent_id: Uuid,
    enrollment_token: String,
    initial_trap_id: Option<Uuid>,
    status: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistrationResponse {
    agent_id: Uuid,
    transport_credential: String,
}

fn default_ssh_port() -> u16 {
    22
}

/// Blocking SSH implementation, isolated behind `RemoteBootstrap` so the core remains transport-free.
struct SshBootstrapper {
    agent_binary: PathBuf,
    kozyavka_image_archive: Option<PathBuf>,
    dispatcher_binary: Option<PathBuf>,
    high_ubuntu_recipe_archive: Option<PathBuf>,
}

#[async_trait::async_trait]
impl RemoteBootstrap for SshBootstrapper {
    async fn install_agent(
        &self,
        target: SshBootstrapTarget,
        script: BootstrapScript,
    ) -> Result<(), CoreError> {
        let agent_binary = self.agent_binary.clone();
        let kozyavka_image_archive = self.kozyavka_image_archive.clone();
        let dispatcher_binary = self.dispatcher_binary.clone();
        let high_ubuntu_recipe_archive = self.high_ubuntu_recipe_archive.clone();
        tokio::task::spawn_blocking(move || {
            run_ssh_install(
                target,
                script,
                agent_binary,
                kozyavka_image_archive,
                dispatcher_binary,
                high_ubuntu_recipe_archive,
            )
        })
        .await
        .map_err(|error| CoreError::Transport(format!("SSH task failed: {error}")))?
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "hf_center=info".into()),
        )
        .init();
    let args = Args::parse();
    if args.public_center_url.contains(['\n', '\r', '"'])
        || args.public_center_url.trim().is_empty()
    {
        anyhow::bail!("HF_PUBLIC_CENTER_URL must be a non-empty URL without quotes or newlines");
    }
    let listen = args.listen;
    let app = Router::new()
        .route("/v1/agents/bootstrap", post(bootstrap))
        .route("/v1/agents/register", post(register))
        .with_state(AppState {
            enrollment_tokens: Arc::default(),
            bootstrapper: Arc::new(SshBootstrapper {
                agent_binary: args.agent_binary,
                kozyavka_image_archive: args.kozyavka_image_archive,
                dispatcher_binary: args.dispatcher_binary,
                high_ubuntu_recipe_archive: args.high_ubuntu_recipe_archive,
            }),
            public_center_url: Arc::from(args.public_center_url),
        });
    info!(address = %listen, "HoneyForge center listening");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn bootstrap(
    State(state): State<AppState>,
    Json(request): Json<BootstrapRequest>,
) -> Result<Json<BootstrapResponse>, StatusCode> {
    validate_bootstrap_request(&request)?;
    let authentication = if request.ssh_password.is_some() {
        "password"
    } else {
        "private_key"
    };
    info!(host = %request.host, port = request.ssh_port, user = %request.ssh_user, authentication, "starting SSH bootstrap");
    let auth = match (request.ssh_password, request.ssh_private_key) {
        (Some(password), None) => hf_core::SshAuthentication::Password(password),
        (None, Some(pem)) => hf_core::SshAuthentication::PrivateKey {
            pem,
            passphrase: request.ssh_key_passphrase,
        },
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let agent_id = Uuid::new_v4();
    let token = Uuid::new_v4().to_string();
    let initial_trap_id = request.initial_high_ubuntu.as_ref().map(|_| Uuid::new_v4());
    let initial_command_json = match (request.initial_high_ubuntu, initial_trap_id) {
        (Some(high), Some(trap_id)) => Some(
            serde_json::to_vec(&AgentCommand::DeployHighUbuntu(HighUbuntuDeployment {
                command_id: Uuid::new_v4(),
                trap_id,
                base_image: high.base_image.unwrap_or_else(|| {
                    "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img".into()
                }),
                external_ssh_port: high.external_ssh_port,
            }))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        ),
        (None, None) => None,
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let script = BootstrapScript {
        contents: render_install_script(&token, &state.public_center_url),
        initial_command_json,
    };
    // Do not log `request` or interpolate the SSH password into a command.
    let target = SshBootstrapTarget {
        host: request.host,
        port: request.ssh_port,
        user: request.ssh_user,
        auth,
        known_host_sha256: request.known_host_sha256,
    };
    if let Err(error) = state.bootstrapper.install_agent(target, script).await {
        warn!(%error, "bootstrap failed");
        return Err(StatusCode::BAD_GATEWAY);
    }
    state
        .enrollment_tokens
        .lock()
        .await
        .insert(token.clone(), agent_id);
    Ok(Json(BootstrapResponse {
        agent_id,
        enrollment_token: token,
        initial_trap_id,
        status: "bootstrap_started",
    }))
}

fn validate_bootstrap_request(request: &BootstrapRequest) -> Result<(), StatusCode> {
    let host_is_invalid = request.host.trim().is_empty()
        || request.host != request.host.trim()
        || request.host.starts_with('[')
        || request.host.ends_with(']')
        || request
            .host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    if host_is_invalid || request.ssh_port == 0 || request.ssh_user.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let Some(encoded_fingerprint) = request.known_host_sha256.strip_prefix("SHA256:") else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let fingerprint_is_valid = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded_fingerprint)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false);
    if !fingerprint_is_valid {
        return Err(StatusCode::BAD_REQUEST);
    }

    match (
        &request.ssh_password,
        &request.ssh_private_key,
        &request.ssh_key_passphrase,
    ) {
        (Some(password), None, None) if !password.is_empty() => validate_initial_high(request),
        (None, Some(pem), passphrase)
            if !pem.is_empty()
                && pem.len() <= 64 * 1024
                && pem.contains("-----BEGIN ")
                && pem.contains("PRIVATE KEY-----")
                && pem.contains("-----END ")
                && passphrase.as_ref().is_none_or(|value| !value.is_empty()) =>
        {
            validate_initial_high(request)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

fn validate_initial_high(request: &BootstrapRequest) -> Result<(), StatusCode> {
    let Some(high) = &request.initial_high_ubuntu else {
        return Ok(());
    };
    let custom_image_is_invalid = high.base_image.as_ref().is_some_and(|base_image| {
        !base_image.starts_with('/')
            || base_image.len() > 4096
            || base_image.chars().any(|character| character.is_control())
    });
    if high.external_ssh_port == 0 || custom_image_is_invalid {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

async fn register(
    State(state): State<AppState>,
    Json(request): Json<AgentRegistration>,
) -> Result<Json<RegistrationResponse>, StatusCode> {
    let Some(agent_id) = state
        .enrollment_tokens
        .lock()
        .await
        .remove(&request.enrollment_token)
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    // Provision an individual Hysteria credential here; it must be revocable by agent_id.
    Ok(Json(RegistrationResponse {
        agent_id,
        transport_credential: format!("hf-dev-{}", Uuid::new_v4()),
    }))
}

fn render_install_script(token: &str, center_url: &str) -> String {
    let mut script = format!(
        "#!/bin/sh\nset -eu\nif [ \"$(id -u)\" -eq 0 ]; then SUDO=''; else SUDO='sudo -n'; fi\nensure_docker() {{\n  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then return; fi\n  [ -r /etc/os-release ] || {{ echo 'Cannot identify Linux distribution' >&2; exit 1; }}\n  . /etc/os-release\n  case \"$ID\" in\n    ubuntu|debian|linuxmint)\n      $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update\n      $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2\n      $SUDO systemctl enable --now docker\n      ;;\n    fedora)\n      $SUDO dnf install -y dnf-plugins-core\n      $SUDO dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo\n      $SUDO dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin\n      $SUDO systemctl enable --now docker\n      ;;\n    rhel|centos|rocky|almalinux)\n      $SUDO dnf install -y dnf-plugins-core\n      $SUDO dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo\n      $SUDO dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin\n      $SUDO systemctl enable --now docker\n      ;;\n    arch|manjaro)\n      $SUDO pacman -Sy --noconfirm docker docker-compose\n      $SUDO systemctl enable --now docker\n      ;;\n    alpine)\n      $SUDO apk add docker docker-cli-compose\n      $SUDO rc-update add docker default\n      $SUDO service docker start\n      ;;\n    *) echo \"Unsupported Linux distribution: $ID\" >&2; exit 1 ;;\n  esac\n  docker compose version >/dev/null\n}}\n$SUDO install -d -m 0700 /etc/honeyforge\n$SUDO install -m 0755 /tmp/hf-agent-bootstrap /usr/local/bin/hf-agent\nif [ -f /tmp/hf-kozyavka-image.tar ]; then\n  ensure_docker\n  $SUDO docker load -i /tmp/hf-kozyavka-image.tar\n  rm -f /tmp/hf-kozyavka-image.tar\nfi\nprintf '%s' '{token}' | $SUDO tee /etc/honeyforge/enrollment-token >/dev/null\nif command -v systemctl >/dev/null 2>&1; then\n  $SUDO tee /etc/systemd/system/hf-agent.service >/dev/null <<'UNIT'\n[Unit]\nDescription=HoneyForge agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nEnvironment=HF_CENTER_URL={center_url}\nEnvironment=HF_KOZYAVKA_IMAGE=honeyforge-low:local\nExecStart=/usr/local/bin/hf-agent\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\nUNIT\n  $SUDO systemctl daemon-reload\n  $SUDO systemctl enable --now hf-agent.service\nelif command -v rc-update >/dev/null 2>&1; then\n  $SUDO tee /etc/init.d/hf-agent >/dev/null <<'OPENRC'\n#!/sbin/openrc-run\nname=\"HoneyForge agent\"\ncommand=\"/usr/local/bin/hf-agent\"\ncommand_background=\"yes\"\npidfile=\"/run/hf-agent.pid\"\nexport HF_CENTER_URL={center_url}\nexport HF_KOZYAVKA_IMAGE=honeyforge-low:local\nOPENRC\n  $SUDO chmod 0755 /etc/init.d/hf-agent\n  $SUDO rc-update add hf-agent default\n  $SUDO rc-service hf-agent start\nelse\n  echo 'Unsupported init system: systemd or OpenRC is required' >&2\n  exit 1\nfi\nrm -f /tmp/hf-agent-bootstrap\n"
    );
    script.push_str(
        "\nif [ -f /tmp/hf-high-ubuntu-ssh.tar.gz ]; then\n  $SUDO install -d -m 0755 /usr/local/lib/honeyforge\n  $SUDO tar -xzf /tmp/hf-high-ubuntu-ssh.tar.gz -C /usr/local/lib/honeyforge\n  $SUDO chmod -R a-w /usr/local/lib/honeyforge/high-ubuntu-ssh/cloud-init\n  $SUDO find /usr/local/lib/honeyforge/high-ubuntu-ssh/scripts -type f -exec chmod 0755 {} \\;\n  rm -f /tmp/hf-high-ubuntu-ssh.tar.gz\nfi\nif [ -f /tmp/hf-initial-command.json ]; then\n  $SUDO install -d -m 0700 /var/lib/honeyforge/inbox\n  $SUDO install -m 0600 /tmp/hf-initial-command.json /var/lib/honeyforge/inbox/initial-high.json\n  rm -f /tmp/hf-initial-command.json\nfi\n",
    );
    script
}

fn run_ssh_install(
    target: SshBootstrapTarget,
    script: BootstrapScript,
    agent_binary: PathBuf,
    kozyavka_image_archive: Option<PathBuf>,
    dispatcher_binary: Option<PathBuf>,
    high_ubuntu_recipe_archive: Option<PathBuf>,
) -> Result<(), CoreError> {
    let authentication = match &target.auth {
        hf_core::SshAuthentication::Password(_) => "password",
        hf_core::SshAuthentication::PrivateKey { .. } => "private_key",
    };
    debug!(host = %target.host, port = target.port, user = %target.user, authentication, "opening SSH TCP connection");
    // `(&str, u16)` correctly resolves host names, IPv4, and raw IPv6 addresses.
    // Do not accept bracketed IPv6 here: brackets are URL syntax, not a DNS/SSH hostname.
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|error| CoreError::Transport(format!("SSH TCP connection failed: {error}")))?;
    debug!(host = %target.host, port = target.port, "SSH TCP connection established");
    let mut session = Session::new()
        .map_err(|error| CoreError::Transport(format!("cannot create SSH session: {error}")))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|error| CoreError::Transport(format!("SSH handshake failed: {error}")))?;
    debug!(host = %target.host, "SSH handshake completed; verifying host key");
    let (host_key, _) = session
        .host_key()
        .ok_or_else(|| CoreError::Transport("server did not provide an SSH host key".into()))?;
    let actual_fingerprint = format!(
        "SHA256:{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            Sha256::digest(host_key)
        )
    );
    if actual_fingerprint != target.known_host_sha256 {
        warn!(host = %target.host, actual_fingerprint = %actual_fingerprint, "SSH host-key fingerprint mismatch");
        return Err(CoreError::Transport(
            "SSH host-key fingerprint mismatch".into(),
        ));
    }
    info!(host = %target.host, "SSH host-key verified");
    match &target.auth {
        hf_core::SshAuthentication::Password(password) => session
            .userauth_password(&target.user, password)
            .map_err(|error| {
                CoreError::Transport(format!("SSH password authentication failed: {error}"))
            })?,
        hf_core::SshAuthentication::PrivateKey { pem, passphrase } => session
            .userauth_pubkey_memory(&target.user, None, pem, passphrase.as_deref())
            .map_err(|error| {
                CoreError::Transport(format!("SSH public-key authentication failed: {error}"))
            })?,
    }
    if !session.authenticated() {
        return Err(CoreError::Transport(
            "SSH authentication was rejected".into(),
        ));
    }
    info!(host = %target.host, user = %target.user, "SSH authentication succeeded");
    let metadata = std::fs::metadata(&agent_binary)
        .map_err(|error| CoreError::Transport(format!("cannot read agent artifact: {error}")))?;
    let mut local_binary = std::fs::File::open(&agent_binary)
        .map_err(|error| CoreError::Transport(format!("cannot open agent artifact: {error}")))?;
    let mut remote_binary = session
        .scp_send(
            std::path::Path::new("/tmp/hf-agent-bootstrap"),
            0o700,
            metadata.len(),
            None,
        )
        .map_err(|error| CoreError::Transport(format!("cannot start agent upload: {error}")))?;
    debug!(host = %target.host, bytes = metadata.len(), "uploading hf-agent over SCP");
    copy(&mut local_binary, &mut remote_binary)
        .map_err(|error| CoreError::Transport(format!("cannot upload agent artifact: {error}")))?;
    remote_binary
        .send_eof()
        .map_err(|error| CoreError::Transport(format!("cannot finish agent upload: {error}")))?;
    remote_binary
        .wait_close()
        .map_err(|error| CoreError::Transport(format!("agent upload failed: {error}")))?;
    debug!(host = %target.host, "agent artifact upload completed");
    if let Some(archive) = kozyavka_image_archive {
        upload_file(&session, &archive, "/tmp/hf-kozyavka-image.tar", 0o600)?;
        debug!(host = %target.host, "kozyavka image archive upload completed");
    }
    if let Some(dispatcher) = dispatcher_binary {
        upload_file(&session, &dispatcher, "/tmp/hf-dispatcher-bootstrap", 0o700)?;
        debug!(host = %target.host, "dispatcher artifact upload completed");
    }
    if let Some(archive) = high_ubuntu_recipe_archive {
        upload_file(&session, &archive, "/tmp/hf-high-ubuntu-ssh.tar.gz", 0o600)?;
        debug!(host = %target.host, "High Ubuntu recipe archive upload completed");
    }
    if let Some(command) = &script.initial_command_json {
        let mut remote = session
            .scp_send(
                std::path::Path::new("/tmp/hf-initial-command.json"),
                0o600,
                command.len() as u64,
                None,
            )
            .map_err(|error| {
                CoreError::Transport(format!("cannot start initial trap command upload: {error}"))
            })?;
        remote.write_all(command).map_err(|error| {
            CoreError::Transport(format!("cannot upload initial trap command: {error}"))
        })?;
        remote.send_eof().map_err(|error| {
            CoreError::Transport(format!(
                "cannot finish initial trap command upload: {error}"
            ))
        })?;
        remote.wait_close().map_err(|error| {
            CoreError::Transport(format!("initial trap command upload failed: {error}"))
        })?;
        debug!(host = %target.host, "initial trap command upload completed");
    }
    let mut channel = session
        .channel_session()
        .map_err(|error| CoreError::Transport(format!("cannot open SSH channel: {error}")))?;
    channel
        .exec("sh -s")
        .map_err(|error| CoreError::Transport(format!("cannot start remote installer: {error}")))?;
    channel
        .write_all(script.contents.as_bytes())
        .map_err(|error| CoreError::Transport(format!("cannot upload installer: {error}")))?;
    channel
        .send_eof()
        .map_err(|error| CoreError::Transport(format!("cannot finish installer input: {error}")))?;
    channel
        .wait_close()
        .map_err(|error| CoreError::Transport(format!("remote installer failed: {error}")))?;
    if channel.exit_status().unwrap_or(-1) != 0 {
        return Err(CoreError::Transport(
            "remote installer returned non-zero exit status".into(),
        ));
    }
    info!(host = %target.host, "remote hf-agent service installed and started");
    Ok(())
}

fn upload_file(
    session: &Session,
    local_path: &PathBuf,
    remote_path: &str,
    mode: i32,
) -> Result<(), CoreError> {
    let metadata = std::fs::metadata(local_path)
        .map_err(|error| CoreError::Transport(format!("cannot read upload artifact: {error}")))?;
    let mut local = std::fs::File::open(local_path)
        .map_err(|error| CoreError::Transport(format!("cannot open upload artifact: {error}")))?;
    let mut remote = session
        .scp_send(
            std::path::Path::new(remote_path),
            mode,
            metadata.len(),
            None,
        )
        .map_err(|error| CoreError::Transport(format!("cannot start artifact upload: {error}")))?;
    copy(&mut local, &mut remote)
        .map_err(|error| CoreError::Transport(format!("cannot upload artifact: {error}")))?;
    remote
        .send_eof()
        .map_err(|error| CoreError::Transport(format!("cannot finish artifact upload: {error}")))?;
    remote
        .wait_close()
        .map_err(|error| CoreError::Transport(format!("artifact upload failed: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn password_request(host: &str) -> BootstrapRequest {
        BootstrapRequest {
            host: host.into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            ssh_password: Some("secret".into()),
            ssh_private_key: None,
            ssh_key_passphrase: None,
            known_host_sha256: FINGERPRINT.into(),
            initial_high_ubuntu: None,
        }
    }

    #[test]
    fn accepts_ipv4_and_raw_ipv6_with_password() {
        assert!(validate_bootstrap_request(&password_request("203.0.113.42")).is_ok());
        assert!(validate_bootstrap_request(&password_request("2001:db8::42")).is_ok());
    }

    #[test]
    fn accepts_pem_key_with_optional_passphrase() {
        let mut request = password_request("vpn.example.test");
        request.ssh_password = None;
        request.ssh_private_key = Some(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nkey-data\n-----END OPENSSH PRIVATE KEY-----"
                .into(),
        );
        request.ssh_key_passphrase = Some("passphrase".into());
        assert!(validate_bootstrap_request(&request).is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_malformed_connection_data() {
        let mut request = password_request("[2001:db8::42]");
        assert!(validate_bootstrap_request(&request).is_err());
        request.host = "203.0.113.42".into();
        request.ssh_private_key =
            Some("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".into());
        assert!(validate_bootstrap_request(&request).is_err());
        request.ssh_private_key = None;
        request.known_host_sha256 = "SHA256:not-a-host-key".into();
        assert!(validate_bootstrap_request(&request).is_err());
    }

    #[test]
    fn validates_initial_high_vm_request() {
        let mut request = password_request("203.0.113.42");
        request.initial_high_ubuntu = Some(InitialHighUbuntuRequest {
            base_image: Some("/var/lib/honeyforge/images/ubuntu-24.04.qcow2".into()),
            external_ssh_port: 1488,
        });
        assert!(validate_bootstrap_request(&request).is_ok());

        request.initial_high_ubuntu.as_mut().unwrap().base_image = Some("relative.qcow2".into());
        assert!(validate_bootstrap_request(&request).is_err());
        request.initial_high_ubuntu.as_mut().unwrap().base_image = Some("/image.qcow2".into());
        request
            .initial_high_ubuntu
            .as_mut()
            .unwrap()
            .external_ssh_port = 0;
        assert!(validate_bootstrap_request(&request).is_err());
    }

    #[test]
    fn installer_script_selects_platform_and_init_system() {
        let script = render_install_script("token", "https://center.example");
        for platform in [
            "ubuntu|debian|linuxmint",
            "fedora",
            "rhel|centos|rocky|almalinux",
            "arch|manjaro",
            "alpine",
        ] {
            assert!(script.contains(platform), "missing {platform} branch");
        }
        assert!(script.contains("docker-compose-plugin"));
        assert!(script.contains("rc-update add hf-agent default"));
        assert!(script.contains("systemctl enable --now hf-agent.service"));
        assert!(script.contains("hf-high-ubuntu-ssh.tar.gz"));
        assert!(script.contains("/usr/local/lib/honeyforge"));
    }
}
