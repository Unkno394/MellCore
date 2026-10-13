use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use hf_core::SHARED_SSH_IDENTIFICATION;
use russh::{
    Channel, ChannelId, MethodKind, MethodSet, Pty,
    keys::load_secret_key,
    server::{self, Auth, ChannelOpenHandle, Msg, Server as _, Session},
};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::{
    config::{AuthPolicy, Config, CredentialCapture},
    session::SessionState,
    shell::{FsActionKind, ShellOutput},
    telemetry::{EventEmitter, SessionTelemetry},
};

use super::auth::constant_time_eq;

fn advertised_auth_methods() -> MethodSet {
    [MethodKind::Password].as_slice().into()
}

fn reject_auth() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(advertised_auth_methods()),
        partial_success: false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("cannot load SSH host key: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("cannot bind SSH listener: {0}")]
    Io(#[from] std::io::Error),
    #[error("configured authentication password environment variable is missing")]
    MissingPassword,
}

pub async fn run(config: Config, emitter: EventEmitter) -> Result<(), ServerError> {
    let key = load_secret_key(&config.host_key, None)?;
    let ssh_config = Arc::new(server::Config {
        server_id: russh::SshId::Standard(SHARED_SSH_IDENTIFICATION.into()),
        methods: advertised_auth_methods(),
        keys: vec![key],
        max_auth_attempts: config.auth.max_attempts,
        inactivity_timeout: Some(config.idle_timeout()),
        auth_rejection_time: Duration::from_millis(750),
        maximum_packet_size: 32 * 1024,
        window_size: 256 * 1024,
        ..server::Config::default()
    });
    let listener = TcpListener::bind(config.bind).await?;
    let configured_password = config
        .auth
        .password_env
        .as_deref()
        .and_then(|name| std::env::var(name).ok());
    if config.auth.policy == AuthPolicy::Configured && configured_password.is_none() {
        return Err(ServerError::MissingPassword);
    }
    let mut server = HoneypotServer {
        shared: Arc::new(Shared {
            semaphore: Arc::new(Semaphore::new(config.max_connections)),
            configured_password,
            config,
            emitter,
        }),
    };
    tracing::info!(address = %listener.local_addr()?, "Pritvoryashka SSH listener started");
    let running = server.run_on_socket(ssh_config, &listener);
    let handle = running.handle();
    tokio::pin!(running);
    tokio::select! {
        result = &mut running => result?,
        () = shutdown() => {
            handle.shutdown("server shutdown".into());
            running.await?;
        }
    }
    Ok(())
}

struct Shared {
    semaphore: Arc<Semaphore>,
    config: Config,
    configured_password: Option<String>,
    emitter: EventEmitter,
}

struct HoneypotServer {
    shared: Arc<Shared>,
}

impl server::Server for HoneypotServer {
    type Handler = Handler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Self::Handler {
        let peer = peer.unwrap_or_else(|| "127.0.0.1:0".parse().expect("static socket address"));
        let permit = self.shared.semaphore.clone().try_acquire_owned().ok();
        let telemetry = self.shared.emitter.session(peer);
        telemetry.emit(
            "connection.opened",
            json!({"accepted":permit.is_some(),"active_limit":self.shared.config.max_connections}),
        );
        Handler {
            shared: self.shared.clone(),
            state: SessionState::new(
                &self.shared.config.hostname,
                self.shared.config.max_input_bytes,
            ),
            telemetry,
            permit,
            auth_attempts: 0,
            authenticated_user: None,
            channels: HashSet::new(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        tracing::debug!(%error, "SSH session ended with protocol error");
    }
}

struct Handler {
    shared: Arc<Shared>,
    state: SessionState,
    telemetry: SessionTelemetry,
    permit: Option<OwnedSemaphorePermit>,
    auth_attempts: usize,
    authenticated_user: Option<String>,
    channels: HashSet<ChannelId>,
}

impl Handler {
    fn end_session(&mut self, reason: &str) {
        if self.state.session_ended || !self.state.shell_started {
            return;
        }
        self.state.session_ended = true;
        let metrics = self.state.shell.metrics();
        self.telemetry.emit(
            "session.ended",
            json!({
                "reason":reason,
                "deception_depth":metrics.stages_reached,
                "unique_objects":metrics.unique_objects,
                "stage_transitions":metrics.transitions
            }),
        );
    }

    fn record_output(&self, line: &str, result: &ShellOutput) {
        let command = line.split_whitespace().next().unwrap_or("");
        self.telemetry.emit(
            "command.executed",
            json!({"command":command,"input":line,"exit_status":result.exit_status}),
        );
        for action in &result.fs_actions {
            let event_type = match action.kind {
                FsActionKind::Accessed => "filesystem.accessed",
                FsActionKind::Modified => "filesystem.modified",
            };
            self.telemetry.emit(
                event_type,
                json!({"operation":action.operation,"path":action.path}),
            );
        }
        for interaction in &result.virtual_interactions {
            self.telemetry.emit(
                "deception.interaction",
                json!({
                    "bait":interaction.bait,
                    "action":interaction.action,
                    "target":interaction.target,
                    "success":interaction.success
                }),
            );
        }
        if let Some(change) = &result.deception {
            self.telemetry.emit(
                "deception.triggered",
                json!({"trigger":change.trigger,"artifact":change.artifact}),
            );
            self.telemetry.emit(
                "deception.stage_changed",
                json!({"from":change.from,"to":change.to}),
            );
        }
    }

    fn send_shell_output(
        &mut self,
        channel: ChannelId,
        result: ShellOutput,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if !result.output.is_empty() {
            session.data(channel, terminal_bytes(&result.output))?;
        }
        if result.close {
            self.end_session("logout");
            session.exit_status_request(channel, result.exit_status)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if self.state.shell_started {
            session.data(channel, self.state.shell.prompt().into_bytes())?;
        }
        Ok(())
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.end_session("connection_closed");
        self.telemetry.emit(
            "connection.closed",
            json!({"authenticated":self.authenticated_user.is_some()}),
        );
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.record_auth(user, None, false);
        Ok(reject_auth())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts = self.auth_attempts.saturating_add(1);
        let accepted = self.permit.is_some()
            && self.auth_attempts <= self.shared.config.auth.max_attempts
            && match self.shared.config.auth.policy {
                AuthPolicy::AcceptAll => true,
                AuthPolicy::RejectAll => false,
                AuthPolicy::Configured => {
                    self.shared.config.auth.username.as_deref() == Some(user)
                        && self
                            .shared
                            .configured_password
                            .as_deref()
                            .is_some_and(|expected| {
                                constant_time_eq(expected.as_bytes(), password.as_bytes())
                            })
                }
            };
        self.record_auth(user, Some(password), accepted);
        if accepted {
            self.authenticated_user = Some(user.to_owned());
            Ok(Auth::Accept)
        } else {
            Ok(reject_auth())
        }
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.telemetry.emit(
            "auth.succeeded",
            json!({"username":self.authenticated_user}),
        );
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.permit.is_some() && self.channels.is_empty() {
            self.channels.insert(channel.id());
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.terminal_columns = col_width.clamp(20, 1000);
        self.state.terminal_rows = row_height.clamp(5, 1000);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.terminal_columns = col_width.clamp(20, 1000);
        self.state.terminal_rows = row_height.clamp(5, 1000);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.shell_started {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.state.shell_started = true;
        session.channel_success(channel)?;
        self.telemetry
            .emit("session.started", json!({"mode":"shell"}));
        session.data(
            channel,
            terminal_bytes(&format!(
                "Ubuntu 22.04.4 LTS {}\n\n{}",
                self.shared.config.hostname,
                self.state.shell.prompt()
            )),
        )?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.len() > self.shared.config.max_input_bytes {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let line = String::from_utf8_lossy(data).into_owned();
        session.channel_success(channel)?;
        self.state.shell_started = true;
        self.telemetry
            .emit("session.started", json!({"mode":"exec"}));
        let result = self.state.shell.execute(&line, chrono::Utc::now());
        self.record_output(&line, &result);
        if !result.output.is_empty() {
            session.data(channel, terminal_bytes(&result.output))?;
        }
        session.exit_status_request(channel, result.exit_status)?;
        self.end_session("exec_completed");
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.state.shell_started {
            return Ok(());
        }
        for &byte in data {
            match byte {
                3 => {
                    self.state.input.clear();
                    session.data(channel, terminal_bytes("^C\n"))?;
                    session.data(channel, self.state.shell.prompt().into_bytes())?;
                }
                4 if self.state.input.is_empty() => {
                    self.end_session("eof");
                    session.eof(channel)?;
                    session.close(channel)?;
                    break;
                }
                8 | 127 if self.state.input.pop().is_some() => {
                    session.data(channel, b"\x08 \x08".to_vec())?;
                }
                b'\r' | b'\n' => {
                    if byte == b'\n' && self.state.last_was_cr {
                        self.state.last_was_cr = false;
                        continue;
                    }
                    self.state.last_was_cr = byte == b'\r';
                    session.data(channel, b"\r\n".to_vec())?;
                    let line = self.state.input.clone();
                    let result = self.state.execute_line();
                    self.record_output(&line, &result);
                    self.send_shell_output(channel, result, session)?;
                }
                32..=126 if self.state.input.len() < self.shared.config.max_input_bytes => {
                    self.state.input.push(char::from(byte));
                    session.data(channel, vec![byte])?;
                    self.state.last_was_cr = false;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        self.end_session("channel_closed");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.end_session("eof");
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl Handler {
    fn record_auth(&self, user: &str, password: Option<&str>, accepted: bool) {
        let mut payload = serde_json::Map::new();
        if self.shared.config.auth.capture != CredentialCapture::None {
            payload.insert("username".into(), Value::String(user.into()));
        }
        if self.shared.config.auth.capture == CredentialCapture::Password
            && let Some(password) = password
        {
            payload.insert("password".into(), Value::String(password.into()));
        }
        payload.insert("accepted".into(), Value::Bool(accepted));
        self.telemetry
            .emit("auth.attempted", Value::Object(payload));
        if !accepted {
            self.telemetry.emit("auth.failed", json!({"username":user}));
        }
    }
}

fn terminal_bytes(value: &str) -> Vec<u8> {
    value
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

async fn shutdown() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to register Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to register SIGTERM handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn middle_advertises_only_password_authentication() {
        let methods = advertised_auth_methods();
        assert!(methods.contains(&MethodKind::Password));
        assert!(!methods.contains(&MethodKind::PublicKey));
        assert!(!methods.contains(&MethodKind::HostBased));
        assert!(!methods.contains(&MethodKind::KeyboardInteractive));
    }

    #[test]
    fn rejected_password_keeps_password_available_for_retry() {
        match reject_auth() {
            Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            } => {
                assert!(methods.contains(&MethodKind::Password));
                assert!(!methods.contains(&MethodKind::PublicKey));
                assert!(!methods.contains(&MethodKind::HostBased));
                assert!(!methods.contains(&MethodKind::KeyboardInteractive));
            }
            _ => panic!("rejected auth must preserve the advertised methods"),
        }
    }
}
