use std::{sync::Arc, time::Duration};

use pritvoryashka::{Config, ssh, telemetry::EventEmitter};
use russh::{ChannelMsg, client, keys::PublicKeyOrCertificate};

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires permission to open loopback TCP listeners"]
async fn real_ssh_client_authenticates_and_executes_virtual_command() {
    let directory = tempfile::tempdir().unwrap();
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let key_path = directory.path().join("host_ed25519");
    tokio::fs::write(
        &key_path,
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let mut config: Config =
        serde_json::from_str(include_str!("../pritvoryashka.example.json")).unwrap();
    config.bind = free_address();
    config.health_bind = free_address();
    config.host_key = key_path;
    config.telemetry.jsonl_path = Some(directory.path().join("events.jsonl"));
    let emitter = EventEmitter::start(
        config.telemetry.clone(),
        config.trap_id,
        config.server_id,
        config.agent_id,
        config.bind.port(),
    )
    .unwrap();
    let address = config.bind;
    let server = tokio::spawn(ssh::run(config, emitter));

    let client_config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..client::Config::default()
    });
    let mut handle = loop {
        match client::connect(client_config.clone(), address, Client).await {
            Ok(handle) => break handle,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    let auth = handle
        .authenticate_password("root", "anything")
        .await
        .unwrap();
    assert!(auth.success());
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "pwd").await.unwrap();
    let mut output = Vec::new();
    let mut status = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            _ => {}
        }
    }
    assert_eq!(status, Some(0));
    assert_eq!(String::from_utf8(output).unwrap(), "/home/admin\r\n");
    handle
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    server.abort();
}
