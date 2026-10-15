mod ftp;
mod http;
mod redis;
mod sql;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};

use crate::{
    config::{Config, Distribution, NetworkListener},
    telemetry::{EventEmitter, SessionTelemetry},
};

#[derive(Default)]
pub(crate) struct VirtualState {
    pub redis: Mutex<HashMap<String, String>>,
    pub redis_hashes: Mutex<HashMap<String, HashMap<String, String>>>,
    pub virtual_files: Mutex<HashMap<String, Vec<u8>>>,
    pub bait_files: HashMap<String, hf_core::BaitFile>,
    pub sql_rows: HashMap<String, Vec<Vec<String>>>,
}

#[derive(Clone)]
pub(crate) struct ServiceContext {
    pub profiles: Arc<HashSet<String>>,
    pub state: Arc<VirtualState>,
    pub distribution: Distribution,
    pub max_input_bytes: usize,
    pub idle_timeout: Duration,
    pub ftp_data_port: Option<u16>,
    pub ftp_data_registry: Arc<FtpDataRegistry>,
}

#[derive(Default)]
pub(crate) struct FtpDataRegistry {
    waiters: tokio::sync::Mutex<VecDeque<(IpAddr, oneshot::Sender<TcpStream>)>>,
}

impl FtpDataRegistry {
    pub async fn register(&self, peer: IpAddr) -> oneshot::Receiver<TcpStream> {
        let (sender, receiver) = oneshot::channel();
        self.waiters.lock().await.push_back((peer, sender));
        receiver
    }

    async fn route(&self, peer: IpAddr, stream: TcpStream) -> bool {
        let mut waiters = self.waiters.lock().await;
        waiters.retain(|(_, sender)| !sender.is_closed());
        let Some(index) = waiters
            .iter()
            .position(|(expected_peer, _)| *expected_peer == peer)
        else {
            return false;
        };
        let (_, sender) = waiters.remove(index).expect("FTP data waiter index exists");
        sender.send(stream).is_ok()
    }
}

pub async fn run(config: Config, emitter: EventEmitter) -> io::Result<()> {
    if config.network_listeners.is_empty() {
        std::future::pending::<()>().await;
        return Ok(());
    }

    let mut listeners = Vec::with_capacity(config.network_listeners.len());
    for listener in &config.network_listeners {
        listeners.push((listener.clone(), TcpListener::bind(listener.bind).await?));
    }

    let profiles = Arc::new(config.vulnerability_profiles.iter().cloned().collect());
    let context = ServiceContext {
        profiles,
        state: Arc::new(initial_virtual_state(&config.baits)),
        distribution: config.distribution,
        max_input_bytes: config.max_input_bytes,
        idle_timeout: config.idle_timeout(),
        ftp_data_port: config
            .network_listeners
            .iter()
            .find(|listener| listener.service_type == "ftp_data")
            .and_then(|listener| listener.public_port),
        ftp_data_registry: Arc::new(FtpDataRegistry::default()),
    };
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    for (spec, listener) in listeners {
        tracing::info!(service = %spec.service_type, address = %listener.local_addr()?, "Middle vulnerability listener started");
        tasks.spawn(accept_loop(
            spec,
            listener,
            context.clone(),
            emitter.clone(),
            semaphore.clone(),
        ));
    }

    loop {
        tokio::select! {
            _ = shutdown() => return Ok(()),
            result = tasks.join_next() => match result {
                Some(Ok(Ok(()))) => return Err(io::Error::other("vulnerability listener stopped unexpectedly")),
                Some(Ok(Err(error))) => return Err(error),
                Some(Err(error)) => return Err(io::Error::other(format!("vulnerability listener task failed: {error}"))),
                None => return Ok(()),
            }
        }
    }
}

async fn accept_loop(
    spec: NetworkListener,
    listener: TcpListener,
    context: ServiceContext,
    emitter: EventEmitter,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        if spec.service_type == "ftp_data" {
            let telemetry = emitter.service_session(
                peer,
                spec.public_port.unwrap_or(spec.bind.port()),
                &spec.service_type,
            );
            telemetry.emit("connection.opened", json!({}));
            if context.ftp_data_registry.route(peer.ip(), stream).await {
                telemetry.emit(
                    "connection.paired",
                    json!({"service":"ftp_data","peer":peer.ip().to_string()}),
                );
            } else {
                telemetry.emit(
                    "connection.rejected",
                    json!({"service":"ftp_data","reason":"no_matching_passive_session"}),
                );
            }
            telemetry.emit("connection.closed", json!({"reason":"data_socket_routed"}));
            continue;
        }
        let permit = semaphore.clone().try_acquire_owned().ok();
        if permit.is_none() {
            let telemetry = emitter.service_session(
                peer,
                spec.public_port.unwrap_or(spec.bind.port()),
                &spec.service_type,
            );
            telemetry.emit("connection.opened", json!({"accepted":false}));
            telemetry.emit("connection.rejected", json!({"reason":"connection_limit"}));
            telemetry.emit("connection.closed", json!({"reason":"connection_limit"}));
            drop(stream);
            continue;
        }
        let service = spec.service_type.clone();
        let context = context.clone();
        let telemetry =
            emitter.service_session(peer, spec.public_port.unwrap_or(spec.bind.port()), &service);
        tokio::spawn(async move {
            telemetry.emit("connection.opened", json!({"accepted":true}));
            let _permit = permit;
            let result = timeout(
                context.idle_timeout,
                serve(&service, stream, peer, context, telemetry.clone()),
            )
            .await;
            match result {
                Ok(Ok(())) => telemetry.emit(
                    "connection.closed",
                    json!({"reason":"peer_closed_or_request_complete"}),
                ),
                Ok(Err(error)) => {
                    telemetry.emit("protocol.error", json!({"kind":error.kind().to_string()}));
                    telemetry.emit("connection.closed", json!({"reason":"protocol_error"}));
                }
                Err(_) => {
                    telemetry.emit("connection.timeout", json!({}));
                    telemetry.emit("connection.closed", json!({"reason":"idle_timeout"}));
                }
            }
        });
    }
}

async fn serve(
    service: &str,
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    match service {
        "redis" => redis::serve(stream, peer, context, telemetry).await,
        "docker_api" => http::serve_docker(stream, peer, context, telemetry).await,
        "http" => http::serve_web(stream, peer, context, telemetry).await,
        "ftp" => ftp::serve(stream, peer, context, telemetry).await,
        "mysql" => sql::serve_mysql(stream, peer, context, telemetry).await,
        "postgres" => sql::serve_postgres(stream, peer, context, telemetry).await,
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown Middle service",
        )),
    }
}

fn initial_virtual_state(baits: &[hf_core::BaitFile]) -> VirtualState {
    let state = VirtualState::default();
    if let Ok(mut redis) = state.redis.lock() {
        redis.insert("service:mode".into(), "production".into());
        redis.insert("app:environment".into(), "production".into());
        redis.insert("cache:health".into(), "ok".into());
    }
    if let Ok(mut hashes) = state.redis_hashes.lock() {
        hashes.insert(
            "user:1001".into(),
            HashMap::from([
                ("name".into(), "deploy".into()),
                ("role".into(), "admin".into()),
            ]),
        );
    }
    let mut virtual_files = HashMap::from([
        ("/README.txt".into(), b"Internal backup mirror\n".to_vec()),
        (
            "/pub/notes.txt".into(),
            b"staging host: app-db-01\n".to_vec(),
        ),
        ("/incoming/.keep".into(), Vec::new()),
    ]);
    let mut bait_files = HashMap::new();
    for bait in baits
        .iter()
        .filter(|bait| bait.effective_implementation() == hf_core::BaitImplementation::VirtualFile)
    {
        if let Some(path) = bait.path.as_ref() {
            virtual_files.insert(path.clone(), bait.content.as_bytes().to_vec());
            bait_files.insert(path.clone(), bait.clone());
        }
    }
    let sql_rows = HashMap::from([
        (
            "users".into(),
            vec![
                vec!["1".into(), "deploy".into(), "deploy@example.invalid".into()],
                vec!["2".into(), "admin".into(), "admin@example.invalid".into()],
            ],
        ),
        (
            "sessions".into(),
            vec![vec!["s-1024".into(), "1001".into(), "active".into()]],
        ),
    ]);
    VirtualState {
        virtual_files: Mutex::new(virtual_files),
        bait_files,
        sql_rows,
        ..state
    }
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}
