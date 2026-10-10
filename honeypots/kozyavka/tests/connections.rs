use honeyforge_low::{
    config::Config,
    network,
    telemetry::{ConnectionEvent, EventSink},
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

struct ChannelSink(mpsc::UnboundedSender<ConnectionEvent>);
impl EventSink for ChannelSink {
    fn emit(&self, event: &ConnectionEvent) -> io::Result<()> {
        self.0.send(event.clone()).map_err(io::Error::other)
    }
}

struct TestServer {
    address: SocketAddr,
    events: mpsc::UnboundedReceiver<ConnectionEvent>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl TestServer {
    async fn start(config: Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, events) = mpsc::unbounded_channel();
        let (shutdown, stop) = oneshot::channel();
        let task = tokio::spawn(network::serve(
            listener,
            config,
            Arc::new(ChannelSink(tx)),
            async {
                let _ = stop.await;
            },
        ));
        Self {
            address,
            events,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        self.shutdown.send(()).unwrap();
        timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(self.address).await.is_err());
    }
}

async fn read_banner(address: SocketAddr) -> (SocketAddr, Vec<u8>) {
    timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let client = stream.local_addr().unwrap();
        let mut bytes = Vec::new();
        // Reading to EOF also proves that the trap closes without waiting for commands.
        stream.read_to_end(&mut bytes).await.unwrap();
        (client, bytes)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn connection_receives_banner_and_emits_matching_event() {
    let config = Config::default();
    let id = config.trap_id;
    let mut server = TestServer::start(config).await;
    let (client, bytes) = read_banner(server.address).await;
    assert_eq!(bytes, b"SSH-2.0-OpenSSH_9.6\r\n");
    let event = timeout(Duration::from_secs(5), server.events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.client_ip, client.ip());
    assert_eq!(event.client_port, client.port());
    assert_eq!(event.trap_port, server.address.port());
    assert_eq!(event.trap_id, id);
    assert_eq!(event.event_id.get_version_num(), 4);
    assert!(server.events.try_recv().is_err());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_clients_receive_custom_banner_and_one_event_each() {
    let mut server = TestServer::start(Config {
        banner: "SSH-2.0-HoneyForge_Test".into(),
        ..Config::default()
    })
    .await;
    let mut clients = JoinSet::new();
    for _ in 0..32 {
        clients.spawn(read_banner(server.address));
    }
    let mut ports = std::collections::HashSet::new();
    let mut event_ids = std::collections::HashSet::new();
    while let Some(result) = clients.join_next().await {
        let (client, bytes) = result.unwrap();
        assert_eq!(bytes, b"SSH-2.0-HoneyForge_Test\r\n");
        ports.insert(client.port());
    }
    for _ in 0..32 {
        let event = timeout(Duration::from_secs(5), server.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ports.remove(&event.client_port));
        assert!(event_ids.insert(event.event_id), "duplicate event_id");
        assert_eq!(event.trap_port, server.address.port());
    }
    assert!(ports.is_empty());
    assert_eq!(event_ids.len(), 32);
    assert!(server.events.try_recv().is_err());
    server.stop().await;
}
