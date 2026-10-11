pub mod events;

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
    time::{Instant, interval_at},
};
use uuid::Uuid;

use crate::config::TelemetryConfig;
use events::{IncomingEvent, SCHEMA_VERSION, TelemetryBatch};

#[derive(Clone)]
pub struct EventEmitter {
    sender: mpsc::Sender<IncomingEvent>,
    dropped: Arc<AtomicU64>,
    trap_id: Uuid,
    destination_port: u16,
    max_event_bytes: usize,
}

pub struct SessionTelemetry {
    emitter: EventEmitter,
    pub session_id: Uuid,
    sequence: AtomicU64,
    peer: SocketAddr,
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("missing telemetry token environment variable")]
    MissingToken,
    #[error("telemetry token must contain at least 32 bytes")]
    InvalidToken,
    #[error("cannot initialize telemetry sink: {0}")]
    Io(#[from] std::io::Error),
}

struct Worker {
    receiver: mpsc::Receiver<IncomingEvent>,
    config: TelemetryConfig,
    agent_id: Uuid,
    server_id: Uuid,
    token: Option<String>,
    client: reqwest::Client,
}

struct PendingDelivery {
    batch: TelemetryBatch,
    jsonl_written: bool,
}

impl EventEmitter {
    pub fn start(
        config: TelemetryConfig,
        trap_id: Uuid,
        server_id: Uuid,
        agent_id: Uuid,
        destination_port: u16,
    ) -> Result<Self, TelemetryError> {
        let token = config
            .token_env
            .as_deref()
            .map(std::env::var)
            .transpose()
            .map_err(|_| TelemetryError::MissingToken)?;
        if config.endpoint.is_some() && token.as_ref().is_none_or(|value| value.len() < 32) {
            return Err(TelemetryError::InvalidToken);
        }
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let emitter = Self {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            trap_id,
            destination_port,
            max_event_bytes: config.max_event_bytes,
        };
        tokio::spawn(
            Worker {
                receiver,
                config,
                agent_id,
                server_id,
                token,
                client: reqwest::Client::new(),
            }
            .run(),
        );
        Ok(emitter)
    }

    pub fn session(&self, peer: SocketAddr) -> SessionTelemetry {
        SessionTelemetry {
            emitter: self.clone(),
            session_id: Uuid::new_v4(),
            sequence: AtomicU64::new(0),
            peer,
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl SessionTelemetry {
    pub fn emit(&self, event_type: &str, payload: Value) {
        let sequence_no = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let event = IncomingEvent {
            event_id: Uuid::new_v4(),
            trap_id: self.emitter.trap_id,
            session_id: Some(self.session_id.to_string()),
            sequence_no: Some(sequence_no),
            event_type: event_type.into(),
            occurred_at: chrono::Utc::now(),
            source_ip: Some(self.peer.ip()),
            source_port: Some(self.peer.port()),
            destination_port: Some(self.emitter.destination_port),
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload,
            metadata: json!({"source":"pritvoryashka","component_version":env!("CARGO_PKG_VERSION")}),
        };
        let valid_size = serde_json::to_vec(&event)
            .is_ok_and(|bytes| bytes.len() <= self.emitter.max_event_bytes);
        if !valid_size || self.emitter.sender.try_send(event).is_err() {
            self.emitter.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Worker {
    async fn run(mut self) {
        let period = Duration::from_millis(self.config.flush_interval_ms);
        let mut ticker = interval_at(Instant::now() + period, period);
        let mut pending = VecDeque::new();
        let mut retry = None;
        loop {
            tokio::select! {
                event = self.receiver.recv() => match event {
                    Some(event) => {
                        pending.push_back(event);
                        if pending.len() >= self.config.batch_size {
                            self.flush(&mut pending, &mut retry).await;
                        }
                    }
                    None => {
                        while !pending.is_empty() {
                            self.flush(&mut pending, &mut retry).await;
                        }
                        return;
                    }
                },
                _ = ticker.tick() => {
                    if !pending.is_empty() {
                        self.flush(&mut pending, &mut retry).await;
                    }
                }
            }
        }
    }

    async fn flush(
        &self,
        pending: &mut VecDeque<IncomingEvent>,
        retry: &mut Option<PendingDelivery>,
    ) {
        ensure_pending_delivery(
            pending,
            retry,
            self.config.batch_size,
            self.agent_id,
            self.server_id,
        );
        let delivery = retry.as_mut().expect("pending delivery initialized");
        match self.deliver(delivery).await {
            Ok(()) => {
                pending.drain(..delivery.batch.events.len());
                *retry = None;
            }
            Err(error) => {
                tracing::warn!(%error, pending = pending.len(), "telemetry delivery delayed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    async fn deliver(&self, delivery: &mut PendingDelivery) -> Result<(), String> {
        if let Some(path) = &self.config.jsonl_path
            && !delivery.jsonl_written
        {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .map_err(|error| error.to_string())?;
            let mut line =
                serde_json::to_vec(&delivery.batch).map_err(|error| error.to_string())?;
            line.push(b'\n');
            file.write_all(&line)
                .await
                .map_err(|error| error.to_string())?;
            delivery.jsonl_written = true;
        }
        if let Some(endpoint) = &self.config.endpoint {
            let mut request = self.client.post(endpoint).json(&delivery.batch);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.map_err(|error| error.to_string())?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()));
            }
        }
        Ok(())
    }
}

fn ensure_pending_delivery(
    pending: &VecDeque<IncomingEvent>,
    retry: &mut Option<PendingDelivery>,
    batch_size: usize,
    agent_id: Uuid,
    server_id: Uuid,
) {
    if retry.is_some() {
        return;
    }
    let count = pending.len().min(batch_size);
    let events = pending.iter().take(count).cloned().collect();
    *retry = Some(PendingDelivery {
        batch: TelemetryBatch {
            schema_version: SCHEMA_VERSION,
            batch_id: Uuid::new_v4(),
            agent_id,
            server_id,
            events,
        },
        jsonl_written: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter(capacity: usize) -> (EventEmitter, mpsc::Receiver<IncomingEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            EventEmitter {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
                trap_id: Uuid::new_v4(),
                destination_port: 2222,
                max_event_bytes: 65_536,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn events_have_stable_session_identity_and_monotonic_sequence() {
        let (emitter, mut receiver) = emitter(4);
        let session = emitter.session("192.0.2.10:4567".parse().unwrap());
        session.emit("connection.opened", json!({}));
        session.emit("auth.attempted", json!({"username":"root"}));
        let first = receiver.recv().await.unwrap();
        let second = receiver.recv().await.unwrap();
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.sequence_no, Some(1));
        assert_eq!(second.sequence_no, Some(2));
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn bounded_queue_drops_instead_of_growing_without_limit() {
        let (emitter, _receiver) = emitter(1);
        let session = emitter.session("192.0.2.10:4567".parse().unwrap());
        session.emit("connection.opened", json!({}));
        session.emit("auth.attempted", json!({}));
        assert_eq!(emitter.dropped(), 1);
    }

    #[test]
    fn oversized_events_are_rejected_before_queueing() {
        let (mut emitter, _receiver) = emitter(1);
        emitter.max_event_bytes = 100;
        let session = emitter.session("192.0.2.10:4567".parse().unwrap());
        session.emit("command.executed", json!({"input":"x".repeat(1000)}));
        assert_eq!(emitter.dropped(), 1);
    }

    #[test]
    fn backend_outage_keeps_the_same_batch_for_idempotent_retry() {
        let (emitter, mut receiver) = emitter(2);
        let session = emitter.session("192.0.2.10:4567".parse().unwrap());
        session.emit("connection.opened", json!({}));
        let mut pending = VecDeque::from([receiver.try_recv().unwrap()]);
        let mut retry = None;
        let agent = Uuid::new_v4();
        let server = Uuid::new_v4();
        ensure_pending_delivery(&pending, &mut retry, 50, agent, server);
        let first_batch = retry.as_ref().unwrap().batch.batch_id;
        // A failed delivery leaves both events and delivery state untouched.
        ensure_pending_delivery(&pending, &mut retry, 50, agent, server);
        assert_eq!(retry.as_ref().unwrap().batch.batch_id, first_batch);
        assert_eq!(retry.as_ref().unwrap().batch.events.len(), 1);
        assert_eq!(pending.len(), 1);
        // Only an acknowledgement removes the event and permits a new batch ID.
        pending.drain(..1);
        retry = None;
        assert!(pending.is_empty());
        assert!(retry.is_none());
    }
}
