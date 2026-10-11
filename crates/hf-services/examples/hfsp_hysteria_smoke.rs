//! End-to-end local smoke test for HFSP carried through Hysteria's SOCKS5 UDP listener.
//!
//! Start the Hysteria server and client from `deploy/local-hysteria/` first, then run:
//! `cargo run -p hf-services --example hfsp_hysteria_smoke`

use std::{net::SocketAddr, time::Duration};

use hf_core::{HfspFrame, HfspMessageKind, PacketTransport};
use hf_services::HysteriaSocks5UdpTransport;
use tokio::{net::UdpSocket, time::timeout};

const CENTER_RECEIVER: &str = "127.0.0.1:44000";
const HYSTERIA_SOCKS5: &str = "127.0.0.1:1080";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let center: SocketAddr = CENTER_RECEIVER.parse()?;
    let receiver = UdpSocket::bind(center).await?;
    let transport = HysteriaSocks5UdpTransport::connect(HYSTERIA_SOCKS5.parse()?, center).await?;

    let outbound = HfspFrame::from_json(
        HfspMessageKind::Heartbeat,
        1,
        0,
        &serde_json::json!({"agent_id": "local-smoke"}),
    )?
    .encode()?;
    transport.send(&outbound).await?;

    let mut buffer = [0_u8; 2048];
    let (length, peer) =
        timeout(Duration::from_secs(10), receiver.recv_from(&mut buffer)).await??;
    let received = HfspFrame::decode(&buffer[..length])?;
    anyhow::ensure!(received.kind == HfspMessageKind::Heartbeat);
    anyhow::ensure!(received.sequence == 1);

    let acknowledgement = HfspFrame::from_json(
        HfspMessageKind::Ack,
        1,
        received.sequence,
        &serde_json::json!({"accepted": true}),
    )?
    .encode()?;
    receiver.send_to(&acknowledgement, peer).await?;

    let answer = timeout(Duration::from_secs(10), transport.receive()).await??;
    let answer = HfspFrame::decode(&answer)?;
    anyhow::ensure!(answer.kind == HfspMessageKind::Ack);
    anyhow::ensure!(answer.acknowledgement == 1);
    println!("OK: HFSP heartbeat crossed Hysteria and ACK returned through the same tunnel");
    Ok(())
}
