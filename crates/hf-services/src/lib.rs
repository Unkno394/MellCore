//! Infrastructure adapters. This crate may depend on sockets, processes and observability;
//! `hf-core` never does.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use hf_core::{PacketTransport, TransportError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
};
use tracing::{debug, warn};

#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    name: &'static str,
}

impl UdpTransport {
    pub async fn bind(
        name: &'static str,
        bind: SocketAddr,
        peer: SocketAddr,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|error| TransportError {
                transport: name,
                message: error.to_string(),
            })?;
        Ok(Self { socket, peer, name })
    }
}

#[async_trait]
impl PacketTransport for UdpTransport {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn send(&self, packet: &[u8]) -> Result<(), TransportError> {
        self.socket
            .send_to(packet, self.peer)
            .await
            .map_err(|error| TransportError {
                transport: self.name,
                message: error.to_string(),
            })?;
        Ok(())
    }
    async fn receive(&self) -> Result<Vec<u8>, TransportError> {
        let mut buffer = vec![0_u8; 1024 * 1024 + 28];
        let (length, _) =
            self.socket
                .recv_from(&mut buffer)
                .await
                .map_err(|error| TransportError {
                    transport: self.name,
                    message: error.to_string(),
                })?;
        buffer.truncate(length);
        Ok(buffer)
    }
}

/// Hysteria is operated outside the process and exposes its documented local SOCKS5 UDP relay.
/// HFSP sees only this adapter; changing it to TCP/HTTPS/LoRa does not alter frames or agent logic.
#[derive(Debug)]
pub struct HysteriaSocks5UdpTransport {
    relay: SocketAddr,
    destination: SocketAddr,
    socket: UdpSocket,
    /// SOCKS5 requires the TCP association to remain open while its UDP relay is used.
    #[allow(dead_code)]
    control: Mutex<TcpStream>,
}

impl HysteriaSocks5UdpTransport {
    /// `proxy` is the loopback SOCKS5 listener of the Hysteria client. `destination` is the
    /// HFSP UDP receiver as seen from the central Hysteria server (normally 127.0.0.1:44000).
    pub async fn connect(
        proxy: SocketAddr,
        destination: SocketAddr,
    ) -> Result<Self, TransportError> {
        let mut control = TcpStream::connect(proxy).await.map_err(socks_error)?;
        control
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(socks_error)?;
        let mut greeting = [0_u8; 2];
        control
            .read_exact(&mut greeting)
            .await
            .map_err(socks_error)?;
        if greeting != [0x05, 0x00] {
            return Err(TransportError {
                transport: "hysteria-socks5-udp",
                message: "SOCKS5 relay rejected no-auth negotiation".into(),
            });
        }
        // UDP ASSOCIATE; Hysteria binds the association to this TCP control connection.
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(socks_error)?;
        let relay = read_socks_reply(&mut control, proxy).await?;
        let bind: SocketAddr = match proxy {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("static address"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("static address"),
        };
        let socket = UdpSocket::bind(bind).await.map_err(socks_error)?;
        Ok(Self {
            relay,
            destination,
            socket,
            control: Mutex::new(control),
        })
    }
}

#[async_trait]
impl PacketTransport for HysteriaSocks5UdpTransport {
    fn name(&self) -> &'static str {
        "hysteria-socks5-udp"
    }
    async fn send(&self, packet: &[u8]) -> Result<(), TransportError> {
        let mut datagram = socks_udp_header(self.destination);
        datagram.extend_from_slice(packet);
        self.socket
            .send_to(&datagram, self.relay)
            .await
            .map_err(socks_error)?;
        Ok(())
    }
    async fn receive(&self) -> Result<Vec<u8>, TransportError> {
        let mut buffer = vec![0_u8; 1024 * 1024 + 300];
        let (length, source) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .map_err(socks_error)?;
        if source != self.relay {
            return Err(TransportError {
                transport: self.name(),
                message: "received UDP datagram from unexpected source".into(),
            });
        }
        buffer.truncate(length);
        parse_socks_udp_datagram(&buffer)
    }
}

fn socks_error(error: std::io::Error) -> TransportError {
    TransportError {
        transport: "hysteria-socks5-udp",
        message: error.to_string(),
    }
}

async fn read_socks_reply(
    stream: &mut TcpStream,
    proxy: SocketAddr,
) -> Result<SocketAddr, TransportError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.map_err(socks_error)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(TransportError {
            transport: "hysteria-socks5-udp",
            message: format!("SOCKS5 UDP associate rejected with code {}", header[1]),
        });
    }
    let ip = match header[3] {
        0x01 => {
            let mut raw = [0_u8; 4];
            stream.read_exact(&mut raw).await.map_err(socks_error)?;
            std::net::IpAddr::from(raw)
        }
        0x04 => {
            let mut raw = [0_u8; 16];
            stream.read_exact(&mut raw).await.map_err(socks_error)?;
            std::net::IpAddr::from(raw)
        }
        _ => {
            return Err(TransportError {
                transport: "hysteria-socks5-udp",
                message: "SOCKS5 relay returned domain address; use an IP listener".into(),
            });
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await.map_err(socks_error)?;
    Ok(SocketAddr::new(
        if ip.is_unspecified() { proxy.ip() } else { ip },
        u16::from_be_bytes(port),
    ))
}

fn socks_udp_header(destination: SocketAddr) -> Vec<u8> {
    let mut header = vec![0, 0, 0]; // RSV, RSV, FRAG=0; HFSP handles loss/retry itself.
    match destination {
        SocketAddr::V4(address) => {
            header.push(0x01);
            header.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            header.push(0x04);
            header.extend_from_slice(&address.ip().octets());
        }
    }
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

fn parse_socks_udp_datagram(datagram: &[u8]) -> Result<Vec<u8>, TransportError> {
    if datagram.len() < 4 || datagram[0..2] != [0, 0] || datagram[2] != 0 {
        return Err(TransportError {
            transport: "hysteria-socks5-udp",
            message: "invalid or fragmented SOCKS5 UDP datagram".into(),
        });
    }
    let address_len = match datagram[3] {
        0x01 => 4,
        0x04 => 16,
        _ => {
            return Err(TransportError {
                transport: "hysteria-socks5-udp",
                message: "unsupported SOCKS5 UDP address type".into(),
            });
        }
    };
    let payload_offset = 4 + address_len + 2;
    if datagram.len() < payload_offset {
        return Err(TransportError {
            transport: "hysteria-socks5-udp",
            message: "truncated SOCKS5 UDP datagram".into(),
        });
    }
    Ok(datagram[payload_offset..].to_vec())
}

/// Sends through the most recently healthy adapter. A failed send tries every configured
/// transport once and promotes the successful one; callers retain their packet for durable retry.
#[derive(Debug)]
pub struct FailoverSender {
    transports: Vec<Arc<dyn PacketTransport>>,
    active: AtomicUsize,
}

impl FailoverSender {
    pub fn new(transports: Vec<Arc<dyn PacketTransport>>) -> Result<Self, &'static str> {
        if transports.is_empty() {
            return Err("at least one transport is required");
        }
        Ok(Self {
            transports,
            active: AtomicUsize::new(0),
        })
    }

    pub async fn send(&self, packet: &[u8]) -> Result<&'static str, TransportError> {
        let first = self.active.load(Ordering::Relaxed) % self.transports.len();
        let mut errors = Vec::new();
        for offset in 0..self.transports.len() {
            let index = (first + offset) % self.transports.len();
            let transport = &self.transports[index];
            match transport.send(packet).await {
                Ok(()) => {
                    self.active.store(index, Ordering::Relaxed);
                    debug!(transport = transport.name(), "HFSP packet sent");
                    return Ok(transport.name());
                }
                Err(error) => {
                    warn!(transport = transport.name(), error = %error, "transport send failed; trying fallback");
                    errors.push(error.message);
                }
            }
        }
        Err(TransportError {
            transport: "failover",
            message: errors.join("; "),
        })
    }
}
