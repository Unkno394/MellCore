use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::telemetry::EventEmitter;

pub async fn serve_health(address: SocketAddr, emitter: EventEmitter) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "health listener started");
    loop {
        let (stream, _) = listener.accept().await?;
        let emitter = emitter.clone();
        tokio::spawn(async move {
            if let Err(error) = respond(stream, emitter).await {
                tracing::debug!(%error, "health client disconnected");
            }
        });
    }
}

async fn respond(mut stream: TcpStream, emitter: EventEmitter) -> std::io::Result<()> {
    let mut request = [0_u8; 1024];
    let read = stream.read(&mut request).await?;
    let line = String::from_utf8_lossy(&request[..read]);
    let path = line.split_whitespace().nth(1).unwrap_or("");
    let (status, body) = match path {
        "/health/live" => ("200 OK", "{\"status\":\"alive\"}".to_owned()),
        "/health/ready" => (
            "200 OK",
            format!(
                "{{\"status\":\"ready\",\"dropped_events\":{}}}",
                emitter.dropped()
            ),
        ),
        _ => ("404 Not Found", "{\"status\":\"not_found\"}".to_owned()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
