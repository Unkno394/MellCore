use std::{io, net::SocketAddr};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use super::ServiceContext;
use crate::telemetry::SessionTelemetry;

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

pub async fn serve_web(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let mut request = match read_request(stream, context.max_input_bytes).await? {
        Some(request) => request,
        None => return Ok(()),
    };
    let decoded_target = decode_url(&request.target);
    let path = decoded_target.split('?').next().unwrap_or("/").to_owned();
    let mut response = (
        200,
        "text/html; charset=utf-8",
        b"<html><title>Welcome</title><h1>Internal application</h1></html>".to_vec(),
    );
    let path_traversal =
        context.profiles.contains("web_path_traversal") && has_parent_segment(&decoded_target);
    if path_traversal {
        telemetry.emit(
            "vulnerability.exploit_attempt",
            json!({"profile_id":"web_path_traversal","path":truncate(&path, 512)}),
        );
        let matching_bait = context
            .state
            .bait_files
            .iter()
            .find(|(bait_path, _)| decoded_target.contains(bait_path.trim_start_matches('/')));
        if let Some((bait_path, bait)) = matching_bait {
            response = (
                200,
                "text/plain; charset=utf-8",
                bait.content.as_bytes().to_vec(),
            );
            telemetry.emit(
                "bait.opened",
                json!({
                    "bait_id":bait.id,
                    "bait_name":bait.name,
                    "bait_kind":bait.kind.as_str(),
                    "path":bait_path,
                    "operation":"read",
                }),
            );
            telemetry.emit(
                "virtual_action",
                json!({"service":"http","action":"read_bait","path":bait_path}),
            );
        } else {
            let content = if decoded_target.to_ascii_lowercase().contains("shadow") {
                b"root:$6$virtual$not-a-real-hash:19000:0:99999:7:::\napp:$6$virtual$not-a-real-hash:19000:0:99999:7:::\n".as_slice()
            } else {
                b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\napp:x:1001:1001:Application:/home/app:/bin/bash\n".as_slice()
            };
            response = (200, "text/plain; charset=utf-8", content.to_vec());
            telemetry.emit(
                "virtual_action",
                json!({"service":"http","action":"read_virtual_file","path":"/etc/passwd"}),
            );
        }
    } else if context.profiles.contains("web_command_injection")
        && (request.target.contains("cmd=")
            || request.target.contains("host=")
            || !request.body.is_empty())
        && {
            let probe = format!(
                "{} {}",
                request.target,
                String::from_utf8_lossy(&request.body)
            );
            has_command_operator(&probe) || has_command_parameter(&probe)
        }
    {
        telemetry.emit(
            "vulnerability.exploit_attempt",
            json!({"profile_id":"web_command_injection","path":truncate(&path, 256)}),
        );
        let result = fake_command_output(&request.target, &request.body);
        response = (200, "text/plain; charset=utf-8", result.into_bytes());
        telemetry.emit(
            "virtual_action",
            json!({"service":"http","action":"simulate_command","executed":false}),
        );
    } else if context.profiles.contains("http_admin_panel_exposure") {
        if request.method.eq_ignore_ascii_case("POST") && path_matches(&path, "/login") {
            let form = parse_form(&String::from_utf8_lossy(&request.body));
            let username = form.get("username").map(String::as_str).unwrap_or("");
            let password = form.get("password").map(String::as_str).unwrap_or("");
            let accepted = matches!(
                (username, password),
                ("admin", "admin")
                    | ("admin", "password")
                    | ("admin", "admin123")
                    | ("root", "toor")
            );
            telemetry.emit(
                "auth.attempted",
                json!({"username":truncate(username, 64),"accepted":accepted}),
            );
            telemetry.emit("vulnerability.exploit_attempt", json!({"profile_id":"http_admin_panel_exposure","username":truncate(username, 64),"accepted":accepted}));
            telemetry.emit(
                "virtual_action",
                json!({"service":"http","action":"admin_login","accepted":accepted}),
            );
            if accepted {
                telemetry.emit(
                    "auth.succeeded",
                    json!({"username":truncate(username, 64),"service":"http"}),
                );
            } else {
                telemetry.emit(
                    "auth.failed",
                    json!({"username":truncate(username, 64),"service":"http"}),
                );
            }
            response = if accepted {
                (
                    200,
                    "text/html; charset=utf-8",
                    b"<html><h1>Admin dashboard</h1><p>Welcome</p></html>".to_vec(),
                )
            } else {
                (
                    401,
                    "text/html; charset=utf-8",
                    b"<html><h1>Invalid credentials</h1></html>".to_vec(),
                )
            };
        } else if path_matches(&path, "/admin") || path_matches(&path, "/") {
            telemetry.emit(
                "vulnerability.exploit_attempt",
                json!({"profile_id":"http_admin_panel_exposure","method":request.method.as_str(),"path":truncate(&path, 256)}),
            );
            response = (200, "text/html; charset=utf-8", b"<html><title>Administration</title><form method=post action=/login><input name=username><input name=password type=password><button>Sign in</button></form></html>".to_vec());
        }
    }
    telemetry.emit("http.request", json!({"method":request.method.as_str(),"path":truncate(&path, 512),"peer":peer.ip().to_string()}));
    write_raw_response(
        &mut request.writer,
        response.0,
        response.1,
        &response.2,
        request.method == "HEAD",
    )
    .await
}

pub async fn serve_docker(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let mut request = match read_request(stream, context.max_input_bytes).await? {
        Some(request) => request,
        None => return Ok(()),
    };
    let raw_path = request.target.split('?').next().unwrap_or("/");
    let path = raw_path
        .strip_prefix("/v1.")
        .and_then(|rest| rest.split_once('/').map(|(_, path)| path.to_owned()))
        .unwrap_or_else(|| raw_path.to_owned());
    let method = request.method.as_str();
    let operating_system = match context.distribution {
        crate::config::Distribution::Ubuntu => "Ubuntu 22.04.4 LTS",
        crate::config::Distribution::Debian => "Debian GNU/Linux 13 (trixie)",
        crate::config::Distribution::Arch => "Arch Linux",
        crate::config::Distribution::Windows => "Windows Server",
    };
    let (status, body) = match (method, path.as_str()) {
        ("GET", "/_ping") => (200, "OK".to_owned()),
        ("GET", "/version") => (200, json!({"Version":"27.3.1","ApiVersion":"1.47","MinAPIVersion":"1.24","GitCommit":"mellcore","GoVersion":"go1.23.3","Os":"linux","Arch":"amd64"}).to_string()),
        ("GET", "/info") => (200, json!({"ID":"MELLCORE-DOCKER-01","Containers":4,"ContainersRunning":3,"ContainersPaused":0,"ContainersStopped":1,"Images":2,"Driver":"overlay2","OperatingSystem":operating_system,"NCPU":4,"MemTotal":8589934592_u64}).to_string()),
        ("GET", "/containers/json") => (200, json!([
            {"Id":"9d42ab41cd73","Names":["/billing-api"],"Image":"registry.internal/billing-api:2.8.4","ImageID":"sha256:be84c73a1590","Command":"/app/billing-api --config /app/config.toml","State":"running","Status":"Up 17 days","Ports":[{"IP":"0.0.0.0","PrivatePort":8080,"PublicPort":8080,"Type":"tcp"}]},
            {"Id":"5a7c091efc20","Names":["/billing-worker"],"Image":"registry.internal/billing-api:2.8.4","ImageID":"sha256:be84c73a1590","Command":"/app/billing-worker --queue invoices","State":"running","Status":"Up 17 days","Ports":[]},
            {"Id":"a82f4c0d19e7","Names":["/redis"],"Image":"redis:7.2-alpine","ImageID":"sha256:6d3a92bc1e0f","Command":"redis-server *:6379","State":"running","Status":"Up 17 days","Ports":[{"PrivatePort":6379,"Type":"tcp"}]}
        ]).to_string()),
        ("GET", "/images/json") => (200, json!([{"Id":"sha256:be84c73a1590","RepoTags":["registry.internal/billing-api:2.8.4"],"Created":1791740400,"Size":142000000},{"Id":"sha256:6d3a92bc1e0f","RepoTags":["redis:7.2-alpine"],"Created":1791740400,"Size":117000000}]).to_string()),
        ("GET", path) if path.starts_with("/containers/") && path.ends_with("/json") => (200, json!({"Id":"9d42ab41cd73","Name":"/billing-api","Path":"/app/billing-api","Args":["--config","/app/config.toml"],"State":{"Status":"running","Running":true,"ExitCode":0},"Config":{"Image":"registry.internal/billing-api:2.8.4","Env":["APP_ENV=production"]},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.18.0.3"}}}}).to_string()),
        ("GET", path) if path.starts_with("/containers/") && path.ends_with("/logs") => (200, "2026-10-12T07:42:03Z INFO billing_api: health check passed\n".to_owned()),
        ("POST", "/containers/create") => (201, json!({"Id":"f05ca0d9c011","Warnings":[]}).to_string()),
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/exec") => (201, json!({"Id":"ea91bd71e345"}).to_string()),
        ("POST", path) if path.starts_with("/exec/") && path.ends_with("/start") => (200, "simulated process output\n".to_owned()),
        ("POST", path) if path.starts_with("/containers/") && ["/start", "/stop", "/restart", "/kill"].iter().any(|suffix| path.ends_with(suffix)) => (200, String::new()),
        _ => (404, json!({"message":"page not found"}).to_string()),
    };
    telemetry.emit(
        "vulnerability.exploit_attempt",
        json!({"profile_id":"docker_api_exposed","method":method,"path":truncate(&path, 256)}),
    );
    if method == "POST" {
        telemetry.emit("virtual_action", json!({"service":"docker_api","action":path.as_str(),"simulated":true,"executed":false}));
    }
    telemetry.emit("http.request", json!({"service":"docker_api","method":method,"path":truncate(&path, 512),"peer":peer.ip().to_string()}));
    let content_type = if path == "/_ping" {
        "text/plain"
    } else {
        "application/json"
    };
    write_raw_response(
        &mut request.writer,
        status,
        content_type,
        body.as_bytes(),
        request.method == "HEAD",
    )
    .await
}

async fn read_request(stream: TcpStream, limit: usize) -> io::Result<Option<Request>> {
    let (read, write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = Vec::new();
    if read_bounded_line(&mut reader, &mut line, limit).await? == 0 {
        return Ok(None);
    }
    let request_line = String::from_utf8_lossy(&line);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_owned();
    let mut content_length = 0usize;
    let mut consumed = line.len();
    loop {
        line.clear();
        let read =
            read_bounded_line(&mut reader, &mut line, limit.saturating_sub(consumed)).await?;
        if read == 0 {
            break;
        }
        consumed = consumed.saturating_add(read);
        if consumed > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed limit",
            ));
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        let header = String::from_utf8_lossy(&line);
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP content length")
            })?;
        }
    }
    if content_length > limit.saturating_sub(consumed) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP body exceeds limit",
        ));
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).await?;
    let stream = reader.into_inner();
    drop(stream);
    // The write half is returned by split; attach it to the request for the one-shot response.
    Ok(Some(Request {
        method,
        target,
        body,
        writer: write,
    }))
}

async fn read_bounded_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    line.clear();
    loop {
        if line.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP line exceeds input limit",
            ));
        }
        let byte = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && line.is_empty() => {
                return Ok(0);
            }
            Err(error) => return Err(error),
        };
        line.push(byte);
        if byte == b'\n' {
            return Ok(line.len());
        }
    }
}

async fn write_raw_response(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    status: u16,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nServer: nginx/1.24.0\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    stream.shutdown().await
}

fn path_matches(path: &str, candidate: &str) -> bool {
    path.split('?')
        .next()
        .unwrap_or(path)
        .eq_ignore_ascii_case(candidate)
}

fn decode_url(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(if bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn has_parent_segment(value: &str) -> bool {
    value
        .replace('\\', "/")
        .split('/')
        .any(|segment| segment == "..")
}

fn has_command_operator(value: &str) -> bool {
    let decoded = decode_url(value).to_ascii_lowercase();
    decoded.contains(';')
        || decoded.contains("&&")
        || decoded.contains("||")
        || decoded.contains('|')
        || decoded.contains("$(")
        || decoded.contains('`')
}

fn has_command_parameter(value: &str) -> bool {
    decode_url(value)
        .split(['?', '&', ' '])
        .filter_map(|part| part.split_once('='))
        .any(|(name, command)| {
            matches!(name.rsplit('/').next().unwrap_or(name), "cmd" | "command")
                && matches!(
                    command.split_whitespace().next().unwrap_or_default(),
                    "echo" | "id" | "whoami" | "uname" | "ping"
                )
        })
}

fn fake_command_output(target: &str, body: &[u8]) -> String {
    let input = format!("{} {}", decode_url(target), String::from_utf8_lossy(body));
    let lower = input.to_ascii_lowercase();
    let command = decode_url(target)
        .split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .filter_map(|part| part.split_once('='))
                .find(|(name, _)| matches!(*name, "cmd" | "command"))
                .map(|(_, command)| command.to_owned())
        })
        .or_else(|| {
            let form = parse_form(&String::from_utf8_lossy(body));
            form.get("cmd").or_else(|| form.get("command")).cloned()
        });
    if let Some(command) = command
        && let Some(value) = command.trim().strip_prefix("echo ")
    {
        format!("{}\n", value.trim())
    } else if lower.contains("whoami") {
        "www-data\n".into()
    } else if lower.contains("uname") {
        "Linux app-01 5.15.0-91-generic x86_64 GNU/Linux\n".into()
    } else if lower.contains("id") {
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n".into()
    } else {
        "PING app.internal (10.0.4.12): 56 data bytes\n64 bytes from 10.0.4.12: icmp_seq=1 ttl=63 time=0.31 ms\n".into()
    }
}

fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((decode_url(key), decode_url(value)))
        })
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Distribution, TelemetryConfig},
        protocols::{FtpDataRegistry, VirtualState},
        telemetry::EventEmitter,
    };
    use std::{collections::HashSet, sync::Arc, time::Duration};
    use tokio::{io::AsyncReadExt, net::TcpListener};
    use uuid::Uuid;

    async fn request_over_listener(request: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut telemetry_config = TelemetryConfig::default();
        telemetry_config.jsonl_path = None;
        let emitter = EventEmitter::start(
            telemetry_config,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            8080,
        )
        .unwrap();
        let context = ServiceContext {
            profiles: Arc::new(HashSet::from(["http_admin_panel_exposure".to_owned()])),
            state: Arc::new(VirtualState::default()),
            distribution: Distribution::Ubuntu,
            max_input_bytes: 8192,
            idle_timeout: Duration::from_secs(5),
            ftp_data_port: None,
            ftp_data_registry: Arc::new(FtpDataRegistry::default()),
        };
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let telemetry = emitter.service_session(peer, 8080, "http");
            serve_web(stream, peer, context, telemetry).await.unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn admin_panel_and_login_are_reachable_through_http_listener() {
        let page = request_over_listener(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(page.starts_with("HTTP/1.1 200 OK"));
        assert!(page.contains("<title>Administration</title>"));
        assert!(page.contains("action=/login"));

        let body = b"username=admin&password=admin";
        let post = format!(
            "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let dashboard = request_over_listener(post.as_bytes()).await;
        assert!(dashboard.starts_with("HTTP/1.1 200 OK"));
        assert!(dashboard.contains("<h1>Admin dashboard</h1>"));
    }
}
