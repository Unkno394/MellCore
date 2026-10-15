use std::{io, net::SocketAddr};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use super::ServiceContext;
use crate::telemetry::SessionTelemetry;

const MAX_ARGS: usize = 128;
const MAX_VIRTUAL_KEYS: usize = 1024;
const MAX_VIRTUAL_VALUE_BYTES: usize = 8192;

pub async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    loop {
        let Some(args) = read_command(&mut read, context.max_input_bytes).await? else {
            return Ok(());
        };
        if args.is_empty() {
            continue;
        }
        let command = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        let key = args.get(1).map(|v| String::from_utf8_lossy(v).into_owned());
        telemetry.emit(
            "vulnerability.exploit_attempt",
            json!({
                "profile_id":"redis_unauthenticated_access",
                "command":command,
                "key":key,
                "source":peer.ip().to_string(),
            }),
        );
        let response = execute(&command, &args, &context, &telemetry);
        write.write_all(&response).await?;
        write.flush().await?;
        telemetry.emit(
            "virtual_action",
            json!({
                "service":"redis",
                "action":command,
                "key":key,
            }),
        );
    }
}

fn execute(
    command: &str,
    args: &[Vec<u8>],
    context: &ServiceContext,
    telemetry: &SessionTelemetry,
) -> Vec<u8> {
    let arg = |index: usize| {
        args.get(index)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let simple = |value: &str| format!("+{value}\r\n").into_bytes();
    let error = |value: &str| format!("-{value}\r\n").into_bytes();
    match command {
        "PING" => args.get(1).map_or_else(|| simple("PONG"), |value| bulk(value)),
        "ECHO" if args.len() == 2 => bulk(&args[1]),
        "AUTH" => error("ERR AUTH called without any password configured"),
        "SELECT" if args.len() == 2 => simple("OK"),
        "QUIT" => simple("OK"),
        "COMMAND" => array(&[]),
        "INFO" => bulk(b"# Server\r\nredis_version:7.0.15\r\nmode:standalone\r\n# Keyspace\r\ndb0:keys=3,expires=0,avg_ttl=0\r\n"),
        "DBSIZE" => {
            let count = context.state.redis.lock().map(|map| map.len()).unwrap_or(0);
            integer(count as i64)
        }
        "GET" if args.len() == 2 => {
            let key = arg(1).unwrap_or_default();
            let value = context.state.redis.lock().ok().and_then(|map| map.get(&key).cloned());
            value.map_or_else(null_bulk, |value| bulk(value.as_bytes()))
        }
        "MGET" if args.len() >= 2 => {
            let values = context.state.redis.lock().ok();
            let responses: Vec<_> = args.iter().skip(1).map(|key| {
                let key = String::from_utf8_lossy(key);
                values.as_ref().and_then(|map| map.get(key.as_ref())).map_or_else(null_bulk, |value| bulk(value.as_bytes()))
            }).collect();
            array_raw(&responses)
        }
        "SET" if args.len() >= 3 => {
            let key = arg(1).unwrap_or_default();
            let value = String::from_utf8_lossy(&args[2]).into_owned();
            let stored = if key.len() <= 512 && value.len() <= MAX_VIRTUAL_VALUE_BYTES {
                context.state.redis.lock().is_ok_and(|mut map| {
                    if map.contains_key(&key) || map.len() < MAX_VIRTUAL_KEYS {
                        map.insert(key.clone(), value);
                        true
                    } else {
                        false
                    }
                })
            } else {
                false
            };
            telemetry.emit("virtual_action", json!({"service":"redis","operation":"set","key":key,"stored":stored}));
            simple("OK")
        }
        "MSET" if args.len() >= 3 && args.len() % 2 == 1 => {
            if let Ok(mut map) = context.state.redis.lock() {
                for pair in args[1..].chunks_exact(2) {
                    let key = String::from_utf8_lossy(&pair[0]).into_owned();
                    let value = String::from_utf8_lossy(&pair[1]).into_owned();
                    if key.len() <= 512
                        && value.len() <= MAX_VIRTUAL_VALUE_BYTES
                        && (map.contains_key(&key) || map.len() < MAX_VIRTUAL_KEYS)
                    {
                        map.insert(key, value);
                    }
                }
            }
            simple("OK")
        }
        "DEL" if args.len() >= 2 => {
            let mut removed = 0;
            if let Ok(mut map) = context.state.redis.lock() {
                for key in args.iter().skip(1) {
                    removed += map.remove(String::from_utf8_lossy(key).as_ref()).is_some() as i64;
                }
            }
            integer(removed)
        }
        "EXISTS" if args.len() >= 2 => {
            let count = context.state.redis.lock().map(|map| args.iter().skip(1).filter(|key| map.contains_key(String::from_utf8_lossy(key).as_ref())).count()).unwrap_or(0);
            integer(count as i64)
        }
        "KEYS" if args.len() == 2 => {
            let pattern = arg(1).unwrap_or_default();
            let keys = context.state.redis.lock().map(|map| map.keys().filter(|key| matches_pattern(key, &pattern)).map(|key| bulk(key.as_bytes())).collect::<Vec<_>>()).unwrap_or_default();
            array_raw(&keys)
        }
        "INCR" | "DECR" if args.len() == 2 => {
            let key = arg(1).unwrap_or_default();
            if key.len() > 512 {
                return error("ERR virtual key exceeds the supported limit");
            }
            let next = if let Ok(mut map) = context.state.redis.lock() {
                if !map.contains_key(&key) && map.len() >= MAX_VIRTUAL_KEYS {
                    return error("ERR virtual store capacity reached");
                }
                let current = map.get(&key).and_then(|value| value.parse::<i64>().ok()).unwrap_or(0);
                let next = if command == "INCR" { current.saturating_add(1) } else { current.saturating_sub(1) };
                map.insert(key, next.to_string());
                next
            } else { 0 };
            integer(next)
        }
        "HSET" if args.len() >= 4 && args.len() % 2 == 0 => {
            let hash = arg(1).unwrap_or_default();
            if hash.len() > 512 {
                return error("ERR virtual hash key exceeds the supported limit");
            }
            let mut added = 0;
            if let Ok(mut hashes) = context.state.redis_hashes.lock() {
                if !hashes.contains_key(&hash) && hashes.len() >= MAX_VIRTUAL_KEYS {
                    return error("ERR virtual hash store capacity reached");
                }
                let total_fields = hashes.values().map(|values| values.len()).sum::<usize>();
                let values = hashes.entry(hash).or_default();
                for pair in args[2..].chunks_exact(2) {
                    let field = String::from_utf8_lossy(&pair[0]).into_owned();
                    let value = String::from_utf8_lossy(&pair[1]).into_owned();
                    if field.len() > 512
                        || value.len() > MAX_VIRTUAL_VALUE_BYTES
                        || (!values.contains_key(&field)
                            && total_fields.saturating_add(added as usize) >= MAX_VIRTUAL_KEYS)
                    {
                        continue;
                    }
                    added += (!values.contains_key(&field)) as i64;
                    values.insert(field, value);
                }
            }
            integer(added)
        }
        "HGET" if args.len() == 3 => {
            let result = context.state.redis_hashes.lock().ok().and_then(|hashes| hashes.get(arg(1)?.as_str())?.get(arg(2)?.as_str()).cloned());
            result.map_or_else(null_bulk, |value| bulk(value.as_bytes()))
        }
        "HGETALL" if args.len() == 2 => {
            let values = context.state.redis_hashes.lock().ok().and_then(|hashes| hashes.get(arg(1)?.as_str()).cloned()).unwrap_or_default();
            let mut responses = Vec::with_capacity(values.len() * 2);
            for (field, value) in values { responses.push(bulk(field.as_bytes())); responses.push(bulk(value.as_bytes())); }
            array_raw(&responses)
        }
        "FLUSHDB" | "FLUSHALL" => {
            if let Ok(mut map) = context.state.redis.lock() { map.clear(); }
            if let Ok(mut map) = context.state.redis_hashes.lock() { map.clear(); }
            simple("OK")
        }
        "CONFIG" if args.len() >= 3 && arg(1).is_some_and(|v| v.eq_ignore_ascii_case("GET")) => {
            let name = arg(2).unwrap_or_default();
            let value = match name.as_str() { "dir" => "/var/lib/redis", "dbfilename" => "dump.rdb", "requirepass" => "", _ => "" };
            array_raw(&[bulk(name.as_bytes()), bulk(value.as_bytes())])
        }
        "CLIENT" | "HELLO" => simple("OK"),
        _ => error(&format!("ERR unknown command '{}', with args beginning with:", command.to_ascii_lowercase())),
    }
}

async fn read_command(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    limit: usize,
) -> io::Result<Option<Vec<Vec<u8>>>> {
    let Some(prefix_line) = read_line(reader, limit).await? else {
        return Ok(None);
    };
    if prefix_line.first() != Some(&b'*') {
        let args = prefix_line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        return Ok(Some(args));
    }
    let count = parse_length(&prefix_line[1..])?;
    if count == 0 {
        return Ok(Some(Vec::new()));
    }
    if count > MAX_ARGS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many RESP arguments",
        ));
    }
    let mut args = Vec::with_capacity(count);
    let mut total_bytes = 0usize;
    for _ in 0..count {
        let line = read_line(reader, 32).await?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated RESP command")
        })?;
        if line.first() != Some(&b'$') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP bulk string expected",
            ));
        }
        let length = parse_length(&line[1..])?;
        total_bytes = total_bytes.saturating_add(length);
        if total_bytes > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP command exceeds input limit",
            ));
        }
        let mut value = vec![0; length];
        reader.read_exact(&mut value).await?;
        let mut ending = [0; 2];
        reader.read_exact(&mut ending).await?;
        if ending != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid RESP bulk ending",
            ));
        }
        args.push(value);
    }
    Ok(Some(args))
}

async fn read_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let byte = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && line.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if byte == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
        if line.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP line exceeds limit",
            ));
        }
        line.push(byte);
    }
}

fn parse_length(value: &[u8]) -> io::Result<usize> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid RESP length"))
}

fn matches_pattern(key: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return key.starts_with(prefix);
    }
    key == pattern
}

fn bulk(value: &[u8]) -> Vec<u8> {
    let mut response = format!("${}\r\n", value.len()).into_bytes();
    response.extend_from_slice(value);
    response.extend_from_slice(b"\r\n");
    response
}
fn null_bulk() -> Vec<u8> {
    b"$-1\r\n".to_vec()
}
fn integer(value: i64) -> Vec<u8> {
    format!(":{value}\r\n").into_bytes()
}
fn array(values: &[&str]) -> Vec<u8> {
    array_raw(
        &values
            .iter()
            .map(|value| bulk(value.as_bytes()))
            .collect::<Vec<_>>(),
    )
}
fn array_raw(values: &[Vec<u8>]) -> Vec<u8> {
    let mut response = format!("*{}\r\n", values.len()).into_bytes();
    for value in values {
        response.extend_from_slice(value);
    }
    response
}
