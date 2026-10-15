use std::{io, net::SocketAddr};

use serde_json::json;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::ServiceContext;
use crate::telemetry::SessionTelemetry;

pub async fn serve_mysql(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    write_mysql_packet(&mut writer, 0, &mysql_greeting()).await?;
    let Some((_seq, handshake)) = read_mysql_packet(&mut reader, context.max_input_bytes).await?
    else {
        return Ok(());
    };
    if handshake.len() < 33 {
        return Err(invalid("short MySQL handshake response"));
    }
    let capabilities = u32::from_le_bytes(handshake[0..4].try_into().unwrap_or([0; 4]));
    let (username, auth_response) = mysql_credentials(&handshake, capabilities);
    let accepted = is_virtual_db_user(&username)
        && [
            "admin",
            "admin123",
            "password",
            "password1",
            "123456",
            "12345678",
            "qwerty",
            "letmein",
            "welcome",
            "ubuntu",
            "toor",
        ]
        .iter()
        .any(|password| mysql_native_password_matches(password.as_bytes(), auth_response));
    telemetry.emit("auth.attempted", json!({"username":username,"accepted":accepted,"database":"mysql","verification":"mysql_native_password"}));
    telemetry.emit("vulnerability.exploit_attempt", json!({"profile_id":"sql_database_weak_credentials","database":"mysql","username":username,"accepted":accepted,"peer":peer.ip().to_string()}));
    if !accepted {
        telemetry.emit(
            "auth.failed",
            json!({"username":username,"database":"mysql"}),
        );
        write_mysql_packet(
            &mut writer,
            2,
            &mysql_error(1045, "28000", "Access denied for user"),
        )
        .await?;
        return Ok(());
    }
    telemetry.emit(
        "auth.succeeded",
        json!({"username":username,"database":"mysql"}),
    );
    write_mysql_packet(&mut writer, 2, &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]).await?;
    loop {
        let Some((_seq, packet)) = read_mysql_packet(&mut reader, context.max_input_bytes).await?
        else {
            return Ok(());
        };
        let Some((&command, payload)) = packet.split_first() else {
            continue;
        };
        if command == 0x01 {
            return Ok(());
        }
        if command != 0x03 {
            write_mysql_packet(
                &mut writer,
                1,
                &mysql_error(1047, "08S01", "Unsupported command"),
            )
            .await?;
            continue;
        }
        let query = String::from_utf8_lossy(payload)
            .trim()
            .trim_end_matches(';')
            .to_owned();
        telemetry.emit(
            "virtual_action",
            json!({"service":"mysql","action":"query","query":truncate(&query, 256)}),
        );
        let response = mysql_query(&query, &context);
        for (sequence, message) in response.into_iter().enumerate() {
            write_mysql_packet(&mut writer, (sequence + 1) as u8, &message).await?;
        }
    }
}

pub async fn serve_postgres(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let (startup, startup_code) = read_pg_startup(&mut reader, context.max_input_bytes).await?;
    if startup_code == 80_877_103 {
        writer.write_all(b"N").await?;
        let (startup, _code) = read_pg_startup(&mut reader, context.max_input_bytes).await?;
        let username = startup_username(&startup);
        return postgres_auth_loop(&mut reader, &mut writer, username, peer, context, telemetry)
            .await;
    }
    let username = startup_username(&startup);
    postgres_auth_loop(&mut reader, &mut writer, username, peer, context, telemetry).await
}

async fn postgres_auth_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    username: String,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    write_pg_message(writer, b'R', &[0, 0, 0, 3]).await?;
    let Some((message_type, payload)) = read_pg_message(reader, context.max_input_bytes).await?
    else {
        return Ok(());
    };
    if message_type != b'p' {
        return Err(invalid("PostgreSQL password message expected"));
    }
    let password = payload.split(|byte| *byte == 0).next().unwrap_or_default();
    let accepted = is_virtual_db_user(&username) && weak_password_bytes(password);
    telemetry.emit(
        "auth.attempted",
        json!({"username":username,"accepted":accepted,"database":"postgres"}),
    );
    telemetry.emit("vulnerability.exploit_attempt", json!({"profile_id":"sql_database_weak_credentials","database":"postgres","username":username,"accepted":accepted,"peer":peer.ip().to_string()}));
    if !accepted {
        telemetry.emit(
            "auth.failed",
            json!({"username":username,"database":"postgres"}),
        );
        let mut error = Vec::new();
        error.extend_from_slice(b"SERROR\0C28P01\0Mpassword authentication failed\0\0");
        write_pg_message(writer, b'E', &error).await?;
        write_pg_message(writer, b'X', &[]).await?;
        return Ok(());
    }
    telemetry.emit(
        "auth.succeeded",
        json!({"username":username,"database":"postgres"}),
    );
    write_pg_message(writer, b'R', &[0, 0, 0, 0]).await?;
    write_pg_message(writer, b'S', b"server_version\x0017.0-mellcore\0").await?;
    write_pg_message(writer, b'S', b"client_encoding\0UTF8\0").await?;
    write_pg_message(writer, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    write_pg_message(writer, b'Z', b"I").await?;
    loop {
        let Some((kind, payload)) = read_pg_message(reader, context.max_input_bytes).await? else {
            return Ok(());
        };
        match kind {
            b'X' => return Ok(()),
            b'Q' => {
                let query = String::from_utf8_lossy(
                    payload.split(|byte| *byte == 0).next().unwrap_or_default(),
                )
                .trim()
                .trim_end_matches(';')
                .to_owned();
                telemetry.emit(
                    "virtual_action",
                    json!({"service":"postgres","action":"query","query":truncate(&query, 256)}),
                );
                let result = postgres_query(&query, &context);
                match result {
                    PgResult::Rows(columns, rows, tag) => {
                        let description = pg_row_description(&columns);
                        write_pg_message(writer, b'T', &description).await?;
                        for row in rows {
                            write_pg_message(writer, b'D', &pg_data_row(&row)).await?;
                        }
                        write_pg_message(writer, b'C', format!("{tag}\0").as_bytes()).await?;
                    }
                    PgResult::Command(tag) => {
                        write_pg_message(writer, b'C', format!("{tag}\0").as_bytes()).await?
                    }
                    PgResult::Error(message) => {
                        let mut error = b"SERROR\0C42P01\0M".to_vec();
                        error.extend_from_slice(message.as_bytes());
                        error.push(0);
                        error.push(0);
                        write_pg_message(writer, b'E', &error).await?;
                    }
                }
                write_pg_message(writer, b'Z', b"I").await?;
            }
            b'S' => write_pg_message(writer, b'Z', b"I").await?,
            _ => {}
        }
    }
}

fn mysql_query(query: &str, context: &ServiceContext) -> Vec<Vec<u8>> {
    let lower = query.to_ascii_lowercase();
    if lower == "select 1" || lower.starts_with("select 1 ") {
        return mysql_result(&["1"], &[vec!["1".into()]]);
    }
    if lower.contains("version()") {
        return mysql_result(&["version()"], &[vec!["8.0.36-mellcore".into()]]);
    }
    if lower.contains("user()") || lower.contains("current_user()") {
        return mysql_result(&["user()"], &[vec!["app@%".into()]]);
    }
    if lower.starts_with("show databases") {
        return mysql_result(
            &["Database"],
            &[vec!["app".into()], vec!["information_schema".into()]],
        );
    }
    if lower.starts_with("show tables") {
        return mysql_result(
            &["Tables_in_app"],
            &[vec!["users".into()], vec!["sessions".into()]],
        );
    }
    if lower.starts_with("select") {
        for table in ["users", "sessions"] {
            if lower.contains(&format!("from {table}"))
                || lower.contains(&format!("from `{table}`"))
            {
                let rows = context
                    .state
                    .sql_rows
                    .get(table)
                    .cloned()
                    .unwrap_or_default();
                let columns: &[&str] = if table == "users" {
                    &["id", "username", "email"]
                } else {
                    &["id", "user_id", "state"]
                };
                return mysql_result(columns, &rows);
            }
        }
        if lower.contains("from ") {
            return vec![mysql_error(1146, "42S02", "Table does not exist")];
        }
    }
    if lower.starts_with("insert") || lower.starts_with("update") || lower.starts_with("delete") {
        return vec![vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00]];
    }
    vec![mysql_error(
        1064,
        "42000",
        "You have an error in your SQL syntax",
    )]
}

enum PgResult {
    Rows(Vec<String>, Vec<Vec<String>>, String),
    Command(String),
    Error(String),
}
fn postgres_query(query: &str, context: &ServiceContext) -> PgResult {
    let lower = query.to_ascii_lowercase();
    if lower == "select 1" || lower.starts_with("select 1 ") {
        return PgResult::Rows(
            vec!["?column?".into()],
            vec![vec!["1".into()]],
            "SELECT 1".into(),
        );
    }
    if lower.contains("version()") {
        return PgResult::Rows(
            vec!["version".into()],
            vec![vec!["PostgreSQL 16.3-mellcore".into()]],
            "SELECT 1".into(),
        );
    }
    if lower.contains("current_user") {
        return PgResult::Rows(
            vec!["current_user".into()],
            vec![vec!["app".into()]],
            "SELECT 1".into(),
        );
    }
    if lower.starts_with("show databases") || lower.starts_with("select datname") {
        return PgResult::Rows(
            vec!["datname".into()],
            vec![vec!["app".into()], vec!["postgres".into()]],
            "SELECT 2".into(),
        );
    }
    if lower.starts_with("show tables") {
        return PgResult::Rows(
            vec!["table_name".into()],
            vec![vec!["users".into()], vec!["sessions".into()]],
            "SELECT 2".into(),
        );
    }
    if lower.starts_with("select") {
        for table in ["users", "sessions"] {
            if lower.contains(&format!("from {table}"))
                || lower.contains(&format!("from \"{table}\""))
            {
                let rows = context
                    .state
                    .sql_rows
                    .get(table)
                    .cloned()
                    .unwrap_or_default();
                let columns = if table == "users" {
                    vec!["id".into(), "username".into(), "email".into()]
                } else {
                    vec!["id".into(), "user_id".into(), "state".into()]
                };
                let row_count = rows.len();
                return PgResult::Rows(columns, rows, format!("SELECT {row_count}"));
            }
        }
        if lower.contains("from ") {
            return PgResult::Error("relation does not exist".into());
        }
    }
    if lower.starts_with("insert") || lower.starts_with("update") || lower.starts_with("delete") {
        return PgResult::Command("INSERT 0 1".into());
    }
    PgResult::Command("SET".into())
}

fn mysql_greeting() -> Vec<u8> {
    let mut packet = vec![10];
    packet.extend_from_slice(b"8.0.36-mellcore\0");
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.extend_from_slice(b"mellcore");
    packet.push(0);
    let capabilities: u32 = 0x0008_8208;
    packet.extend_from_slice(&(capabilities as u16).to_le_bytes());
    packet.push(45);
    packet.extend_from_slice(&2u16.to_le_bytes());
    packet.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    packet.push(21);
    packet.extend_from_slice(&[0; 10]);
    packet.extend_from_slice(b"123456789012");
    packet.push(0);
    packet.extend_from_slice(b"mysql_native_password\0");
    packet
}

fn mysql_result(columns: &[&str], rows: &[Vec<String>]) -> Vec<Vec<u8>> {
    let mut packets = vec![vec![columns.len() as u8]];
    for column in columns {
        let mut field = Vec::new();
        for value in ["def", "app", "", "", *column, *column] {
            put_lenenc_bytes(&mut field, value.as_bytes());
        }
        field.push(0x0c);
        field.extend_from_slice(&45u16.to_le_bytes());
        field.extend_from_slice(&1024u32.to_le_bytes());
        field.push(0xfd);
        field.extend_from_slice(&0u16.to_le_bytes());
        field.push(0);
        field.extend_from_slice(&[0, 0]);
        packets.push(field);
    }
    packets.push(vec![0xfe, 0, 0, 2, 0]);
    for row in rows {
        let mut encoded = Vec::new();
        for value in row {
            put_lenenc_bytes(&mut encoded, value.as_bytes());
        }
        packets.push(encoded);
    }
    packets.push(vec![0xfe, 0, 0, 2, 0]);
    packets
}

fn mysql_error(code: u16, state: &str, message: &str) -> Vec<u8> {
    let mut packet = vec![0xff];
    packet.extend_from_slice(&code.to_le_bytes());
    packet.push(b'#');
    packet.extend_from_slice(state.as_bytes());
    packet.extend_from_slice(message.as_bytes());
    packet
}

async fn read_mysql_packet<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut header[1..]).await?;
    let size = header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    if size > limit {
        return Err(invalid("MySQL packet exceeds input limit"));
    }
    let mut payload = vec![0; size];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[3], payload)))
}

async fn write_mysql_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    sequence: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > 0x00ff_ffff {
        return Err(invalid("MySQL response too large"));
    }
    writer
        .write_all(&[
            (payload.len() & 255) as u8,
            ((payload.len() >> 8) & 255) as u8,
            ((payload.len() >> 16) & 255) as u8,
            sequence,
        ])
        .await?;
    writer.write_all(payload).await
}

fn put_lenenc_bytes(output: &mut Vec<u8>, value: &[u8]) {
    if value.len() < 251 {
        output.push(value.len() as u8);
    } else {
        output.push(0xfc);
        output.extend_from_slice(&(value.len() as u16).to_le_bytes());
    }
    output.extend_from_slice(value);
}

fn cstring_at(value: &[u8], offset: usize) -> Option<String> {
    let end = value.get(offset..)?.iter().position(|byte| *byte == 0)? + offset;
    Some(String::from_utf8_lossy(&value[offset..end]).into_owned())
}

fn mysql_credentials(handshake: &[u8], capabilities: u32) -> (String, &[u8]) {
    let Some(username_end) = handshake
        .get(32..)
        .and_then(|slice| slice.iter().position(|byte| *byte == 0))
        .map(|end| end + 32)
    else {
        return (String::new(), &[]);
    };
    let username = cstring_at(handshake, 32).unwrap_or_default();
    let mut offset = username_end + 1;
    if capabilities & 0x0000_8000 != 0 {
        let Some(length) = handshake.get(offset).copied().map(usize::from) else {
            return (username, &[]);
        };
        offset += 1;
        let Some(response) = handshake.get(offset..offset.saturating_add(length)) else {
            return (username, &[]);
        };
        return (username, response);
    }
    let Some(end) = handshake
        .get(offset..)
        .and_then(|slice| slice.iter().position(|byte| *byte == 0))
        .map(|end| end + offset)
    else {
        return (username, &[]);
    };
    (username, handshake.get(offset..end).unwrap_or_default())
}

fn mysql_native_password_matches(password: &[u8], response: &[u8]) -> bool {
    if response.len() != 20 {
        return false;
    }
    let stage_one = Sha1::digest(password);
    let stage_two = Sha1::digest(stage_one);
    let mut salted = Vec::with_capacity(20 + stage_two.len());
    salted.extend_from_slice(b"mellcore123456789012");
    salted.extend_from_slice(&stage_two);
    let stage_three = Sha1::digest(salted);
    response
        .iter()
        .zip(stage_one.iter().zip(stage_three.iter()))
        .all(|(actual, (first, third))| *actual == (*first ^ *third))
}

async fn read_pg_startup<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<(Vec<u8>, u32)> {
    let mut length = [0; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if !(8..=limit).contains(&length) {
        return Err(invalid("PostgreSQL startup packet exceeds input limit"));
    }
    let mut payload = vec![0; length - 4];
    reader.read_exact(&mut payload).await?;
    let code = u32::from_be_bytes(
        payload
            .get(..4)
            .ok_or_else(|| invalid("short PostgreSQL startup packet"))?
            .try_into()
            .map_err(|_| invalid("invalid PostgreSQL startup code"))?,
    );
    Ok((payload, code))
}

fn startup_username(payload: &[u8]) -> String {
    let mut fields = payload
        .get(4..)
        .unwrap_or_default()
        .split(|byte| *byte == 0);
    while let (Some(key), Some(value)) = (fields.next(), fields.next()) {
        if key == b"user" {
            return String::from_utf8_lossy(value).into_owned();
        }
    }
    "unknown".into()
}

async fn read_pg_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0];
    match reader.read_exact(&mut kind).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut length = [0; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if !(4..=limit).contains(&length) {
        return Err(invalid("PostgreSQL message exceeds input limit"));
    }
    let mut payload = vec![0; length - 4];
    reader.read_exact(&mut payload).await?;
    Ok(Some((kind[0], payload)))
}

async fn write_pg_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> io::Result<()> {
    let length =
        u32::try_from(payload.len() + 4).map_err(|_| invalid("PostgreSQL response too large"))?;
    writer.write_all(&[kind]).await?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await
}

fn pg_row_description(columns: &[String]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(columns.len() as i16).to_be_bytes());
    for column in columns {
        payload.extend_from_slice(column.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&1043u32.to_be_bytes());
        payload.extend_from_slice(&(-1i16).to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
    }
    payload
}

fn pg_data_row(row: &[String]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(row.len() as i16).to_be_bytes());
    for value in row {
        payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
        payload.extend_from_slice(value.as_bytes());
    }
    payload
}

fn is_virtual_db_user(username: &str) -> bool {
    matches!(
        username.to_ascii_lowercase().as_str(),
        "app" | "admin" | "deploy" | "root" | "postgres" | "mysql" | "dbadmin"
    )
}

fn weak_password_bytes(password: &[u8]) -> bool {
    matches!(
        String::from_utf8_lossy(password)
            .to_ascii_lowercase()
            .as_str(),
        "admin"
            | "admin123"
            | "password"
            | "password1"
            | "123456"
            | "12345678"
            | "qwerty"
            | "letmein"
            | "welcome"
            | "ubuntu"
            | "toor"
    )
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
