use std::{io, net::SocketAddr};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::ServiceContext;
use crate::telemetry::SessionTelemetry;

const MAX_VIRTUAL_FILES: usize = 1024;
const MAX_VIRTUAL_FILE_BYTES: usize = 8 * 1024 * 1024;

pub async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    context: ServiceContext,
    telemetry: SessionTelemetry,
) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write
        .write_all(b"220 MellCore FTP service ready\r\n")
        .await?;
    let mut username = None::<String>;
    let mut authenticated = false;
    let mut data_connection = None;
    let mut current_directory = "/".to_owned();
    loop {
        let Some(line) = read_line(&mut read, context.max_input_bytes).await? else {
            return Ok(());
        };
        let mut parts = line.splitn(2, char::is_whitespace);
        let command = parts.next().unwrap_or_default().to_ascii_uppercase();
        let argument = parts.next().unwrap_or_default().trim();
        match command.as_str() {
            "USER" => {
                username = Some(argument.to_owned());
                authenticated = false;
                if argument.eq_ignore_ascii_case("anonymous") {
                    write
                        .write_all(
                            b"331 Anonymous login ok, send your email address as password\r\n",
                        )
                        .await?;
                } else {
                    write.write_all(b"331 Password required\r\n").await?;
                }
            }
            "PASS" => {
                let is_anonymous = username
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case("anonymous"));
                authenticated = is_anonymous;
                telemetry.emit("auth.attempted", json!({"username":username,"accepted":authenticated,"service":"ftp","peer":peer.ip().to_string()}));
                telemetry.emit("vulnerability.exploit_attempt", json!({"profile_id":"ftp_anonymous_login","username":username,"accepted":authenticated}));
                if authenticated {
                    telemetry.emit(
                        "auth.succeeded",
                        json!({"username":username,"service":"ftp"}),
                    );
                    write.write_all(b"230 Anonymous access granted\r\n").await?;
                } else {
                    telemetry.emit("auth.failed", json!({"username":username,"service":"ftp"}));
                    write.write_all(b"530 Login incorrect\r\n").await?;
                }
            }
            "QUIT" => {
                write.write_all(b"221 Goodbye\r\n").await?;
                return Ok(());
            }
            "SYST" => write.write_all(b"215 UNIX Type: L8\r\n").await?,
            "FEAT" => {
                write
                    .write_all(b"211-Features\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n")
                    .await?
            }
            "TYPE" => write.write_all(b"200 Type set\r\n").await?,
            "NOOP" => write.write_all(b"200 NOOP ok\r\n").await?,
            "PWD" if authenticated => {
                write
                    .write_all(
                        format!("257 \"{}\" is the current directory\r\n", current_directory)
                            .as_bytes(),
                    )
                    .await?
            }
            "CWD" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                let exists = virtual_directory_exists(&context, &path);
                telemetry.emit("virtual_action", json!({"service":"ftp","action":"change_directory","path":path,"accepted":exists}));
                if exists {
                    current_directory = path;
                    write.write_all(b"250 Directory changed\r\n").await?;
                } else {
                    write.write_all(b"550 Directory not found\r\n").await?;
                }
            }
            "SIZE" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                let size = context
                    .state
                    .virtual_files
                    .lock()
                    .ok()
                    .and_then(|files| files.get(&path).map(Vec::len));
                telemetry.emit(
                    "virtual_action",
                    json!({"service":"ftp","action":"stat","path":path,"exists":size.is_some()}),
                );
                if let Some(size) = size {
                    write
                        .write_all(format!("213 {size}\r\n").as_bytes())
                        .await?;
                } else {
                    write.write_all(b"550 File not found\r\n").await?;
                }
            }
            "MDTM" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                if context
                    .state
                    .virtual_files
                    .lock()
                    .is_ok_and(|files| files.contains_key(&path))
                {
                    write.write_all(b"213 20261014090000\r\n").await?;
                } else {
                    write.write_all(b"550 File not found\r\n").await?;
                }
            }
            "EPSV" => {
                if let Some(port) = context.ftp_data_port {
                    drop(data_connection.take());
                    data_connection = Some(context.ftp_data_registry.register(peer.ip()).await);
                    write
                        .write_all(
                            format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                                .as_bytes(),
                        )
                        .await?;
                } else {
                    write
                        .write_all(b"425 Passive data endpoint is not configured\r\n")
                        .await?;
                }
            }
            "PASV" => {
                write
                    .write_all(b"522 Use EPSV for the virtual passive data channel\r\n")
                    .await?
            }
            "LIST" | "NLST" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                telemetry.emit(
                    "virtual_action",
                    json!({"service":"ftp","action":"list_directory","path":path}),
                );
                let Some(receiver) = data_connection.take() else {
                    write
                        .write_all(b"425 Use EPSV before requesting a data transfer\r\n")
                        .await?;
                    continue;
                };
                write
                    .write_all(b"150 Opening virtual data connection\r\n")
                    .await?;
                match timeout(context.idle_timeout, receiver).await {
                    Ok(Ok(mut data)) => {
                        let listing = virtual_listing(&context, &path, command == "NLST");
                        data.write_all(listing.as_bytes()).await?;
                        data.shutdown().await?;
                        write.write_all(b"226 Transfer complete\r\n").await?;
                    }
                    _ => {
                        write
                            .write_all(b"425 Data connection timed out\r\n")
                            .await?
                    }
                }
            }
            "RETR" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                telemetry.emit(
                    "virtual_action",
                    json!({"service":"ftp","action":"read_file","path":path,"virtual":true}),
                );
                let content = context
                    .state
                    .virtual_files
                    .lock()
                    .ok()
                    .and_then(|files| files.get(&path).cloned());
                let Some(content) = content else {
                    write.write_all(b"550 File not found\r\n").await?;
                    continue;
                };
                if let Some(bait) = context.state.bait_files.get(&path) {
                    telemetry.emit(
                        "bait.opened",
                        json!({
                            "bait_id":bait.id,
                            "bait_name":bait.name,
                            "bait_kind":bait.kind.as_str(),
                            "path":path,
                            "operation":"read",
                        }),
                    );
                }
                let Some(receiver) = data_connection.take() else {
                    write
                        .write_all(b"425 Use EPSV before requesting a data transfer\r\n")
                        .await?;
                    continue;
                };
                write
                    .write_all(b"150 Opening virtual data connection\r\n")
                    .await?;
                match timeout(context.idle_timeout, receiver).await {
                    Ok(Ok(mut data)) => {
                        data.write_all(&content).await?;
                        data.shutdown().await?;
                        write.write_all(b"226 Transfer complete\r\n").await?;
                    }
                    _ => {
                        write
                            .write_all(b"425 Data connection timed out\r\n")
                            .await?
                    }
                }
            }
            "STOR" | "APPE" if authenticated => {
                let path = resolve_path(&current_directory, argument);
                let Some(receiver) = data_connection.take() else {
                    write
                        .write_all(b"425 Use EPSV before requesting a data transfer\r\n")
                        .await?;
                    continue;
                };
                write
                    .write_all(b"150 Opening virtual data connection\r\n")
                    .await?;
                match timeout(context.idle_timeout, receiver).await {
                    Ok(Ok(mut data)) => {
                        let mut content = Vec::new();
                        let mut limited = (&mut data).take(context.max_input_bytes as u64);
                        limited.read_to_end(&mut content).await?;
                        drop(limited);
                        let stored = if let Ok(mut files) = context.state.virtual_files.lock() {
                            let existing_size = files.get(&path).map_or(0, Vec::len);
                            let new_size = if command == "APPE" {
                                existing_size
                                    .saturating_add(content.len())
                                    .min(context.max_input_bytes)
                            } else {
                                content.len().min(context.max_input_bytes)
                            };
                            let total_size = files.values().map(Vec::len).sum::<usize>();
                            let projected_size = total_size
                                .saturating_sub(existing_size)
                                .saturating_add(new_size);
                            if path.len() > 4096
                                || (!files.contains_key(&path) && files.len() >= MAX_VIRTUAL_FILES)
                                || projected_size > MAX_VIRTUAL_FILE_BYTES
                            {
                                false
                            } else {
                                if command == "APPE" {
                                    if let Some(existing) = files.get_mut(&path) {
                                        existing.extend_from_slice(&content);
                                        existing.truncate(context.max_input_bytes);
                                    } else {
                                        files.insert(path.clone(), content.clone());
                                    }
                                } else {
                                    files.insert(path.clone(), content.clone());
                                }
                                true
                            }
                        } else {
                            false
                        };
                        let bytes = content.len();
                        data.shutdown().await?;
                        telemetry.emit("virtual_action", json!({"service":"ftp","action":"write_file","path":path,"bytes":bytes,"stored":stored}));
                        if stored {
                            write.write_all(b"226 Transfer complete\r\n").await?;
                        } else {
                            write
                                .write_all(b"552 Virtual storage limit reached\r\n")
                                .await?;
                        }
                    }
                    _ => {
                        write
                            .write_all(b"425 Data connection timed out\r\n")
                            .await?
                    }
                }
            }
            "PWD" | "CWD" | "SIZE" | "MDTM" | "LIST" | "NLST" | "RETR" | "STOR" | "APPE" => {
                write
                    .write_all(b"530 Please login with USER and PASS\r\n")
                    .await?;
            }
            _ => write.write_all(b"502 Command not implemented\r\n").await?,
        }
        write.flush().await?;
    }
}

fn virtual_listing(context: &ServiceContext, path: &str, names_only: bool) -> String {
    let Ok(files) = context.state.virtual_files.lock() else {
        return String::new();
    };
    let prefix = if path == "/" {
        "/".to_owned()
    } else {
        format!("{}/", path.trim_end_matches('/'))
    };
    let mut children = std::collections::BTreeMap::<String, Option<usize>>::new();
    for filename in files.keys() {
        if let Some(rest) = filename.strip_prefix(&prefix) {
            if let Some((directory, _)) = rest.split_once('/') {
                children.insert(directory.to_owned(), None);
            } else if !rest.is_empty() {
                children.insert(rest.to_owned(), files.get(filename).map(Vec::len));
            }
        }
    }
    if path == "/" {
        children.insert("pub".into(), None);
        children.insert("incoming".into(), None);
    }
    children
        .into_iter()
        .map(|(name, size)| {
            if names_only {
                format!("{name}\r\n")
            } else if size.is_none() {
                format!("drwxr-xr-x 1 ftp ftp 0 Oct 14 09:00 {name}\r\n")
            } else {
                format!(
                    "-rw-r--r-- 1 ftp ftp {} Oct 14 09:00 {name}\r\n",
                    size.unwrap_or_default()
                )
            }
        })
        .collect()
}

fn virtual_directory_exists(context: &ServiceContext, path: &str) -> bool {
    if path == "/" || path == "/pub" || path == "/incoming" {
        return true;
    }
    let prefix = format!("{}/", path.trim_end_matches('/'));
    context.state.virtual_files.lock().is_ok_and(|files| {
        files
            .keys()
            .any(|file| file == path || file.starts_with(&prefix))
    })
}

async fn read_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    limit: usize,
) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        if bytes.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FTP command exceeds input limit",
            ));
        }
        let byte = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && bytes.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if byte == b'\n' {
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
        }
        bytes.push(byte);
    }
}

fn virtual_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "." {
        return "/".into();
    }
    let mut normalized = Vec::new();
    let normalized_path = path.replace('\\', "/");
    for component in normalized_path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                normalized.pop();
            }
            name => normalized.push(name),
        }
    }
    format!("/{}", normalized.join("/"))
}

fn resolve_path(current_directory: &str, input: &str) -> String {
    if input.starts_with('/') {
        virtual_path(input)
    } else {
        virtual_path(&format!("{current_directory}/{input}"))
    }
}
