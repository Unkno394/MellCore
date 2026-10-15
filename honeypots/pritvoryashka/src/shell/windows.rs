//! SSH-accessible Windows Server shell simulation. Commands only mutate the virtual filesystem.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hf_core::{BaitFile, BaitKind, VirtualProcess};
use serde::{Deserialize, Serialize};

use crate::{deception::DeceptionMetrics, filesystem::VirtualFileSystem};

use super::executor::{BaitOpen, FsAction, FsActionKind, ShellOutput, VulnerabilityAttempt};

pub struct WindowsShell {
    hostname: String,
    user: String,
    cwd: String,
    fs: VirtualFileSystem,
    baits: Vec<BaitFile>,
    processes: Vec<VirtualProcess>,
    vulnerability_profiles: BTreeSet<String>,
    variables: BTreeMap<String, PsValue>,
    max_input_bytes: usize,
}

#[cfg(test)]
mod scenario_command_tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap()
    }

    fn command(shell: &mut WindowsShell, words: &[&str]) -> ShellOutput {
        shell.execute_words(
            &words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
            None,
            now(),
        )
    }

    #[test]
    fn service_share_and_registry_commands_read_the_same_virtual_state() {
        let profiles = [
            "win_autologon_credentials",
            "win_always_install_elevated",
            "win_writable_service_binary",
            "win_guest_share",
        ]
        .map(str::to_owned);
        let mut shell = WindowsShell::new_with_scenarios(
            "matrix-host",
            "admin",
            8192,
            &[],
            &[],
            &profiles,
            now(),
        );
        assert!(
            command(&mut shell, &["sc.exe", "qc", "OpsBackup"])
                .output
                .contains("backup.exe")
        );
        assert!(
            command(&mut shell, &["Get-Service", "OpsBackup"])
                .output
                .contains("OpsBackup")
        );
        assert!(
            command(&mut shell, &["net", "share"])
                .output
                .contains("PublicShare")
        );
        assert!(
            command(&mut shell, &["Get-SmbShare"])
                .output
                .contains("PublicShare")
        );
        assert!(
            command(
                &mut shell,
                &["Get-Acl", "C:\\ProgramData\\OpsBackup\\backup.exe"]
            )
            .output
            .contains("Modify")
        );
        assert!(
            command(
                &mut shell,
                &["icacls", "C:\\ProgramData\\OpsBackup\\backup.exe"]
            )
            .output
            .contains("Users:(M)")
        );
        assert!(
            command(
                &mut shell,
                &[
                    "Get-ItemProperty",
                    "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                ]
            )
            .output
            .contains("DECOY-ONLY")
        );
        assert!(
            command(
                &mut shell,
                &[
                    "Get-ItemProperty",
                    "HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer"
                ]
            )
            .output
            .contains("AlwaysInstallElevated")
        );
        assert!(
            command(&mut shell, &["Get-Command", "msiexec.exe"])
                .output
                .contains("msiexec.exe")
        );
    }

    #[test]
    fn writable_service_binary_changes_only_the_virtual_filesystem() {
        let profiles = ["win_writable_service_binary".to_owned()];
        let mut shell = WindowsShell::new_with_scenarios(
            "matrix-host",
            "admin",
            8192,
            &[],
            &[],
            &profiles,
            now(),
        );
        let result = command(
            &mut shell,
            &[
                "Set-Content",
                "C:\\ProgramData\\OpsBackup\\backup.exe",
                "-Value",
                "matrix",
            ],
        );
        assert_eq!(result.exit_status, 0, "{}", result.output);
        assert!(
            result
                .fs_actions
                .iter()
                .any(|action| action.path == "/C/ProgramData/OpsBackup/backup.exe")
        );
        assert!(
            command(
                &mut shell,
                &["Get-Content", "C:\\ProgramData\\OpsBackup\\backup.exe"]
            )
            .output
            .contains("matrix")
        );
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ParsedScript {
    error: Option<String>,
    #[serde(default)]
    items: Vec<PsStatement>,
}

enum ParserWorkerState {
    Uninitialized,
    Unavailable,
    Running(ParserWorker),
}

struct ParserWorker {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Result<String, String>>,
}

impl ParserWorker {
    fn spawn() -> Result<Self, String> {
        let mut child = Command::new("pwsh")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                include_str!("../../powershell/parse-only.ps1"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "PowerShell parser is unavailable in this Middle image.".to_owned())?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "PowerShell parser did not open its input stream.".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "PowerShell parser did not open its output stream.".to_owned())?;
        let (sender, responses) = mpsc::channel();
        thread::Builder::new()
            .name("powershell-parser-output".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            if sender.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            break;
                        }
                    }
                }
            })
            .map_err(|_| "PowerShell parser output reader could not start.".to_owned())?;
        Ok(Self {
            child,
            stdin,
            responses,
        })
    }

    fn request(&mut self, source: &str) -> Result<String, String> {
        if self
            .child
            .try_wait()
            .map_err(|_| "PowerShell parser state could not be checked.".to_owned())?
            .is_some()
        {
            return Err("PowerShell parser process exited unexpectedly.".into());
        }
        let request = serde_json::to_string(source)
            .map_err(|_| "PowerShell parser request could not be encoded.".to_owned())?;
        self.stdin
            .write_all(request.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|_| "PowerShell parser did not accept the input.".to_owned())?;
        match self.responses.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("PowerShell parser output stream closed unexpectedly.".into())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Err("PowerShell parser timed out.".into())
            }
        }
    }
}

impl Drop for ParserWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

static POWERSHELL_PARSER: OnceLock<Mutex<ParserWorkerState>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PsStatement {
    Pipeline {
        elements: Vec<PsElement>,
    },
    Assignment {
        left: String,
        right: String,
    },
    If {
        clauses: Vec<PsClause>,
        #[serde(default)]
        else_body: Vec<PsStatement>,
    },
    ForEach {
        variable: String,
        expression: String,
        body: Vec<PsStatement>,
    },
}

#[derive(Clone, Debug, Deserialize)]
struct PsClause {
    condition: String,
    body: Vec<PsStatement>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PsElement {
    Command { words: Vec<String> },
    Expression { text: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
enum PsValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<PsValue>),
    Object(BTreeMap<String, PsValue>),
}

const POWERSHELL_ALIASES: &[(&str, &str)] = &[
    ("%", "ForEach-Object"),
    ("?", "Where-Object"),
    ("cat", "Get-Content"),
    ("cd", "Set-Location"),
    ("clear", "Clear-Host"),
    ("cp", "Copy-Item"),
    ("dir", "Get-ChildItem"),
    ("echo", "Write-Output"),
    ("gci", "Get-ChildItem"),
    ("gi", "Get-Item"),
    ("gl", "Get-Location"),
    ("gcm", "Get-Command"),
    ("gal", "Get-Alias"),
    ("gps", "Get-Process"),
    ("gsv", "Get-Service"),
    ("ls", "Get-ChildItem"),
    ("measure", "Measure-Object"),
    ("mkdir", "New-Item"),
    ("mv", "Move-Item"),
    ("pwd", "Get-Location"),
    ("rm", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("del", "Remove-Item"),
    ("ren", "Rename-Item"),
    ("type", "Get-Content"),
    ("select", "Select-Object"),
    ("where", "Where-Object"),
    ("md", "New-Item"),
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WinService {
    name: String,
    display_name: String,
    status: String,
    start_type: String,
    process_id: u32,
    #[serde(default)]
    services: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WinProcess {
    name: String,
    id: u32,
    cpu_seconds: u32,
    working_set_kb: u32,
    path: String,
    #[serde(default)]
    services: Vec<String>,
    running: bool,
}

fn process_handle_count(process: &WinProcess) -> u32 {
    match process.name.to_ascii_lowercase().as_str() {
        "system" => 0,
        "registry" => 1,
        _ => 32 + process.id.wrapping_mul(37) % 640,
    }
}

fn process_nonpaged_pool_kb(process: &WinProcess) -> u32 {
    match process.name.to_ascii_lowercase().as_str() {
        "system" | "registry" => 0,
        _ => 4 + process.id.wrapping_mul(13) % 112,
    }
}

fn tasklist_image_name(process: &WinProcess) -> String {
    if matches!(
        process.name.to_ascii_lowercase().as_str(),
        "system" | "registry"
    ) {
        process.name.clone()
    } else if process.name.to_ascii_lowercase().ends_with(".exe") {
        process.name.clone()
    } else {
        format!("{}.exe", process.name)
    }
}

fn tasklist_session(process: &WinProcess) -> (&'static str, u8) {
    let system_process = matches!(
        process.name.to_ascii_lowercase().as_str(),
        "system"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "svchost"
            | "sshd"
            | "backup"
    );
    if system_process || !process.services.is_empty() {
        ("Services", 0)
    } else {
        ("Console", 1)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WinNetwork {
    adapter: String,
    interface_index: u32,
    mac: String,
    ipv4: String,
    prefix: u8,
    gateway: String,
    dns: Vec<String>,
    dhcp: bool,
    dns_suffix: String,
}

impl PsValue {
    fn text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => value.to_string(),
            Self::String(value) => value.clone(),
            Self::Array(values) => values.iter().map(Self::text).collect::<Vec<_>>().join("\n"),
            Self::Object(values) => {
                let major = value_property(values, "Major");
                let minor = value_property(values, "Minor");
                let build = value_property(values, "Build");
                let revision = value_property(values, "Revision");
                if let (Some(major), Some(minor), Some(build), Some(revision)) =
                    (major, minor, build, revision)
                {
                    format!(
                        "{}.{}.{}.{}",
                        major.text(),
                        minor.text(),
                        build.text(),
                        revision.text()
                    )
                } else {
                    values
                        .iter()
                        .map(|(name, value)| format!("{name}={}", value.text()))
                        .collect::<Vec<_>>()
                        .join("; ")
                }
            }
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0,
            Self::String(value) => !value.is_empty(),
            Self::Array(values) => !values.is_empty(),
            Self::Object(_) => true,
        }
    }
}

fn value_property<'a>(values: &'a BTreeMap<String, PsValue>, name: &str) -> Option<&'a PsValue> {
    values
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    let value = value.to_ascii_lowercase().into_bytes();
    let pattern = pattern.to_ascii_lowercase().into_bytes();
    let mut matched = vec![false; value.len() + 1];
    matched[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            b'*' => {
                next[0] = matched[0];
                for index in 1..=value.len() {
                    next[index] = matched[index] || next[index - 1];
                }
            }
            b'?' => {
                for index in 1..=value.len() {
                    next[index] = matched[index - 1];
                }
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = matched[index - 1] && value[index - 1] == literal;
                }
            }
        }
        matched = next;
    }
    matched[value.len()]
}

fn split_at_top_level<'a>(
    input: &'a str,
    operators: &[&str],
) -> Option<(&'a str, &'a str, &'a str)> {
    let mut quote = None;
    let mut parens = 0i32;
    let mut braces = 0i32;
    let mut brackets = 0i32;
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if let Some(open) = quote {
            if ch == open {
                if open == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                    chars.next();
                } else {
                    quote = None;
                }
            } else if open == '"' && ch == '`' {
                chars.next();
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                continue;
            }
            '(' => {
                parens += 1;
                continue;
            }
            ')' => {
                parens -= 1;
                continue;
            }
            '{' => {
                braces += 1;
                continue;
            }
            '}' => {
                braces -= 1;
                continue;
            }
            '[' => {
                brackets += 1;
                continue;
            }
            ']' => {
                brackets -= 1;
                continue;
            }
            _ => {}
        }
        if parens != 0 || braces != 0 || brackets != 0 {
            continue;
        }
        for operator in operators {
            if input[index..].len() >= operator.len()
                && input[index..]
                    .get(..operator.len())
                    .is_some_and(|rest| rest.eq_ignore_ascii_case(operator))
            {
                let end = index + operator.len();
                return Some((&input[..index], &input[index..end], &input[end..]));
            }
        }
    }
    None
}

fn split_array_items(input: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut parens = 0i32;
    for (index, ch) in input.char_indices() {
        if let Some(open) = quote {
            if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => parens += 1,
            ')' => parens -= 1,
            ',' if parens == 0 => {
                items.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < input.len() {
        items.push(input[start..].trim());
    }
    items.into_iter().filter(|item| !item.is_empty()).collect()
}

fn outer_parentheses_wrap(input: &str) -> bool {
    if !input.starts_with('(') || !input.ends_with(')') {
        return false;
    }
    let mut depth = 0i32;
    let mut quote = None;
    for (index, ch) in input.char_indices() {
        if let Some(open) = quote {
            if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && index + ch.len_utf8() < input.len() {
            return false;
        }
    }
    depth == 0
}

fn service_value(service: WinService) -> PsValue {
    PsValue::Object(BTreeMap::from([
        ("Name".into(), PsValue::String(service.name)),
        ("DisplayName".into(), PsValue::String(service.display_name)),
        ("Status".into(), PsValue::String(service.status)),
        ("StartType".into(), PsValue::String(service.start_type)),
        (
            "ProcessId".into(),
            PsValue::Number(service.process_id as i64),
        ),
    ]))
}

fn network_value(network: &WinNetwork) -> PsValue {
    PsValue::Object(BTreeMap::from([
        ("Name".into(), PsValue::String(network.adapter.clone())),
        ("Status".into(), PsValue::String("Up".into())),
        ("LinkSpeed".into(), PsValue::String("1 Gbps".into())),
        (
            "InterfaceAlias".into(),
            PsValue::String(network.adapter.clone()),
        ),
        (
            "InterfaceIndex".into(),
            PsValue::Number(network.interface_index as i64),
        ),
        ("MacAddress".into(), PsValue::String(network.mac.clone())),
        ("IPAddress".into(), PsValue::String(network.ipv4.clone())),
        (
            "PrefixLength".into(),
            PsValue::Number(network.prefix as i64),
        ),
        (
            "DefaultGateway".into(),
            PsValue::String(network.gateway.clone()),
        ),
        ("IPv4Address".into(), PsValue::String(network.ipv4.clone())),
        (
            "IPv4DefaultGateway".into(),
            PsValue::String(network.gateway.clone()),
        ),
        (
            "DNSServer".into(),
            PsValue::Array(network.dns.iter().cloned().map(PsValue::String).collect()),
        ),
        ("DhcpEnabled".into(), PsValue::Bool(network.dhcp)),
        (
            "DnsSuffix".into(),
            PsValue::String(network.dns_suffix.clone()),
        ),
    ]))
}

fn format_values(values: &[PsValue]) -> String {
    if values.is_empty() {
        return String::new();
    }
    if values
        .iter()
        .all(|value| matches!(value, PsValue::Object(_)))
    {
        let objects = values
            .iter()
            .filter_map(|value| {
                if let PsValue::Object(object) = value {
                    Some(object)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let Some(first) = objects.first() else {
            return String::new();
        };
        let preferred: &[&str] =
            if first.contains_key("Status") && first.contains_key("DisplayName") {
                &["Status", "Name", "DisplayName"]
            } else if first.contains_key("Id") && first.contains_key("CPU") {
                &["Handles", "NPM", "WS", "CPU", "Id", "Name"]
            } else if first.contains_key("InterfaceAlias") {
                &[
                    "InterfaceAlias",
                    "InterfaceIndex",
                    "IPAddress",
                    "PrefixLength",
                    "DefaultGateway",
                    "MacAddress",
                ]
            } else if first.contains_key("Count") {
                &["Count"]
            } else if first.contains_key("DriveLetter") {
                &[
                    "DriveLetter",
                    "FileSystemLabel",
                    "FileSystem",
                    "DriveType",
                    "HealthStatus",
                    "OperationalStatus",
                    "SizeRemaining",
                    "Size",
                ]
            } else if first.contains_key("ServerAddresses") {
                &[
                    "InterfaceAlias",
                    "InterfaceIndex",
                    "AddressFamily",
                    "ServerAddresses",
                ]
            } else if first.contains_key("TimeCreated") && first.contains_key("ProviderName") {
                &[
                    "TimeCreated",
                    "Id",
                    "LevelDisplayName",
                    "ProviderName",
                    "LogName",
                    "Message",
                ]
            } else if first.contains_key("CookedValue") {
                &["Path", "InstanceName", "CookedValue", "Timestamp"]
            } else if first.contains_key("SMBIOSBIOSVersion") {
                &["SMBIOSBIOSVersion", "Manufacturer", "Name", "SerialNumber"]
            } else if first.contains_key("ExecutablePath") {
                &[
                    "ProcessId",
                    "ParentProcessId",
                    "Name",
                    "ExecutablePath",
                    "ThreadCount",
                ]
            } else {
                &[]
            };
        let mut columns = preferred
            .iter()
            .filter(|name| value_property(first, name).is_some())
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        if columns.is_empty() {
            columns = first.keys().cloned().collect();
        }
        let cells = objects
            .iter()
            .map(|object| {
                columns
                    .iter()
                    .map(|name| {
                        value_property(object, name)
                            .map(PsValue::text)
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let widths = columns
            .iter()
            .enumerate()
            .map(|(column, name)| {
                cells
                    .iter()
                    .map(|row| row[column].chars().count())
                    .max()
                    .unwrap_or(0)
                    .max(name.chars().count())
            })
            .collect::<Vec<_>>();
        let header = columns
            .iter()
            .enumerate()
            .map(|(index, name)| format!("{name:<width$}", width = widths[index]))
            .collect::<Vec<_>>()
            .join("  ");
        let separator = columns
            .iter()
            .enumerate()
            .map(|(index, _)| "-".repeat(widths[index]))
            .collect::<Vec<_>>()
            .join("  ");
        let rows = cells
            .iter()
            .map(|row| {
                row.iter()
                    .enumerate()
                    .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
                    .collect::<Vec<_>>()
                    .join("  ")
            })
            .collect::<Vec<_>>();
        return format!("{header}\n{separator}\n{}\n", rows.join("\n"));
    }
    values
        .iter()
        .map(|value| format!("{}\n", value.text()))
        .collect()
}

fn parse_with_powershell(line: &str) -> Result<Vec<PsStatement>, String> {
    let parser = POWERSHELL_PARSER.get_or_init(|| Mutex::new(ParserWorkerState::Uninitialized));
    let Ok(mut state) = parser.lock() else {
        return parse_fallback_script(line);
    };
    if matches!(*state, ParserWorkerState::Uninitialized) {
        *state = match ParserWorker::spawn() {
            Ok(worker) => ParserWorkerState::Running(worker),
            Err(_) => ParserWorkerState::Unavailable,
        };
    }
    let parsed: ParsedScript = match &mut *state {
        ParserWorkerState::Unavailable => return parse_fallback_script(line),
        ParserWorkerState::Uninitialized => unreachable!(),
        ParserWorkerState::Running(worker) => match worker.request(line) {
            Ok(response) => match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(_) => {
                    *state = ParserWorkerState::Uninitialized;
                    return Err("PowerShell parser returned an invalid result.".into());
                }
            },
            Err(error) => {
                *state = ParserWorkerState::Uninitialized;
                return Err(error);
            }
        },
    };
    if let Some(error) = parsed.error {
        return Err(error);
    }
    Ok(parsed.items)
}

fn parse_fallback_script(source: &str) -> Result<Vec<PsStatement>, String> {
    let mut items = Vec::new();
    for statement in split_script_statements(source) {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        if starts_with_keyword(statement, "if") {
            let rest = statement[2..].trim_start();
            let Some(open_paren) = rest.find('(') else {
                return Err("Missing '(' after 'if' in PowerShell expression.".into());
            };
            let close_paren = matching_delimiter(rest, open_paren, '(', ')')
                .ok_or_else(|| "Missing ')' in PowerShell condition.".to_owned())?;
            let condition = rest[open_paren + 1..close_paren].trim().to_owned();
            let after_condition = rest[close_paren + 1..].trim_start();
            let Some(open_brace) = after_condition.find('{') else {
                return Err("Missing '{' after PowerShell condition.".into());
            };
            let close_brace = matching_delimiter(after_condition, open_brace, '{', '}')
                .ok_or_else(|| "Missing '}' in PowerShell condition body.".to_owned())?;
            if !after_condition[..open_brace].trim().is_empty() {
                return Err("Unexpected input before PowerShell condition body.".into());
            }
            let body = parse_fallback_script(&after_condition[open_brace + 1..close_brace])?;
            let tail = after_condition[close_brace + 1..].trim();
            let else_body = if starts_with_keyword(tail, "else") {
                let block = tail[4..].trim_start();
                let Some(open) = block.find('{') else {
                    return Err("Missing '{' after 'else'.".into());
                };
                let close = matching_delimiter(block, open, '{', '}')
                    .ok_or_else(|| "Missing '}' in PowerShell else body.".to_owned())?;
                parse_fallback_script(&block[open + 1..close])?
            } else if tail.is_empty() {
                Vec::new()
            } else {
                return Err("Unexpected input after PowerShell condition body.".into());
            };
            items.push(PsStatement::If {
                clauses: vec![PsClause { condition, body }],
                else_body,
            });
            continue;
        }
        if starts_with_keyword(statement, "foreach") {
            let rest = statement[7..].trim_start();
            let Some(open_paren) = rest.find('(') else {
                return Err("Missing '(' after 'foreach' in PowerShell expression.".into());
            };
            let close_paren = matching_delimiter(rest, open_paren, '(', ')')
                .ok_or_else(|| "Missing ')' in PowerShell foreach expression.".to_owned())?;
            let iterator = rest[open_paren + 1..close_paren].trim();
            let Some((variable, expression)) = iterator.split_once(" in ") else {
                return Err("Invalid PowerShell foreach expression.".into());
            };
            let variable = variable.trim();
            let expression = expression.trim();
            if !variable.starts_with('$') || expression.is_empty() {
                return Err("Invalid PowerShell foreach expression.".into());
            }
            let after_iterator = rest[close_paren + 1..].trim_start();
            let Some(open_brace) = after_iterator.find('{') else {
                return Err("Missing '{' after PowerShell foreach expression.".into());
            };
            let close_brace = matching_delimiter(after_iterator, open_brace, '{', '}')
                .ok_or_else(|| "Missing '}' in PowerShell foreach body.".to_owned())?;
            if !after_iterator[..open_brace].trim().is_empty()
                || !after_iterator[close_brace + 1..].trim().is_empty()
            {
                return Err("Unexpected input around PowerShell foreach body.".into());
            }
            items.push(PsStatement::ForEach {
                variable: variable.to_owned(),
                expression: expression.to_owned(),
                body: parse_fallback_script(&after_iterator[open_brace + 1..close_brace])?,
            });
            continue;
        }
        if starts_with_keyword(statement, "exit") || starts_with_keyword(statement, "logout") {
            items.push(PsStatement::Pipeline {
                elements: vec![PsElement::Command {
                    words: vec![statement.split_whitespace().next().unwrap().to_owned()],
                }],
            });
            continue;
        }
        if let Some(equal) = top_level_assignment_operator(statement) {
            let left = statement[..equal].trim();
            let right = statement[equal + 1..].trim();
            if !left.starts_with('$') || right.is_empty() {
                return Err("Invalid PowerShell assignment.".into());
            }
            items.push(PsStatement::Assignment {
                left: left.to_owned(),
                right: right.to_owned(),
            });
            continue;
        }
        let parts = split_top_level(statement, '|');
        let mut elements = Vec::new();
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                return Err("Empty command in PowerShell pipeline.".into());
            }
            if is_expression_text(part) {
                elements.push(PsElement::Expression {
                    text: part.to_owned(),
                });
            } else {
                let words = split_powershell_words(part);
                if words.is_empty() {
                    return Err("Empty PowerShell command.".into());
                }
                elements.push(PsElement::Command { words });
            }
        }
        items.push(PsStatement::Pipeline { elements });
    }
    Ok(items)
}

fn starts_with_keyword(source: &str, keyword: &str) -> bool {
    source
        .get(..keyword.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(keyword))
        && source
            .get(keyword.len()..)
            .and_then(|tail| tail.chars().next())
            .is_none_or(char::is_whitespace)
}

fn split_script_statements(source: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut parens = 0usize;
    let mut braces = 0usize;
    let mut brackets = 0usize;
    for (index, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => parens += 1,
            ')' => parens = parens.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            ';' | '\n' if parens == 0 && brackets == 0 && braces == 0 => {
                parts.push(&source[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&source[start..]);
    parts
}

fn split_top_level(source: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut parens = 0usize;
    let mut brackets = 0usize;
    let mut braces = 0usize;
    for (index, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => parens += 1,
            ')' => parens = parens.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            value if value == separator && parens == 0 && brackets == 0 && braces == 0 => {
                parts.push(&source[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&source[start..]);
    parts
}

fn matching_delimiter(source: &str, open_index: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in source
        .char_indices()
        .filter(|(index, _)| *index >= open_index)
    {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            value if value == open => depth += 1,
            value if value == close => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn top_level_assignment_operator(source: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut parens = 0usize;
    let mut brackets = 0usize;
    let mut braces = 0usize;
    for (index, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => parens += 1,
            ')' => parens = parens.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            '=' if parens == 0 && brackets == 0 && braces == 0 => {
                let before = source[..index].chars().next_back();
                let after = source[index + 1..].chars().next();
                if before != Some('=')
                    && before != Some('!')
                    && before != Some('<')
                    && before != Some('>')
                    && after != Some('=')
                {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_expression_text(source: &str) -> bool {
    let source = source.trim_start();
    source.starts_with('$')
        || source.starts_with('"')
        || source.starts_with('\'')
        || source.starts_with("@(")
        || source.starts_with('(')
        || source.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        || source.eq_ignore_ascii_case("$true")
        || source.eq_ignore_ascii_case("$false")
        || source.eq_ignore_ascii_case("$null")
}

fn split_powershell_words(source: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    let mut parens = 0usize;
    let mut braces = 0usize;
    for (index, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                start.get_or_insert(index);
                quote = Some(ch);
            }
            '(' => {
                start.get_or_insert(index);
                parens += 1;
            }
            ')' => parens = parens.saturating_sub(1),
            '{' => {
                start.get_or_insert(index);
                braces += 1;
            }
            '}' => braces = braces.saturating_sub(1),
            value if value.is_whitespace() && parens == 0 && braces == 0 => {
                if let Some(word_start) = start.take() {
                    words.push(source[word_start..index].to_owned());
                }
            }
            _ => {
                start.get_or_insert(index);
            }
        }
    }
    if let Some(word_start) = start {
        words.push(source[word_start..].to_owned());
    }
    words
}

pub fn check_parser() -> Result<(), String> {
    let parsed = parse_with_powershell(
        "$test = 123; if ($test -eq 123) { Get-Process | Select-Object Name }; \"hello\"; 1 + 2; @(1, 2, 3)",
    )?;
    if parsed.len() == 5
        && matches!(parsed.first(), Some(PsStatement::Assignment { left, .. }) if left.eq_ignore_ascii_case("$test"))
        && matches!(parsed.get(1), Some(PsStatement::If { .. }))
        && matches!(parsed.get(2), Some(PsStatement::Pipeline { elements }) if matches!(elements.first(), Some(PsElement::Expression { .. })))
    {
        Ok(())
    } else {
        Err("PowerShell parser did not return the expected safe AST for expressions, assignment, conditions and pipelines.".into())
    }
}

impl WindowsShell {
    pub fn new(
        hostname: &str,
        user: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        processes: &[VirtualProcess],
        now: DateTime<Utc>,
    ) -> Self {
        Self::new_with_scenarios(hostname, user, max_input_bytes, baits, processes, &[], now)
    }

    pub fn new_with_scenarios(
        hostname: &str,
        user: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        processes: &[VirtualProcess],
        vulnerability_profiles: &[String],
        now: DateTime<Utc>,
    ) -> Self {
        let mut fs = VirtualFileSystem::windows(hostname, user, now);
        for bait in baits {
            if let Some(path) = &bait.path {
                let _ = fs.install_bait(bait, path, now);
            }
        }
        let mut shell = Self {
            hostname: hostname.into(),
            user: user.into(),
            cwd: format!("/C/Users/{user}"),
            fs,
            baits: baits.to_vec(),
            processes: processes.to_vec(),
            vulnerability_profiles: vulnerability_profiles.iter().cloned().collect(),
            variables: BTreeMap::new(),
            max_input_bytes,
        };
        shell.initialize_windows_state(now);
        shell.initialize_variables();
        shell
    }

    pub fn prompt(&self) -> String {
        format!("PS {}> ", Self::display_path(&self.cwd))
    }
    pub fn metrics(&self) -> DeceptionMetrics {
        DeceptionMetrics::default()
    }
    pub fn filesystem(&self) -> &VirtualFileSystem {
        &self.fs
    }
    pub fn replace_filesystem(&mut self, mut fs: VirtualFileSystem) {
        let now = Utc::now();
        fs.upgrade_windows_layout(&self.fs, now);
        self.fs = fs;
        self.initialize_windows_state(now);
        self.initialize_variables();
    }

    fn display_path(path: &str) -> String {
        let rest = path.strip_prefix("/C").unwrap_or(path);
        format!(
            "C:{}",
            if rest.is_empty() {
                "\\".into()
            } else {
                rest.replace('/', "\\")
            }
        )
    }

    fn path(&self, raw: &str) -> Option<String> {
        if raw.contains('\0') || raw.len() > 4096 {
            return None;
        }
        let value = raw.trim_matches(['\'', '"']).replace('\\', "/");
        let joined = if value.len() >= 2 && value.as_bytes()[1] == b':' {
            if !value[..1].eq_ignore_ascii_case("c") {
                return None;
            }
            format!("/C{}", &value[2..])
        } else if value.starts_with("/C/") || value == "/C" {
            value
        } else if value.starts_with('/') {
            format!("/C{value}")
        } else if value == "~" {
            format!("/C/Users/{}", self.user)
        } else {
            format!("{}/{}", self.cwd, value)
        };
        let normalized = VirtualFileSystem::normalize("/", &joined).ok()?;
        if normalized != "/C" && !normalized.starts_with("/C/") {
            return None;
        }
        let mut current = String::new();
        for component in normalized.split('/').filter(|part| !part.is_empty()) {
            let parent = if current.is_empty() { "/" } else { &current };
            let canonical = self.fs.list(parent).ok().and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(component))
                    .map(|(name, _)| name)
            });
            current.push('/');
            current.push_str(canonical.as_deref().unwrap_or(component));
        }
        Some(current)
    }

    fn output(text: impl Into<String>) -> ShellOutput {
        ShellOutput {
            output: text.into(),
            ..ShellOutput::default()
        }
    }
    fn error(text: impl Into<String>) -> ShellOutput {
        ShellOutput {
            output: text.into(),
            exit_status: 1,
            ..ShellOutput::default()
        }
    }

    fn write_host(&self, args: &[String]) -> ShellOutput {
        let mut values = Vec::new();
        let mut separator = " ".to_owned();
        let mut no_newline = false;
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if arg.eq_ignore_ascii_case("-NoNewline") {
                no_newline = true;
            } else if arg.eq_ignore_ascii_case("-Separator") {
                if let Some(value) = args.get(index + 1) {
                    separator.clone_from(value);
                    index += 1;
                }
            } else if ["-ForegroundColor", "-BackgroundColor", "-InformationAction"]
                .iter()
                .any(|parameter| arg.eq_ignore_ascii_case(parameter))
            {
                index += usize::from(index + 1 < args.len());
            } else if arg.eq_ignore_ascii_case("-Object") {
                // The following argument is still part of the object list.
            } else {
                values.push(arg.as_str());
            }
            index += 1;
        }
        let mut output = values.join(&separator);
        if !no_newline {
            output.push('\n');
        }
        Self::output(output)
    }

    fn join_path_command(&self, args: &[String]) -> ShellOutput {
        match self.join_path_value(args) {
            PsValue::String(path) if !path.is_empty() => Self::output(format!("{path}\n")),
            _ => Self::error("Join-Path: A path and child path are required.\n"),
        }
    }

    fn execution_policy(&self, args: &[String]) -> ShellOutput {
        if args.iter().any(|arg| arg.eq_ignore_ascii_case("-List")) {
            return Self::output(
                "Scope          ExecutionPolicy\n-----          ---------------\nMachinePolicy  Undefined\nUserPolicy     Undefined\nProcess        Undefined\nCurrentUser    Undefined\nLocalMachine   RemoteSigned\n",
            );
        }
        let scope = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Scope"))
            .and_then(|index| args.get(index + 1))
            .map(String::as_str);
        let policy = match scope.map(str::to_ascii_lowercase).as_deref() {
            Some("machinepolicy" | "userpolicy" | "process" | "currentuser") => "Undefined",
            _ => "RemoteSigned",
        };
        Self::output(format!("{policy}\n"))
    }

    fn module_values(&self) -> Vec<PsValue> {
        [
            ("Microsoft.PowerShell.Archive", "1.2.5", "Manifest"),
            ("Microsoft.PowerShell.Diagnostics", "3.0.0.0", "Manifest"),
            ("Microsoft.PowerShell.Host", "3.0.0.0", "Manifest"),
            ("Microsoft.PowerShell.Management", "3.1.0.0", "Manifest"),
            ("Microsoft.PowerShell.Security", "3.0.0.0", "Manifest"),
            ("Microsoft.PowerShell.Utility", "3.1.0.0", "Manifest"),
            ("Microsoft.WSMan.Management", "3.0.0.0", "Manifest"),
            ("PackageManagement", "1.4.8.1", "Manifest"),
            ("PowerShellGet", "2.2.5", "Script"),
            ("PSReadline", "2.0.0", "Binary"),
        ]
        .into_iter()
        .map(|(name, version, module_type)| {
            PsValue::Object(BTreeMap::from([
                ("Name".into(), PsValue::String(name.into())),
                ("Version".into(), PsValue::String(version.into())),
                ("ModuleType".into(), PsValue::String(module_type.into())),
                (
                    "Path".into(),
                    PsValue::String(format!(
                        "{}\\{name}\\{name}.psd1",
                        if name.starts_with("Microsoft.") {
                            "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules"
                        } else {
                            "C:\\Program Files\\WindowsPowerShell\\Modules"
                        }
                    )),
                ),
            ]))
        })
        .collect()
    }

    fn get_module(&self, args: &[String]) -> ShellOutput {
        let filter = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|index| args.get(index + 1))
            .or_else(|| args.iter().find(|arg| !arg.starts_with('-')));
        let values = self
            .module_values()
            .into_iter()
            .filter(|module| {
                filter.is_none_or(|filter| {
                    value_property(
                        match module {
                            PsValue::Object(object) => object,
                            _ => unreachable!(),
                        },
                        "Name",
                    )
                    .is_some_and(|name| wildcard_match(&name.text(), filter))
                })
            })
            .collect::<Vec<_>>();
        Self::output(format_values(&values))
    }

    fn cmd_command(&self, args: &[String]) -> ShellOutput {
        let Some(command_index) = args.iter().position(|arg| {
            matches!(
                arg.trim_start_matches(['-', '/'])
                    .to_ascii_lowercase()
                    .as_str(),
                "c" | "k"
            )
        }) else {
            return Self::output(format!(
                "Microsoft Windows [Version 10.0.20348.2402]\n(c) Microsoft Corporation. All rights reserved.\n\n{}>",
                Self::display_path(&self.cwd)
            ));
        };
        let command = args
            .get(command_index + 1..)
            .unwrap_or_default()
            .join(" ")
            .trim()
            .trim_matches(['\'', '"'])
            .to_owned();
        let mut words = split_powershell_words(&command);
        if words.is_empty() {
            return Self::output("");
        }
        let verb = words
            .remove(0)
            .trim_matches(['\'', '"'])
            .to_ascii_lowercase();
        match verb.as_str() {
            "ver" => Self::output("Microsoft Windows [Version 10.0.20348.2402]\n"),
            "echo" => Self::output(format!("{}\n", words.join(" "))),
            "whoami" => Self::output(format!("{}\\{}\n", self.hostname, self.user)),
            "hostname" => Self::output(format!("{}\n", self.hostname)),
            _ => Self::error(format!(
                "'{}' is not recognized as an internal or external command, operable program or batch file.\n",
                verb
            )),
        }
    }

    fn reg_command(&self, args: &[String], _now: DateTime<Utc>) -> ShellOutput {
        let Some(action) = args.first() else {
            return Self::error("ERROR: Invalid syntax. Type \"REG /?\" for usage.\n");
        };
        if !action.eq_ignore_ascii_case("query") {
            return Self::error("ERROR: Invalid syntax. Type \"REG /?\" for usage.\n");
        }
        let Some(key_args) = args.get(1..) else {
            return Self::error("ERROR: The syntax of this command is incorrect.\n");
        };
        let raw_key = key_args
            .iter()
            .take_while(|arg| !arg.starts_with('/') && !arg.starts_with('-'))
            .map(|arg| arg.trim_matches(['\'', '"']))
            .collect::<Vec<_>>()
            .join(" ");
        if raw_key.is_empty() {
            return Self::error("ERROR: The syntax of this command is incorrect.\n");
        }
        let normalized = if let Some(rest) =
            strip_prefix_ignore_ascii_case(&raw_key, "HKEY_LOCAL_MACHINE\\")
        {
            format!("HKLM:\\{rest}")
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(&raw_key, "HKEY_CURRENT_USER\\") {
            format!("HKCU:\\{rest}")
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(&raw_key, "HKLM\\") {
            format!("HKLM:\\{rest}")
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(&raw_key, "HKCU\\") {
            format!("HKCU:\\{rest}")
        } else {
            return Self::error(
                "ERROR: The system was unable to find the specified registry key or value.\n",
            );
        };
        let Some(key) = self.registry_path(&normalized) else {
            return Self::error(
                "ERROR: The system was unable to find the specified registry key or value.\n",
            );
        };
        if !self.registry_read_allowed(&key) {
            return Self::error("ERROR: Access is denied.\n");
        }
        let Some(value_name) = args
            .iter()
            .position(|arg| arg.trim_start_matches(['-', '/']).eq_ignore_ascii_case("v"))
            .and_then(|index| args.get(index + 1))
        else {
            return self.reg_query_key(&key, None);
        };
        self.reg_query_key(&key, Some(value_name))
    }

    fn reg_query_key(&self, key: &str, selected: Option<&String>) -> ShellOutput {
        let target = format!("{key}.txt");
        if !self.fs.exists(key) && !self.fs.exists(&target) {
            return Self::error(
                "ERROR: The system was unable to find the specified registry key or value.\n",
            );
        }
        let values = String::from_utf8_lossy(self.fs.read(&target).unwrap_or_default());
        let mut output = format!("{}\n", Self::display_registry_key(key));
        for (name, value) in values.lines().filter_map(|line| line.split_once('=')) {
            if selected.is_some_and(|wanted| !name.eq_ignore_ascii_case(wanted)) {
                continue;
            }
            let kind = if ["start", "type", "alwaysinstallelevated"]
                .iter()
                .any(|dword| name.eq_ignore_ascii_case(dword))
            {
                "REG_DWORD"
            } else {
                "REG_SZ"
            };
            output.push_str(&format!("    {name:<24}{kind:<12}{value}\n"));
        }
        let mut result = Self::output(output);
        result.fs_actions.push(FsAction {
            kind: FsActionKind::Accessed,
            operation: "registry_query",
            path: target,
        });
        result
    }

    fn display_registry_key(key: &str) -> String {
        let rest = key.strip_prefix("/Registry/").unwrap_or(key);
        if let Some(rest) = rest.strip_prefix("HKLM/") {
            format!("HKEY_LOCAL_MACHINE\\{}", rest.replace('/', "\\"))
        } else if let Some(rest) = rest.strip_prefix("HKCU/") {
            format!("HKEY_CURRENT_USER\\{}", rest.replace('/', "\\"))
        } else {
            rest.replace('/', "\\")
        }
    }

    fn owner_principal(&self, owner: &str) -> String {
        if owner.eq_ignore_ascii_case("SYSTEM") || owner.eq_ignore_ascii_case("root") {
            "NT AUTHORITY\\SYSTEM".into()
        } else if owner.eq_ignore_ascii_case("Administrators") {
            "BUILTIN\\Administrators".into()
        } else if owner.eq_ignore_ascii_case("Users") {
            "BUILTIN\\Users".into()
        } else if owner.eq_ignore_ascii_case(&self.user) {
            format!("{}\\{}", self.hostname, self.user)
        } else {
            format!("{}\\{}", self.hostname, owner)
        }
    }

    fn initialize_variables(&mut self) {
        let version = PsValue::Object(BTreeMap::from([
            ("Major".into(), PsValue::Number(5)),
            ("Minor".into(), PsValue::Number(1)),
            ("Build".into(), PsValue::Number(20348)),
            ("Revision".into(), PsValue::Number(0)),
        ]));
        let table = PsValue::Object(BTreeMap::from([
            ("PSVersion".into(), version),
            ("PSEdition".into(), PsValue::String("Desktop".into())),
            (
                "PSCompatibleVersions".into(),
                PsValue::Array(vec![
                    PsValue::String("1.0".into()),
                    PsValue::String("2.0".into()),
                    PsValue::String("3.0".into()),
                    PsValue::String("4.0".into()),
                    PsValue::String("5.0".into()),
                    PsValue::String("5.1.20348.0".into()),
                ]),
            ),
            (
                "BuildVersion".into(),
                PsValue::String("10.0.20348.2402".into()),
            ),
            (
                "CLRVersion".into(),
                PsValue::String("4.0.30319.42000".into()),
            ),
            ("WSManStackVersion".into(), PsValue::String("3.0".into())),
            (
                "PSRemotingProtocolVersion".into(),
                PsValue::String("2.3".into()),
            ),
            (
                "SerializationVersion".into(),
                PsValue::String("1.1.0.1".into()),
            ),
        ]));
        let env = [
            ("username", self.user.clone()), ("computername", self.hostname.clone()),
            ("userdomain", self.hostname.clone()), ("userprofile", format!("C:\\Users\\{}", self.user)),
            ("homedrive", "C:".into()), ("homepath", format!("\\Users\\{}", self.user)),
            ("windir", "C:\\Windows".into()), ("systemroot", "C:\\Windows".into()),
            ("systemdrive", "C:".into()), ("os", "Windows_NT".into()),
            ("processor_architecture", "AMD64".into()), ("path", "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\".into()),
            ("temp", format!("C:\\Users\\{}\\AppData\\Local\\Temp", self.user)),
            ("tmp", format!("C:\\Users\\{}\\AppData\\Local\\Temp", self.user)),
        ];
        for (key, value) in env {
            self.variables
                .insert(format!("env:{key}"), PsValue::String(value));
        }
        self.variables.insert("psversiontable".into(), table);
        self.variables
            .insert("pwd".into(), PsValue::String(Self::display_path(&self.cwd)));
        self.variables.insert(
            "home".into(),
            PsValue::String(format!("C:\\Users\\{}", self.user)),
        );
    }

    fn initialize_windows_state(&mut self, now: DateTime<Utc>) {
        self.ensure_directory("/C/Windows/System32/OpenSSH", now);
        self.ensure_directory("/C/ProgramData/ssh", now);
        let ssh_binaries = [
            ("ssh.exe", 355_328usize),
            ("sshd.exe", 421_888usize),
            ("ssh-keygen.exe", 233_472usize),
            ("sftp.exe", 340_992usize),
        ];
        for (name, size) in ssh_binaries {
            let path = format!("/C/Windows/System32/OpenSSH/{name}");
            if !self.fs.exists(&path) {
                let seed = path.bytes().fold(0x9e37_79b9u32, |state, byte| {
                    state.rotate_left(5) ^ u32::from(byte)
                });
                self.fs.put_file(
                    &path,
                    crate::filesystem::windows_pe_fixture(size, seed),
                    now,
                );
                if let Ok(node) = self.fs.node_mut(&path) {
                    node.permissions = crate::filesystem::permissions::Permissions(0o755);
                }
            }
        }
        if !self.fs.exists("/C/ProgramData/ssh/sshd_config") {
            self.fs.put_file(
                "/C/ProgramData/ssh/sshd_config",
                "# OpenSSH server configuration\nPort 22\nAddressFamily any\nListenAddress 0.0.0.0\nPubkeyAuthentication yes\nPasswordAuthentication yes\nSubsystem sftp sftp-server.exe\n",
                now,
            );
        }
        let hosts = format!(
            "# Copyright (c) Microsoft Corp.\n127.0.0.1 localhost\n::1 localhost\n10.20.0.24 {}\n",
            self.hostname
        );
        let _ = self.fs.write(
            "/C/Windows/System32/drivers/etc/hosts",
            hosts.into_bytes(),
            now,
        );
        let _ = self.fs.write(
            "/Registry/HKLM/SOFTWARE/AppSuite.txt",
            format!(
                "ComputerName={}\nInstallPath=C:\\Program Files\\AppSuite\n",
                self.hostname
            )
            .into_bytes(),
            now,
        );
        let mut services: Vec<WinService> =
            serde_json::from_slice(self.fs.read("/State/services.json").unwrap_or_default())
                .unwrap_or_default();
        if services.is_empty() {
            let defaults = [
                ("AppIDSvc", "Application Identity", "Stopped", "Manual", 948),
                (
                    "BrokerInfrastructure",
                    "Background Tasks Infrastructure Service",
                    "Running",
                    "Automatic",
                    804,
                ),
                (
                    "CryptSvc",
                    "Cryptographic Services",
                    "Running",
                    "Automatic",
                    948,
                ),
                (
                    "DcomLaunch",
                    "DCOM Server Process Launcher",
                    "Running",
                    "Automatic",
                    804,
                ),
                ("Dhcp", "DHCP Client", "Running", "Automatic", 948),
                ("Dnscache", "DNS Client", "Running", "Automatic", 948),
                ("EventLog", "Windows Event Log", "Running", "Automatic", 948),
                ("LanmanServer", "Server", "Running", "Automatic", 1088),
                (
                    "LanmanWorkstation",
                    "Workstation",
                    "Running",
                    "Automatic",
                    1088,
                ),
                ("LSM", "Local Session Manager", "Running", "Automatic", 804),
                (
                    "MpsSvc",
                    "Windows Defender Firewall",
                    "Running",
                    "Automatic",
                    948,
                ),
                (
                    "RpcEptMapper",
                    "RPC Endpoint Mapper",
                    "Running",
                    "Automatic",
                    804,
                ),
                ("Schedule", "Task Scheduler", "Running", "Automatic", 804),
                (
                    "SamSs",
                    "Security Accounts Manager",
                    "Running",
                    "Automatic",
                    672,
                ),
                ("Sshd", "OpenSSH SSH Server", "Running", "Automatic", 3712),
                (
                    "TermService",
                    "Remote Desktop Services",
                    "Running",
                    "Manual",
                    804,
                ),
                ("W32Time", "Windows Time", "Stopped", "Manual", 1088),
                (
                    "WinDefend",
                    "Microsoft Defender Antivirus Service",
                    "Running",
                    "Automatic",
                    948,
                ),
                (
                    "WinRM",
                    "Windows Remote Management (WS-Management)",
                    "Running",
                    "Automatic",
                    1088,
                ),
                ("WSearch", "Windows Search", "Stopped", "Automatic", 1088),
            ];
            services = defaults
                .into_iter()
                .map(
                    |(name, display_name, status, start_type, process_id)| WinService {
                        name: name.trim().into(),
                        display_name: display_name.into(),
                        status: status.into(),
                        start_type: start_type.into(),
                        process_id,
                        services: Vec::new(),
                    },
                )
                .collect();
        }
        if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
            && !services.iter().any(|service| service.name == "OpsBackup")
        {
            services.push(WinService {
                name: "OpsBackup".into(),
                display_name: "Operations Backup".into(),
                status: "Running".into(),
                start_type: "Automatic".into(),
                process_id: 4256,
                services: Vec::new(),
            });
        }

        let mut processes: Vec<WinProcess> =
            serde_json::from_slice(self.fs.read("/State/processes.json").unwrap_or_default())
                .unwrap_or_default();
        if processes.is_empty() {
            processes = vec![
                ("System", 4, 0, 96, "NT Kernel & System", true),
                ("Registry", 88, 0, 11800, "Registry", true),
                ("smss", 356, 0, 1152, "Session Manager Subsystem", true),
                ("csrss", 492, 0, 5400, "Client Server Runtime Process", true),
                (
                    "wininit",
                    576,
                    0,
                    4800,
                    "Windows Start-Up Application",
                    true,
                ),
                (
                    "services",
                    660,
                    0,
                    10200,
                    "Services and Controller app",
                    true,
                ),
                (
                    "lsass",
                    672,
                    0,
                    14300,
                    "Local Security Authority Process",
                    true,
                ),
                ("winlogon", 588, 0, 9200, "Windows Logon Application", true),
                ("svchost", 804, 0, 21000, "Service Host: DcomLaunch", true),
                (
                    "svchost",
                    948,
                    0,
                    27800,
                    "Service Host: LocalServiceNetworkRestricted",
                    true,
                ),
                ("svchost", 1088, 0, 24600, "Service Host: netsvcs", true),
                ("dwm", 1272, 0, 62000, "Desktop Window Manager", true),
                ("explorer", 2860, 18, 78200, "Windows Explorer", true),
                (
                    "taskhostw",
                    2992,
                    1,
                    14100,
                    "Host Process for Windows Tasks",
                    true,
                ),
                ("sshd", 3712, 0, 17100, "OpenSSH SSH Server", true),
                ("powershell", 3920, 2, 44800, "Windows PowerShell", true),
                ("conhost", 3940, 0, 6800, "Console Window Host", true),
            ]
            .into_iter()
            .map(
                |(name, id, cpu_seconds, working_set_kb, path, running)| WinProcess {
                    name: name.into(),
                    id,
                    cpu_seconds,
                    working_set_kb,
                    path: path.into(),
                    services: Vec::new(),
                    running,
                },
            )
            .collect();
        }
        if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
            && !processes.iter().any(|process| process.id == 4256)
        {
            processes.push(WinProcess {
                name: "backup".into(),
                id: 4256,
                cpu_seconds: 1,
                working_set_kb: 12288,
                path: "C:\\ProgramData\\OpsBackup\\backup.exe".into(),
                services: vec!["OpsBackup".into()],
                running: true,
            });
        }
        let mut next_id = processes
            .iter()
            .map(|process| process.id)
            .max()
            .unwrap_or(5000)
            .max(5000)
            + 1;
        for virtual_process in &self.processes {
            let process_id = if let Some(process) = processes
                .iter()
                .find(|process| process.name.eq_ignore_ascii_case(&virtual_process.name))
            {
                process.id
            } else {
                let process_id = next_id;
                processes.push(WinProcess {
                    name: virtual_process.name.clone(),
                    id: process_id,
                    cpu_seconds: 0,
                    working_set_kb: 16000,
                    path: virtual_process.command.clone(),
                    services: Vec::new(),
                    running: virtual_process.running,
                });
                next_id += 1;
                process_id
            };
            if matches!(
                virtual_process.kind,
                BaitKind::NetworkService | BaitKind::WebInterface
            ) && !services
                .iter()
                .any(|service| service.name.eq_ignore_ascii_case(&virtual_process.name))
            {
                services.push(WinService {
                    name: virtual_process.name.clone(),
                    display_name: virtual_process.title.clone(),
                    status: if virtual_process.running {
                        "Running"
                    } else {
                        "Stopped"
                    }
                    .into(),
                    start_type: "Manual".into(),
                    process_id,
                    services: Vec::new(),
                });
            }
        }
        for service in &services {
            if let Some(process) = processes
                .iter_mut()
                .find(|process| process.id == service.process_id)
            {
                if !process
                    .services
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&service.name))
                {
                    process.services.push(service.name.clone());
                }
            }
        }
        let _ = self.fs.write(
            "/State/services.json",
            serde_json::to_vec(&services).unwrap_or_default(),
            now,
        );
        let _ = self.fs.write(
            "/State/processes.json",
            serde_json::to_vec(&processes).unwrap_or_default(),
            now,
        );
        let user_rid = if self.user.eq_ignore_ascii_case("administrator") {
            500
        } else {
            1001
        };
        let current_sid = format!("S-1-5-21-3967214721-1742538666-854245398-{user_rid}");
        let mut users = if self.user.eq_ignore_ascii_case("administrator") {
            serde_json::json!([
                {"name":"Administrator","sid":current_sid,"enabled":true,"description":"Built-in account for administering the computer/domain"},
                {"name":"Guest","sid":"S-1-5-21-3967214721-1742538666-854245398-501","enabled":false,"description":"Built-in account for guest access"}
            ])
        } else {
            serde_json::json!([
                {"name":"Administrator","sid":"S-1-5-21-3967214721-1742538666-854245398-500","enabled":true,"description":"Built-in account for administering the computer/domain"},
                {"name":self.user,"sid":current_sid,"enabled":true,"description":"Local user account"},
                {"name":"Guest","sid":"S-1-5-21-3967214721-1742538666-854245398-501","enabled":false,"description":"Built-in account for guest access"}
            ])
        };
        let accounts: Vec<_> = self
            .baits
            .iter()
            .filter_map(|bait| bait.config.account.clone())
            .collect();
        for (index, bait) in accounts.iter().enumerate() {
            if let Some(entries) = users.as_array_mut() {
                if !entries.iter().any(|entry| {
                    entry["name"]
                        .as_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case(&bait.login))
                }) {
                    entries.push(serde_json::json!({"name": bait.login, "sid": format!("S-1-5-21-3967214721-1742538666-854245398-{}", 1100 + index), "enabled": true, "description": "Local user account"}));
                }
            }
            if let Some(home) = &bait.home_directory {
                self.ensure_directory(home, now);
            }
        }
        let _ = self.fs.write(
            "/State/users.json",
            serde_json::to_vec(&users).unwrap_or_default(),
            now,
        );
        for service in &services {
            let key = format!(
                "/Registry/HKLM/SYSTEM/CurrentControlSet/Services/{}",
                service.name
            );
            if !self.fs.exists(&key) {
                let _ = self.fs.mkdir(&key, now);
            }
            let image_path = if service.name.eq_ignore_ascii_case("Sshd") {
                "C:\\Windows\\System32\\OpenSSH\\sshd.exe"
            } else {
                "C:\\Windows\\System32\\svchost.exe -k netsvcs"
            };
            let props = format!(
                "DisplayName={}\nStart={}\nType=0x10\nImagePath={}\nObjectName=LocalSystem\nState={}\nProcessId={}\n",
                service.display_name,
                if service.start_type.eq_ignore_ascii_case("Automatic") {
                    2
                } else {
                    3
                },
                image_path,
                service.status,
                service.process_id
            );
            let _ = self
                .fs
                .write(&format!("{key}.txt"), props.into_bytes(), now);
        }
        self.install_windows_scenarios(now);
    }

    fn ensure_directory(&mut self, path: &str, now: DateTime<Utc>) {
        let mut current = String::new();
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            current.push('/');
            current.push_str(segment);
            if !self.fs.exists(&current) {
                let _ = self.fs.mkdir(&current, now);
            }
        }
    }

    fn install_windows_scenarios(&mut self, now: DateTime<Utc>) {
        if self
            .vulnerability_profiles
            .contains("win_autologon_credentials")
        {
            let key = "/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon";
            self.ensure_directory(key, now);
            let _ = self.fs.write(&format!("{key}.txt"), b"AutoAdminLogon=1\nDefaultUserName=svc-backup\nDefaultPassword=DECOY-ONLY-backup-2026\n".to_vec(), now);
        }
        if self
            .vulnerability_profiles
            .contains("win_always_install_elevated")
        {
            let executable = "/C/Windows/System32/msiexec.exe";
            if !self.fs.exists(executable) {
                let _ = self.fs.write(
                    executable,
                    b"MZ\x00\x00Windows Installer virtual executable\n".to_vec(),
                    now,
                );
            }
            for (hive, software) in [("HKLM", "SOFTWARE"), ("HKCU", "Software")] {
                let key =
                    format!("/Registry/{hive}/{software}/Policies/Microsoft/Windows/Installer");
                self.ensure_directory(&key, now);
                let _ = self.fs.write(
                    &format!("{key}.txt"),
                    b"AlwaysInstallElevated=1\n".to_vec(),
                    now,
                );
            }
        }
        if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
        {
            let directory = "/C/ProgramData/OpsBackup";
            self.ensure_directory(directory, now);
            let binary = format!("{directory}/backup.exe");
            if !self.fs.exists(&binary) {
                let _ = self.fs.write(
                    &binary,
                    b"MZ\x00\x00OpsBackup virtual service binary\n".to_vec(),
                    now,
                );
            }
            let key = "/Registry/HKLM/SYSTEM/CurrentControlSet/Services/OpsBackup.txt";
            let _ = self.fs.write(key, b"DisplayName=Operations Backup\nStart=2\nType=0x10\nImagePath=C:\\ProgramData\\OpsBackup\\backup.exe\nObjectName=LocalSystem\nState=Running\nProcessId=4256\n".to_vec(), now);
        }
        if self.vulnerability_profiles.contains("win_guest_share") {
            self.ensure_directory("/C/ProgramData/PublicShare", now);
            let path = "/C/ProgramData/PublicShare/README.txt";
            if !self.fs.exists(path) {
                let _ = self
                    .fs
                    .write(path, b"Shared operations documents\n".to_vec(), now);
            }
        }
    }

    fn lookup_variable(&self, reference: &str) -> PsValue {
        let reference = reference.trim().trim_start_matches('$');
        let mut parts = reference.splitn(2, '.');
        let name = parts.next().unwrap_or_default().to_ascii_lowercase();
        let Some(mut value) = self.variables.get(&name).cloned() else {
            return PsValue::Null;
        };
        if let Some(property_path) = parts.next() {
            for property in property_path.split('.') {
                if name == "pwd"
                    && (property.eq_ignore_ascii_case("path")
                        || property.eq_ignore_ascii_case("providerpath"))
                {
                    continue;
                }
                value = match value {
                    PsValue::Object(ref properties) => value_property(properties, property)
                        .cloned()
                        .unwrap_or(PsValue::Null),
                    PsValue::String(ref string) if property.eq_ignore_ascii_case("length") => {
                        PsValue::Number(string.chars().count() as i64)
                    }
                    PsValue::Array(ref items)
                        if property.eq_ignore_ascii_case("count")
                            || property.eq_ignore_ascii_case("length") =>
                    {
                        PsValue::Number(items.len() as i64)
                    }
                    _ => PsValue::Null,
                };
            }
        }
        value
    }

    fn evaluate_expression(&self, expression: &str) -> PsValue {
        let expression = expression.trim();
        if expression.is_empty() {
            return PsValue::Null;
        }
        let static_member = expression
            .to_ascii_lowercase()
            .replace("[system.environment]", "[environment]");
        match static_member.as_str() {
            "[environment]::osversion.versionstring" => {
                return PsValue::String("Microsoft Windows NT 10.0.20348.0".into());
            }
            "[environment]::osversion.version" => {
                return PsValue::Object(BTreeMap::from([
                    ("Major".into(), PsValue::Number(10)),
                    ("Minor".into(), PsValue::Number(0)),
                    ("Build".into(), PsValue::Number(20348)),
                    ("Revision".into(), PsValue::Number(0)),
                ]));
            }
            "[environment]::machinename" => {
                return PsValue::String(self.hostname.clone());
            }
            "[environment]::username" => {
                return PsValue::String(format!("{}\\{}", self.hostname, self.user));
            }
            _ => {}
        }
        if let Some(inner) = expression
            .strip_prefix("@(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return PsValue::Array(
                split_array_items(inner)
                    .into_iter()
                    .map(|item| self.evaluate_expression(item))
                    .collect(),
            );
        }
        if outer_parentheses_wrap(expression) {
            return self.evaluate_expression(&expression[1..expression.len() - 1]);
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[".."]) {
            if let (PsValue::Number(start), PsValue::Number(end)) = (
                self.evaluate_expression(left),
                self.evaluate_expression(right),
            ) {
                let length = start.abs_diff(end).min(9_999) as usize + 1;
                let step = if end >= start { 1 } else { -1 };
                return PsValue::Array(
                    (0..length)
                        .map(|offset| PsValue::Number(start + step * offset as i64))
                        .collect(),
                );
            }
        }
        for (method, uppercase) in [
            (".ToUpper()", true),
            (".ToUpperInvariant()", true),
            (".ToLower()", false),
            (".ToLowerInvariant()", false),
        ] {
            if expression.len() >= method.len() {
                let split = expression.len() - method.len();
                if expression[split..].eq_ignore_ascii_case(method) {
                    let value = self.evaluate_expression(expression[..split].trim()).text();
                    return PsValue::String(if uppercase {
                        value.to_uppercase()
                    } else {
                        value.to_lowercase()
                    });
                }
            }
        }
        let invocation = split_powershell_words(expression);
        if invocation
            .first()
            .is_some_and(|command| command.eq_ignore_ascii_case("join-path"))
        {
            return self.join_path_value(&invocation[1..]);
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" -or "]) {
            return PsValue::Bool(
                self.evaluate_expression(left).truthy() || self.evaluate_expression(right).truthy(),
            );
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" -and "]) {
            return PsValue::Bool(
                self.evaluate_expression(left).truthy() && self.evaluate_expression(right).truthy(),
            );
        }
        if let Some((left, operator, right)) = split_at_top_level(
            expression,
            &[
                " -eq ", " -ne ", " -gt ", " -ge ", " -lt ", " -le ", " -like ",
            ],
        ) {
            let left = self.evaluate_expression(left);
            let right = self.evaluate_expression(right);
            let left_num = left.text().parse::<i64>().ok();
            let right_num = right.text().parse::<i64>().ok();
            let ordering = match (left_num, right_num) {
                (Some(left), Some(right)) => Some(left.cmp(&right)),
                _ => Some(
                    left.text()
                        .to_ascii_lowercase()
                        .cmp(&right.text().to_ascii_lowercase()),
                ),
            };
            let equal = left.text().eq_ignore_ascii_case(&right.text());
            let matched = match operator.trim().to_ascii_lowercase().as_str() {
                "-eq" => equal,
                "-ne" => !equal,
                "-gt" => ordering.is_some_and(|order| order.is_gt()),
                "-ge" => ordering.is_some_and(|order| order.is_ge()),
                "-lt" => ordering.is_some_and(|order| order.is_lt()),
                "-le" => ordering.is_some_and(|order| order.is_le()),
                "-like" => {
                    let pattern = right.text().replace('*', "");
                    if right.text().starts_with('*') && right.text().ends_with('*') {
                        left.text()
                            .to_ascii_lowercase()
                            .contains(&pattern.to_ascii_lowercase())
                    } else if right.text().starts_with('*') {
                        left.text()
                            .to_ascii_lowercase()
                            .ends_with(&pattern.to_ascii_lowercase())
                    } else if right.text().ends_with('*') {
                        left.text()
                            .to_ascii_lowercase()
                            .starts_with(&pattern.to_ascii_lowercase())
                    } else {
                        equal
                    }
                }
                _ => false,
            };
            return PsValue::Bool(matched);
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" + ", "+"]) {
            let left = self.evaluate_expression(left);
            let right = self.evaluate_expression(right);
            return match (&left, &right) {
                (PsValue::Number(a), PsValue::Number(b)) => PsValue::Number(a.saturating_add(*b)),
                (PsValue::Array(items), PsValue::Array(more)) => {
                    PsValue::Array(items.iter().cloned().chain(more.iter().cloned()).collect())
                }
                (PsValue::Array(items), value) => {
                    PsValue::Array(items.iter().cloned().chain([value.clone()]).collect())
                }
                (value, PsValue::Array(items)) => PsValue::Array(
                    std::iter::once(value.clone())
                        .chain(items.iter().cloned())
                        .collect(),
                ),
                _ => PsValue::String(format!("{}{}", left.text(), right.text())),
            };
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" - ", "-"]) {
            let left = self.evaluate_expression(left);
            let right = self.evaluate_expression(right);
            if let (PsValue::Number(left), PsValue::Number(right)) = (left, right) {
                return PsValue::Number(left.saturating_sub(right));
            }
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" * ", "*"]) {
            let left = self.evaluate_expression(left);
            let right = self.evaluate_expression(right);
            if let (PsValue::Number(left), PsValue::Number(right)) = (left, right) {
                return PsValue::Number(left.saturating_mul(right));
            }
        }
        if let Some((left, _, right)) = split_at_top_level(expression, &[" / ", "/"]) {
            let left = self.evaluate_expression(left);
            let right = self.evaluate_expression(right);
            if let (PsValue::Number(left), PsValue::Number(right)) = (left, right) {
                return if right == 0 {
                    PsValue::Null
                } else {
                    PsValue::Number(left / right)
                };
            }
        }
        if expression.eq_ignore_ascii_case("$true") {
            return PsValue::Bool(true);
        }
        if expression.eq_ignore_ascii_case("$false") {
            return PsValue::Bool(false);
        }
        if expression.eq_ignore_ascii_case("$null") {
            return PsValue::Null;
        }
        if expression.starts_with('$') {
            if expression.contains(['\\', '/']) {
                return PsValue::String(self.expand_string(expression));
            }
            return self.lookup_variable(expression);
        }
        if expression.len() >= 2 && expression.starts_with('\'') && expression.ends_with('\'') {
            return PsValue::String(expression[1..expression.len() - 1].replace("''", "'"));
        }
        if expression.len() >= 2 && expression.starts_with('"') && expression.ends_with('"') {
            let text = &expression[1..expression.len() - 1];
            return PsValue::String(self.expand_string(text));
        }
        if let Ok(number) = expression.parse::<i64>() {
            return PsValue::Number(number);
        }
        if expression.contains(',') {
            let values = split_array_items(expression);
            if values.len() > 1 {
                return PsValue::Array(
                    values
                        .into_iter()
                        .map(|item| self.evaluate_expression(item))
                        .collect(),
                );
            }
        }
        PsValue::String(expression.to_owned())
    }

    fn join_path_value(&self, args: &[String]) -> PsValue {
        let argument = |flags: &[&str], position: usize| {
            args.iter()
                .position(|arg| flags.iter().any(|flag| arg.eq_ignore_ascii_case(flag)))
                .and_then(|index| args.get(index + 1))
                .or_else(|| {
                    args.iter()
                        .filter(|arg| !arg.starts_with('-'))
                        .nth(position)
                })
        };
        let Some(parent) = argument(&["-Path", "-LiteralPath"], 0) else {
            return PsValue::Null;
        };
        let Some(child) = argument(&["-ChildPath"], 1) else {
            return PsValue::Null;
        };
        let parent = self.evaluate_expression(parent).text();
        let child = self.evaluate_expression(child).text();
        let joined = if child.starts_with(['\\', '/'])
            || (child.len() >= 2 && child.as_bytes()[1] == b':')
        {
            child
        } else {
            format!(
                "{}\\{}",
                parent.trim_end_matches(['\\', '/']),
                child.trim_start_matches(['\\', '/'])
            )
        };
        let value = self
            .path(&joined)
            .map(|path| Self::display_path(&path))
            .unwrap_or_else(|| joined.replace('/', "\\"));
        PsValue::String(value)
    }

    fn expand_string(&self, input: &str) -> String {
        let chars = input.char_indices().collect::<Vec<_>>();
        let mut output = String::new();
        let mut char_pos = 0usize;
        while char_pos < chars.len() {
            let (byte_index, ch) = chars[char_pos];
            if ch == '`' && char_pos + 1 < chars.len() {
                output.push(chars[char_pos + 1].1);
                char_pos += 2;
                continue;
            }
            if ch != '$' {
                output.push(ch);
                char_pos += 1;
                continue;
            }
            let start = char_pos;
            char_pos += 1;
            if char_pos < chars.len() && chars[char_pos].1 == '{' {
                char_pos += 1;
                while char_pos < chars.len() && chars[char_pos].1 != '}' {
                    char_pos += 1;
                }
                let end = chars
                    .get(char_pos)
                    .map(|(index, _)| *index)
                    .unwrap_or(input.len());
                let begin = chars
                    .get(start + 1)
                    .map(|(index, _)| *index)
                    .unwrap_or(byte_index + 1);
                let reference = input[begin..end].trim();
                if char_pos < chars.len() {
                    char_pos += 1;
                }
                output.push_str(&self.lookup_variable(reference).text());
                continue;
            }
            while char_pos < chars.len()
                && (chars[char_pos].1.is_ascii_alphanumeric()
                    || matches!(chars[char_pos].1, '_' | ':' | '.'))
            {
                char_pos += 1;
            }
            if char_pos == start + 1 {
                output.push('$');
                continue;
            }
            let end = chars
                .get(char_pos)
                .map(|(index, _)| *index)
                .unwrap_or(input.len());
            let begin = chars
                .get(start + 1)
                .map(|(index, _)| *index)
                .unwrap_or(byte_index + 1);
            output.push_str(&self.lookup_variable(&input[begin..end]).text());
        }
        output
    }

    fn evaluate_condition(&self, condition: &str) -> bool {
        self.evaluate_expression(condition).truthy()
    }

    fn execute_items(&mut self, items: &[PsStatement], now: DateTime<Utc>) -> ShellOutput {
        let mut combined = ShellOutput::default();
        for item in items {
            let result = match item {
                PsStatement::Assignment { left, right } => {
                    let name = left.trim().trim_start_matches('$').to_ascii_lowercase();
                    if name.is_empty() || name.contains([' ', '.', '[', ']']) {
                        Self::error(
                            "ParserError: Only simple PowerShell variable assignment is supported.\n",
                        )
                    } else {
                        let value = self.evaluate_expression(right);
                        self.variables.insert(name, value.clone());
                        Self::output(format!("{}\n", value.text()))
                    }
                }
                PsStatement::Pipeline { elements } => self.execute_pipeline(elements, now),
                PsStatement::If { clauses, else_body } => {
                    let matching = clauses
                        .iter()
                        .find(|clause| self.evaluate_condition(&clause.condition));
                    if let Some(clause) = matching {
                        self.execute_items(&clause.body, now)
                    } else {
                        self.execute_items(else_body, now)
                    }
                }
                PsStatement::ForEach {
                    variable,
                    expression,
                    body,
                } => {
                    let values = match self.evaluate_expression(expression) {
                        PsValue::Array(values) => values,
                        PsValue::Null => Vec::new(),
                        value => vec![value],
                    };
                    let name = variable.trim().trim_start_matches('$').to_ascii_lowercase();
                    let mut loop_result = ShellOutput::default();
                    for value in values.into_iter().take(10_000) {
                        self.variables.insert(name.clone(), value);
                        let iteration = self.execute_items(body, now);
                        loop_result.fs_actions.extend(iteration.fs_actions);
                        loop_result.bait_opens.extend(iteration.bait_opens);
                        loop_result
                            .virtual_interactions
                            .extend(iteration.virtual_interactions);
                        if iteration.deception.is_some() {
                            loop_result.deception = iteration.deception;
                        }
                        loop_result.output.push_str(&iteration.output);
                        if iteration.close {
                            loop_result.close = true;
                            return loop_result;
                        }
                        if iteration.exit_status != 0 {
                            loop_result.exit_status = iteration.exit_status;
                            return loop_result;
                        }
                    }
                    loop_result
                }
            };
            combined.fs_actions.extend(result.fs_actions);
            combined.bait_opens.extend(result.bait_opens);
            combined
                .virtual_interactions
                .extend(result.virtual_interactions);
            if result.deception.is_some() {
                combined.deception = result.deception;
            }
            combined.output.push_str(&result.output);
            if result.close {
                combined.close = true;
                return combined;
            }
            if result.exit_status != 0 {
                combined.exit_status = result.exit_status;
                return combined;
            }
        }
        combined
    }

    fn execute_pipeline(&mut self, elements: &[PsElement], now: DateTime<Utc>) -> ShellOutput {
        let mut aggregate = ShellOutput::default();
        let mut values = Vec::<PsValue>::new();
        let mut last = ShellOutput::default();
        for (index, element) in elements.iter().enumerate() {
            let result = match element {
                PsElement::Expression { text } => {
                    values = match self.evaluate_expression(text) {
                        PsValue::Array(items) => items,
                        value => vec![value],
                    };
                    Self::output(format_values(&values))
                }
                PsElement::Command { words } => {
                    let prepared = words
                        .iter()
                        .map(|word| {
                            if word.starts_with('-') && !word.starts_with("--") {
                                word.clone()
                            } else {
                                self.evaluate_expression(word).text()
                            }
                        })
                        .collect::<Vec<_>>();
                    let command = prepared
                        .first()
                        .map(|word| word.to_ascii_lowercase())
                        .unwrap_or_default();
                    let pipeline_command = match command.as_str() {
                        "select" => "select-object",
                        "where" => "where-object",
                        "sort" => "sort-object",
                        "measure" => "measure-object",
                        other => other,
                    };
                    if matches!(
                        pipeline_command,
                        "select-object"
                            | "where-object"
                            | "sort-object"
                            | "measure-object"
                            | "out-string"
                    ) && (index > 0 || !values.is_empty())
                    {
                        self.transform_pipeline_values(
                            pipeline_command,
                            &prepared[1..],
                            &mut values,
                        )
                    } else {
                        let pipe_text = if index == 0 {
                            None
                        } else {
                            Some(format_values(&values))
                        };
                        let mut result = self.execute_words(&prepared, pipe_text.as_deref(), now);
                        if matches!(
                            command.as_str(),
                            "get-process"
                                | "gps"
                                | "get-service"
                                | "gsv"
                                | "get-childitem"
                                | "gci"
                                | "get-item"
                                | "gi"
                                | "get-netipaddress"
                                | "get-netipconfiguration"
                                | "get-netadapter"
                                | "get-ciminstance"
                                | "gwmi"
                                | "get-wmiobject"
                                | "get-volume"
                                | "get-winevent"
                                | "get-eventlog"
                                | "get-counter"
                                | "get-dnsclientserveraddress"
                        ) {
                            values = self.pipeline_source_values(&command, &prepared[1..], now);
                        } else if result.output.is_empty() {
                            values.clear();
                        } else {
                            values = result
                                .output
                                .lines()
                                .map(|line| PsValue::String(line.to_owned()))
                                .collect();
                        }
                        // Suppress intermediate formatted output; the final
                        // stage formats values after selection/projection.
                        if index + 1 < elements.len() {
                            result.output.clear();
                        }
                        result
                    }
                }
            };
            aggregate.fs_actions.extend(result.fs_actions.clone());
            aggregate.bait_opens.extend(result.bait_opens.clone());
            aggregate
                .virtual_interactions
                .extend(result.virtual_interactions.clone());
            if result.deception.is_some() {
                aggregate.deception = result.deception.clone();
            }
            if result.close || result.exit_status != 0 {
                aggregate.close = result.close;
                aggregate.exit_status = result.exit_status;
                aggregate.output.push_str(&result.output);
                return aggregate;
            }
            last = result;
        }
        if !elements.is_empty()
            && !matches!(elements.last(), Some(PsElement::Command { words }) if words.first().is_some_and(|word| matches!(word.to_ascii_lowercase().as_str(), "write-output" | "write-host" | "echo" | "out-string" | "select-object" | "select" | "where-object" | "where" | "sort-object" | "sort" | "measure-object" | "measure")))
        {
            last.output = format_values(&values);
        }
        aggregate.output.push_str(&last.output);
        aggregate
    }

    fn transform_pipeline_values(
        &self,
        command: &str,
        args: &[String],
        values: &mut Vec<PsValue>,
    ) -> ShellOutput {
        match command {
            "select-object" | "select" => {
                if let Some(count) = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-First"))
                    .and_then(|index| args.get(index + 1))
                    .and_then(|value| value.trim_matches(['\'', '"']).parse::<usize>().ok())
                {
                    values.truncate(count);
                }
                if let Some(count) = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Skip"))
                    .and_then(|index| args.get(index + 1))
                    .and_then(|value| value.trim_matches(['\'', '"']).parse::<usize>().ok())
                {
                    *values = values.iter().skip(count).cloned().collect();
                }
                if let Some(count) = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Last"))
                    .and_then(|index| args.get(index + 1))
                    .and_then(|value| value.trim_matches(['\'', '"']).parse::<usize>().ok())
                {
                    let start = values.len().saturating_sub(count);
                    *values = values[start..].to_vec();
                }
                let property_index = args.iter().position(|arg| {
                    arg.eq_ignore_ascii_case("-Property")
                        || arg.eq_ignore_ascii_case("-ExpandProperty")
                });
                let props = property_index
                    .and_then(|index| args.get(index + 1))
                    .map(|value| {
                        value
                            .trim_matches(['\'', '"'])
                            .split(',')
                            .map(str::trim)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| {
                        args.iter()
                            .filter(|arg| !arg.starts_with('-') && arg.parse::<usize>().is_err())
                            .map(|arg| arg.trim_matches(['\'', '"']).to_owned())
                            .collect()
                    });
                if props.is_empty() {
                    return Self::output(format_values(values));
                }
                let expand = args
                    .iter()
                    .any(|arg| arg.eq_ignore_ascii_case("-ExpandProperty"));
                if expand {
                    *values = values
                        .iter()
                        .filter_map(|value| match value {
                            PsValue::Object(source) => value_property(source, &props[0]).cloned(),
                            _ => None,
                        })
                        .collect();
                    return Self::output(format_values(values));
                }
                *values = values
                    .iter()
                    .map(|value| {
                        let PsValue::Object(source) = value else {
                            return value.clone();
                        };
                        let projection = props
                            .iter()
                            .filter_map(|property| {
                                value_property(source, property)
                                    .map(|value| (property.clone(), value.clone()))
                            })
                            .collect::<BTreeMap<_, _>>();
                        PsValue::Object(projection)
                    })
                    .collect();
                Self::output(format_values(values))
            }
            "sort-object" => {
                let prop = args
                    .iter()
                    .find(|arg| !arg.starts_with('-'))
                    .map(String::as_str);
                values.sort_by_key(|value| match (value, prop) {
                    (PsValue::Object(object), Some(name)) => value_property(object, name)
                        .map(PsValue::text)
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    _ => value.text().to_ascii_lowercase(),
                });
                Self::output(format_values(values))
            }
            "where-object" => {
                if let Some(expression) = args.iter().find(|arg| !arg.starts_with('-')) {
                    let normalized = expression
                        .trim()
                        .trim_start_matches('{')
                        .trim_end_matches('}')
                        .trim()
                        .replace("$_.", "")
                        .replace("$_", "");
                    if let Some((property, operator, rhs)) = split_at_top_level(
                        &normalized,
                        &[
                            " -eq ", " -ne ", " -gt ", " -ge ", " -lt ", " -le ", " -like ",
                        ],
                    ) {
                        let expected = self.evaluate_expression(rhs).text();
                        values.retain(|value| {
                            let actual = match value {
                                PsValue::Object(object) => value_property(object, property.trim())
                                    .map(PsValue::text)
                                    .unwrap_or_default(),
                                _ => value.text(),
                            };
                            match operator.trim().to_ascii_lowercase().as_str() {
                                "-eq" => actual.eq_ignore_ascii_case(&expected),
                                "-ne" => !actual.eq_ignore_ascii_case(&expected),
                                "-gt" => {
                                    actual.parse::<i64>().unwrap_or_default()
                                        > expected.parse::<i64>().unwrap_or_default()
                                }
                                "-ge" => {
                                    actual.parse::<i64>().unwrap_or_default()
                                        >= expected.parse::<i64>().unwrap_or_default()
                                }
                                "-lt" => {
                                    actual.parse::<i64>().unwrap_or_default()
                                        < expected.parse::<i64>().unwrap_or_default()
                                }
                                "-le" => {
                                    actual.parse::<i64>().unwrap_or_default()
                                        <= expected.parse::<i64>().unwrap_or_default()
                                }
                                "-like" => wildcard_match(&actual, &expected),
                                _ => false,
                            }
                        });
                    }
                }
                Self::output(format_values(values))
            }
            "measure-object" => {
                let count = values.len();
                *values = vec![PsValue::Object(BTreeMap::from([(
                    "Count".into(),
                    PsValue::Number(count as i64),
                )]))];
                Self::output(format!("\nCount    : {count}\n\n"))
            }
            "out-string" => Self::output(format_values(values)),
            _ => Self::output(format_values(values)),
        }
    }

    fn pipeline_source_values(
        &self,
        command: &str,
        args: &[String],
        now: DateTime<Utc>,
    ) -> Vec<PsValue> {
        match command {
            "get-process" | "gps" => {
                let processes: Vec<WinProcess> = serde_json::from_slice(
                    self.fs.read("/State/processes.json").unwrap_or_default(),
                )
                .unwrap_or_default();
                let name_filter = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                    .and_then(|i| args.get(i + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
                    .map(String::as_str);
                let id_filter = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Id"))
                    .and_then(|i| args.get(i + 1))
                    .and_then(|id| id.parse::<u32>().ok());
                processes
                    .into_iter()
                    .filter(|process| process.running)
                    .filter(|process| {
                        name_filter.is_none_or(|name| {
                            process.name.eq_ignore_ascii_case(name)
                                || process
                                    .name
                                    .trim_end_matches(".exe")
                                    .eq_ignore_ascii_case(name.trim_end_matches(".exe"))
                        })
                    })
                    .filter(|process| id_filter.is_none_or(|id| process.id == id))
                    .map(|process| {
                        let handles = process_handle_count(&process);
                        let nonpaged_pool_kb = process_nonpaged_pool_kb(&process);
                        PsValue::Object(BTreeMap::from([
                            ("Name".into(), PsValue::String(process.name.clone())),
                            ("Id".into(), PsValue::Number(process.id as i64)),
                            ("CPU".into(), PsValue::Number(process.cpu_seconds as i64)),
                            (
                                "WS".into(),
                                PsValue::Number(process.working_set_kb as i64 * 1024),
                            ),
                            ("ProcessName".into(), PsValue::String(process.name.clone())),
                            ("Path".into(), PsValue::String(process.path.clone())),
                            ("Handles".into(), PsValue::Number(handles as i64)),
                            ("NPM".into(), PsValue::Number(nonpaged_pool_kb as i64)),
                        ]))
                    })
                    .collect()
            }
            "get-module" | "gmo" => self.module_values(),
            "get-service" | "gsv" => {
                let services: Vec<WinService> = serde_json::from_slice(
                    self.fs.read("/State/services.json").unwrap_or_default(),
                )
                .unwrap_or_default();
                let filter = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                    .and_then(|i| args.get(i + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
                    .map(String::as_str);
                services
                    .into_iter()
                    .filter(|service| {
                        filter.is_none_or(|name| {
                            wildcard_match(&service.name, name)
                                || wildcard_match(&service.display_name, name)
                        })
                    })
                    .map(service_value)
                    .collect()
            }
            "get-childitem" | "gci" => {
                let path_arg = args
                    .iter()
                    .position(|arg| {
                        arg.eq_ignore_ascii_case("-Path")
                            || arg.eq_ignore_ascii_case("-LiteralPath")
                    })
                    .and_then(|i| args.get(i + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
                    .map(String::as_str)
                    .unwrap_or(".");
                if path_arg.eq_ignore_ascii_case("Env:") {
                    return self
                        .variables
                        .iter()
                        .filter_map(|(name, value)| {
                            name.strip_prefix("env:").map(|name| {
                                PsValue::Object(BTreeMap::from([
                                    ("Name".into(), PsValue::String(name.to_ascii_uppercase())),
                                    ("Value".into(), value.clone()),
                                ]))
                            })
                        })
                        .collect();
                }
                let Some(path) = self.path(path_arg) else {
                    return Vec::new();
                };
                self.fs
                    .list(&path)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, node)| {
                        let full_path = if path.ends_with('/') {
                            format!("{path}{name}")
                        } else {
                            format!("{path}/{name}")
                        };
                        PsValue::Object(BTreeMap::from([
                            ("Name".into(), PsValue::String(name)),
                            (
                                "FullName".into(),
                                PsValue::String(Self::display_path(&full_path)),
                            ),
                            ("Length".into(), PsValue::Number(node.len() as i64)),
                            (
                                "Mode".into(),
                                PsValue::String(
                                    if node.is_dir() { "d-----" } else { "-a----" }.into(),
                                ),
                            ),
                            (
                                "LastWriteTime".into(),
                                PsValue::String(
                                    node.modified_at.format("%m/%d/%Y %I:%M:%S %p").to_string(),
                                ),
                            ),
                            (
                                "Attributes".into(),
                                PsValue::String(
                                    if node.is_dir() {
                                        "Directory"
                                    } else {
                                        "Archive"
                                    }
                                    .into(),
                                ),
                            ),
                            (
                                "Owner".into(),
                                PsValue::String(self.owner_principal(&node.owner)),
                            ),
                        ]))
                    })
                    .collect()
            }
            "get-item" | "gi" => {
                let path_arg = args
                    .iter()
                    .position(|arg| {
                        arg.eq_ignore_ascii_case("-Path")
                            || arg.eq_ignore_ascii_case("-LiteralPath")
                    })
                    .and_then(|i| args.get(i + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
                    .map(String::as_str)
                    .unwrap_or(".");
                let Some(path) = self.path(path_arg) else {
                    return Vec::new();
                };
                self.fs
                    .node(&path)
                    .ok()
                    .map(|node| {
                        vec![PsValue::Object(BTreeMap::from([
                            (
                                "Name".into(),
                                PsValue::String(path.rsplit('/').next().unwrap_or("").into()),
                            ),
                            (
                                "FullName".into(),
                                PsValue::String(Self::display_path(&path)),
                            ),
                            ("Length".into(), PsValue::Number(node.len() as i64)),
                            (
                                "Mode".into(),
                                PsValue::String(
                                    if node.is_dir() { "d-----" } else { "-a----" }.into(),
                                ),
                            ),
                            (
                                "LastWriteTime".into(),
                                PsValue::String(
                                    node.modified_at.format("%m/%d/%Y %I:%M:%S %p").to_string(),
                                ),
                            ),
                            (
                                "Attributes".into(),
                                PsValue::String(
                                    if node.is_dir() {
                                        "Directory"
                                    } else {
                                        "Archive"
                                    }
                                    .into(),
                                ),
                            ),
                            (
                                "Owner".into(),
                                PsValue::String(self.owner_principal(&node.owner)),
                            ),
                        ]))]
                    })
                    .unwrap_or_default()
            }
            "get-netipaddress" | "get-netipconfiguration" | "get-netadapter" => {
                let network: WinNetwork =
                    serde_json::from_slice(self.fs.read("/State/network.json").unwrap_or_default())
                        .unwrap_or_default();
                vec![network_value(&network)]
            }
            "get-ciminstance" | "gwmi" | "get-wmiobject" => {
                let class = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-ClassName"))
                    .and_then(|index| args.get(index + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
                    .map(String::as_str)
                    .unwrap_or_default();
                self.cim_values(class, args)
            }
            "get-volume" => self.volume_values(args),
            "get-winevent" | "get-eventlog" => self.event_values(command, args, now),
            "get-counter" => self.counter_values(args, now),
            "get-dnsclientserveraddress" => self.dns_client_values(args),
            _ => {
                let _ = now;
                Vec::new()
            }
        }
    }

    pub fn execute(&mut self, line: &str, now: DateTime<Utc>) -> ShellOutput {
        if line.len() > self.max_input_bytes {
            return Self::error("The command line is too long.\n");
        }
        let items = match parse_with_powershell(line) {
            Ok(items) => items,
            Err(error) => return Self::error(format!("ParserError: {error}\n")),
        };
        self.variables
            .insert("pwd".into(), PsValue::String(Self::display_path(&self.cwd)));
        let mut result = self.execute_items(&items, now);
        if result.exit_status == 0 {
            let lower = line.to_ascii_lowercase();
            let observed = [
                (
                    "win_autologon_credentials",
                    lower.contains("winlogon")
                        && (lower.contains("get-itemproperty")
                            || lower.contains("get-itempropertyvalue")),
                ),
                (
                    "win_always_install_elevated",
                    (lower.contains("installer") && lower.contains("alwaysinstallelevated"))
                        || lower.contains("msiexec"),
                ),
                (
                    "win_writable_service_binary",
                    lower.contains("opsbackup")
                        && (lower.contains("set-content")
                            || lower.contains("add-content")
                            || lower.contains("sc.exe")
                            || lower.contains("get-acl")),
                ),
                (
                    "win_guest_share",
                    lower.contains("net share")
                        || lower.contains("get-smbshare")
                        || lower.contains("publicshare"),
                ),
            ];
            for (profile, matched) in observed {
                if matched && self.vulnerability_profiles.contains(profile) {
                    result.vulnerability_attempts.push(VulnerabilityAttempt {
                        profile_id: profile.into(), details: serde_json::json!({"command": line, "result": "virtual_interaction"}),
                    });
                }
            }
        }
        result
    }

    fn execute_words(
        &mut self,
        words: &[String],
        pipe_input: Option<&str>,
        now: DateTime<Utc>,
    ) -> ShellOutput {
        let Some(command) = words.first() else {
            return ShellOutput::default();
        };
        let cmd = command.to_ascii_lowercase();
        let args = &words[1..];
        let arg = args
            .iter()
            .position(|word| {
                [
                    "-Path",
                    "-LiteralPath",
                    "-Name",
                    "-Id",
                    "-Group",
                    "-Identity",
                    "-ClassName",
                ]
                .iter()
                .any(|flag| word.eq_ignore_ascii_case(flag))
            })
            .and_then(|i| args.get(i + 1))
            .or_else(|| args.iter().find(|word| !word.starts_with('-')))
            .map(String::as_str)
            .unwrap_or("");
        match cmd.as_str() {
            "write-output" | "echo" => Self::output(if args.is_empty() {
                pipe_input.unwrap_or("").to_owned()
            } else {
                format!("{}\n", args.join(" "))
            }),
            "write-host" => self.write_host(args),
            "join-path" => self.join_path_command(args),
            "get-executionpolicy" => self.execution_policy(args),
            "get-module" | "gmo" => self.get_module(args),
            "cmd" | "cmd.exe" => self.cmd_command(args),
            "reg" | "reg.exe" => self.reg_command(args, now),
            "out-string" => Self::output(pipe_input.unwrap_or("").to_owned()),
            "select-string" => {
                let pattern = args
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("-Pattern"))
                    .and_then(|index| args.get(index + 1))
                    .or_else(|| args.first());
                let Some(pattern) = pattern else {
                    return Self::error("Select-String: Specify a pattern.\n");
                };
                let source = pipe_input.unwrap_or("");
                Self::output(
                    source
                        .lines()
                        .filter(|line| {
                            line.to_ascii_lowercase()
                                .contains(&pattern.to_ascii_lowercase())
                        })
                        .map(|line| format!("{line}\n"))
                        .collect::<String>(),
                )
            }
            "sort-object" => {
                let mut rows = pipe_input.unwrap_or("").lines().collect::<Vec<_>>();
                rows.sort_unstable_by_key(|line| line.to_ascii_lowercase());
                Self::output(
                    rows.into_iter()
                        .map(|line| format!("{line}\n"))
                        .collect::<String>(),
                )
            }
            "measure-object" => Self::output(format!(
                "Count             : {}\n",
                pipe_input.unwrap_or("").lines().count()
            )),
            "get-date" => Self::output(format!("{}\n", now.format("%A, %B %-d, %Y %-I:%M:%S %p"))),
            "clear-host" | "cls" | "clear" => Self::output("\u{1b}[2J\u{1b}[H"),
            "get-command" | "gcm" => self.get_command(args),
            "get-alias" | "gal" => self.get_alias(args),
            "where.exe" => self.where_exe(args),
            "get-help" | "help" => Self::output(format!(
                "NAME\n    {}\n\nSYNOPSIS\n    Displays help for a virtual PowerShell command.\n",
                if arg.is_empty() { "Get-Help" } else { arg }
            )),
            "pwd" | "gl" | "get-location" => {
                Self::output(format!("Path\n----\n{}\n", Self::display_path(&self.cwd)))
            }
            "hostname" | "hostname.exe" => Self::output(format!("{}\n", self.hostname)),
            "whoami" | "whoami.exe" => self.whoami(args),
            "$psversiontable" => Self::output(format!(
                "{}\n",
                self.variables
                    .get("psversiontable")
                    .map(PsValue::text)
                    .unwrap_or_default()
            )),
            "get-computerinfo" => Self::output(format!(
                "CsName                : {}\nWindowsProductName    : Windows Server 2022 Standard\nOsArchitecture        : 64-bit\n",
                self.hostname
            )),
            "systeminfo" => Self::output(format!(
                "Host Name:                 {}\nOS Name:                   Microsoft Windows Server 2022 Standard\nSystem Type:               x64-based PC\n",
                self.hostname
            )),
            "ipconfig" | "ipconfig.exe" => self.ipconfig(args),
            "route" | "route.exe" => self.route_print(),
            "arp" | "arp.exe" => self.arp_table(),
            "get-ciminstance" | "gwmi" | "get-wmiobject" => {
                let class = args
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("-ClassName"))
                    .and_then(|index| args.get(index + 1))
                    .map(String::as_str)
                    .unwrap_or(arg);
                if class.eq_ignore_ascii_case("Win32_OperatingSystem") {
                    Self::output(format!(
                        "Caption           : Microsoft Windows Server 2022 Standard\nCSName            : {}\nOSArchitecture    : 64-bit\n",
                        self.hostname
                    ))
                } else if class.eq_ignore_ascii_case("Win32_ComputerSystem") {
                    Self::output(format!(
                        "Name              : {}\nUserName          : {}\\{}\n",
                        self.hostname, self.hostname, self.user
                    ))
                } else if class.eq_ignore_ascii_case("Win32_BIOS")
                    || class.eq_ignore_ascii_case("Win32_Process")
                {
                    Self::output(format_values(&self.cim_values(class, args)))
                } else {
                    Self::error(format!("Get-CimInstance: Invalid class '{}'.\n", class))
                }
            }
            "get-volume" => Self::output(format_values(&self.volume_values(args))),
            "get-winevent" | "get-eventlog" => {
                Self::output(format_values(&self.event_values(&cmd, args, now)))
            }
            "get-counter" => Self::output(format_values(&self.counter_values(args, now))),
            "get-dnsclientserveraddress" => {
                Self::output(format_values(&self.dns_client_values(args)))
            }
            "ssh" | "ssh.exe" => {
                if args.iter().any(|arg| arg == "-V") {
                    Self::output("OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2\n")
                } else {
                    Self::error(
                        "usage: ssh [-Q query_option] [-b bind_address] [-c cipher_spec] destination [command]\n",
                    )
                }
            }
            "get-localuser" => self.local_users(args),
            "get-localgroup" => self.local_groups(args),
            "get-localgroupmember" => self.local_group_members(args),
            "net" | "net.exe" => self.net_command(args),
            "get-psdrive" => Self::output(
                "Name Used (GB) Free (GB) Provider   Root\n---- --------- --------- --------   ----\nC       18.42     81.58 FileSystem C:\\\n",
            ),
            "get-netipconfiguration" | "get-netipaddress" | "get-netadapter" => {
                self.network_command(&cmd)
            }
            "get-nettcpconnection" | "netstat" | "netstat.exe" => self.tcp_connections(args),
            "get-smbshare" if self.vulnerability_profiles.contains("win_guest_share") => {
                Self::output(
                    "Name        ScopeName Path                           Description\n----        --------- ----                           -----------\nPublicShare *         C:\\ProgramData\\PublicShare    Operations documents\n",
                )
            }
            "msiexec" | "msiexec.exe"
                if self
                    .vulnerability_profiles
                    .contains("win_always_install_elevated") =>
            {
                if let Some(index) = args.iter().position(|arg| arg.eq_ignore_ascii_case("/i")) {
                    let package = args.get(index + 1).and_then(|raw| self.path(raw));
                    if package.as_deref().is_some_and(|path| {
                        path.to_ascii_lowercase().ends_with(".msi") && self.fs.exists(path)
                    }) {
                        Self::output("Windows Installer completed a virtual installation.\n")
                    } else {
                        Self::error(
                            "This installation package could not be opened. Verify that the package exists.\n",
                        )
                    }
                } else {
                    Self::output("Windows Installer. Usage: msiexec /i package.msi\n")
                }
            }
            "cd" | "sl" | "set-location" => {
                let Some(path) = self.path(if arg.is_empty() { "~" } else { arg }) else {
                    return Self::error("Set-Location: Invalid path.\n");
                };
                if !self.fs.is_dir(&path) {
                    return Self::error(format!(
                        "Set-Location: Cannot find path '{}' because it does not exist.\n",
                        arg
                    ));
                }
                self.cwd = path;
                self.variables
                    .insert("pwd".into(), PsValue::String(Self::display_path(&self.cwd)));
                ShellOutput::default()
            }
            "ls" | "dir" | "gci" | "get-childitem" => {
                if arg.eq_ignore_ascii_case("Env:") {
                    let mut output =
                        "Name                 Value\n----                 -----\n".to_owned();
                    for (name, value) in self
                        .variables
                        .iter()
                        .filter(|(name, _)| name.starts_with("env:"))
                    {
                        output.push_str(&format!(
                            "{:<20} {}\n",
                            name.trim_start_matches("env:").to_ascii_uppercase(),
                            value.text()
                        ));
                    }
                    return Self::output(output);
                }
                if let Some(path) = self.registry_path(arg) {
                    return self.registry_list(&path);
                }
                let Some(path) = self.path(if arg.is_empty() { "." } else { arg }) else {
                    return Self::error("Get-ChildItem: Invalid path.\n");
                };
                if self.is_read_restricted_path(&path) {
                    return Self::error(format!(
                        "Get-ChildItem : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                match self.fs.list(&path) {
                    Ok(entries) => {
                        let mut output = format!(
                            "    Directory: {}\n\nMode   LastWriteTime         Length Name\n----   -------------         ------ ----\n",
                            Self::display_path(&path)
                        );
                        for (name, node) in entries {
                            output.push_str(&format!(
                                "{}  {} {:>8} {}\n",
                                if node.is_dir() { "d-----" } else { "-a----" },
                                node.modified_at.format("%m/%d/%Y %I:%M %p"),
                                if node.is_dir() {
                                    String::new()
                                } else {
                                    node.len().to_string()
                                },
                                name
                            ));
                        }
                        Self::output(output)
                    }
                    Err(_) => Self::error(format!("Get-ChildItem: Cannot find path '{}'.\n", arg)),
                }
            }
            "get-item" | "gi" => {
                if arg
                    .get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Env:"))
                {
                    let name = arg[4..].to_ascii_lowercase();
                    return match self.variables.get(&format!("env:{name}")) {
                        Some(value) => Self::output(format!(
                            "Name          Value\n----          -----\n{:<13} {}\n",
                            name.to_ascii_uppercase(),
                            value.text()
                        )),
                        None => Self::error(format!(
                            "Get-Item : Cannot find path 'Env:{}' because it does not exist.\n",
                            &arg[4..]
                        )),
                    };
                }
                if let Some(path) = self.registry_path(arg) {
                    return self.registry_item(&path, arg);
                }
                let Some(path) = self.path(arg) else {
                    return Self::error("Get-Item: Specify a path.\n");
                };
                if self.is_read_restricted_path(&path) {
                    return Self::error(format!(
                        "Get-Item : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                match self.fs.node(&path) {
                    Ok(node) => {
                        let owner = self.owner_principal(&node.owner);
                        Self::output(format!(
                            "    Directory: {}\n\nMode   LastWriteTime         Length Name\n----   -------------         ------ ----\n{}  {} {:>8} {}\n\nAttributes : {}\nOwner      : {}\n",
                            Self::display_path(
                                path.rsplit_once('/')
                                    .map(|(parent, _)| if parent.is_empty() {
                                        "/C"
                                    } else {
                                        parent
                                    })
                                    .unwrap_or("/C")
                            ),
                            if node.is_dir() { "d-----" } else { "-a----" },
                            node.modified_at.format("%m/%d/%Y %I:%M %p"),
                            if node.is_dir() {
                                String::new()
                            } else {
                                node.len().to_string()
                            },
                            path.rsplit('/').next().unwrap_or(""),
                            if node.is_dir() {
                                "Directory"
                            } else {
                                "Archive"
                            },
                            owner
                        ))
                    }
                    Err(_) => Self::error(format!("Get-Item: Cannot find path '{}'.\n", arg)),
                }
            }
            "cat" | "type" | "gc" | "get-content" => {
                if arg.is_empty() && pipe_input.is_some() {
                    return Self::output(pipe_input.unwrap_or(""));
                }
                let Some(path) = self.path(arg) else {
                    return Self::error("Get-Content: Specify a path.\n");
                };
                if self.is_read_restricted_path(&path) {
                    return Self::error(format!(
                        "Get-Content : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                match self.fs.read(&path) {
                    Ok(bytes) => {
                        let mut result = Self::output(format!(
                            "{}\n",
                            String::from_utf8_lossy(bytes).trim_end_matches('\n')
                        ));
                        result.fs_actions.push(FsAction {
                            kind: FsActionKind::Accessed,
                            operation: "read",
                            path: path.clone(),
                        });
                        if let Some(bait) = self
                            .baits
                            .iter()
                            .find(|bait| bait.path.as_deref() == Some(path.as_str()))
                        {
                            result.bait_opens.push(BaitOpen {
                                id: bait.id,
                                name: bait.name.clone(),
                                path,
                                operation: "read".into(),
                                kind: bait.kind,
                            });
                        }
                        result
                    }
                    Err(_) => Self::error(format!("Get-Content: Cannot find path '{}'.\n", arg)),
                }
            }
            "test-path" => Self::output(format!(
                "{}\n",
                if arg
                    .get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Env:"))
                {
                    self.variables
                        .contains_key(&format!("env:{}", arg[4..].to_ascii_lowercase()))
                } else if let Some(path) = self.registry_path(arg) {
                    self.fs.exists(&path) || self.fs.exists(&format!("{path}.txt"))
                } else {
                    self.path(arg).is_some_and(|path| self.fs.exists(&path))
                }
            )),
            "new-item" | "ni" | "mkdir" | "md" => {
                let Some(path) = self.path(arg) else {
                    return Self::error("New-Item: Specify a valid path.\n");
                };
                if self.is_protected_path(&path) {
                    return Self::error(format!(
                        "New-Item : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                let directory = matches!(cmd.as_str(), "mkdir" | "md")
                    || args
                        .iter()
                        .any(|word| word.eq_ignore_ascii_case("directory"));
                let result = if directory {
                    self.fs.mkdir(&path, now)
                } else {
                    self.fs.touch(&path, now)
                };
                match result {
                    Ok(()) => {
                        let mut result = Self::output(format!("{}\n", Self::display_path(&path)));
                        result.fs_actions.push(FsAction {
                            kind: FsActionKind::Modified,
                            operation: "create",
                            path,
                        });
                        result
                    }
                    Err(error) => Self::error(format!("New-Item: {error}\n")),
                }
            }
            "set-content" | "add-content" => {
                let Some(path) = self.path(arg) else {
                    return Self::error("Set-Content: Specify a valid path.\n");
                };
                if self.is_protected_path(&path) {
                    return Self::error(format!(
                        "Set-Content : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                let value_pos = args
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("-value"));
                let value = value_pos
                    .and_then(|i| args.get(i + 1))
                    .or_else(|| args.get(1))
                    .map(String::as_str)
                    .or(pipe_input)
                    .unwrap_or("");
                let mut bytes = if cmd == "add-content" {
                    self.fs.read(&path).unwrap_or_default().to_vec()
                } else {
                    Vec::new()
                };
                bytes.extend_from_slice(value.as_bytes());
                bytes.push(b'\n');
                match self.fs.write(&path, bytes, now) {
                    Ok(()) => {
                        let mut result = ShellOutput::default();
                        result.fs_actions.push(FsAction {
                            kind: FsActionKind::Modified,
                            operation: "write",
                            path,
                        });
                        result
                    }
                    Err(error) => Self::error(format!("Set-Content: {error}\n")),
                }
            }
            "remove-item" | "rm" | "del" | "rmdir" => {
                let Some(path) = self.path(arg) else {
                    return Self::error("Remove-Item: Specify a valid path.\n");
                };
                if self.is_protected_path(&path) {
                    return Self::error(format!(
                        "Remove-Item : Access to the path '{}' is denied.\n",
                        Self::display_path(&path)
                    ));
                }
                let recursive = args
                    .iter()
                    .any(|word| word.eq_ignore_ascii_case("-Recurse"));
                match self.fs.remove(&path, recursive) {
                    Ok(()) => {
                        let mut result = ShellOutput::default();
                        result.fs_actions.push(FsAction {
                            kind: FsActionKind::Modified,
                            operation: "delete",
                            path,
                        });
                        result
                    }
                    Err(error) => Self::error(format!("Remove-Item: {error}\n")),
                }
            }
            "copy-item" | "cp" | "copy" | "move-item" | "mv" => {
                let target = args
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("-Destination"))
                    .and_then(|index| args.get(index + 1))
                    .or_else(|| args.get(1));
                let (Some(source), Some(mut target)) =
                    (self.path(arg), target.and_then(|value| self.path(value)))
                else {
                    return Self::error(format!(
                        "{}: Specify source and destination paths.\n",
                        command
                    ));
                };
                if self.fs.is_dir(&target) {
                    let Some(name) = source.rsplit('/').next() else {
                        return Self::error("Copy-Item: Invalid source path.\n");
                    };
                    target = format!("{}/{name}", target.trim_end_matches('/'));
                }
                let moving = matches!(cmd.as_str(), "move-item" | "mv");
                if self.is_protected_path(&target)
                    || (moving && self.is_protected_path(&source))
                    || self.is_read_restricted_path(&source)
                {
                    return Self::error(format!(
                        "{} : Access to the requested path is denied.\n",
                        command
                    ));
                }
                if self.fs.exists(&target)
                    && !args.iter().any(|word| word.eq_ignore_ascii_case("-Force"))
                {
                    return Self::error(format!(
                        "{} : Cannot create a file when that file already exists.\n",
                        command
                    ));
                }
                let result = if matches!(cmd.as_str(), "move-item" | "mv") {
                    self.fs.rename(&source, &target, now)
                } else {
                    self.fs.copy(&source, &target, now)
                };
                match result {
                    Ok(()) => {
                        let mut output = ShellOutput::default();
                        output.fs_actions.push(FsAction {
                            kind: FsActionKind::Modified,
                            operation: if matches!(cmd.as_str(), "move-item" | "mv") {
                                "move"
                            } else {
                                "copy"
                            },
                            path: target,
                        });
                        output
                    }
                    Err(error) => Self::error(format!("{}: {error}\n", command)),
                }
            }
            "rename-item" | "rni" | "ren" => {
                let new_name = args
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("-NewName"))
                    .and_then(|index| args.get(index + 1))
                    .or_else(|| args.get(1));
                let (Some(source), Some(new_name)) = (self.path(arg), new_name) else {
                    return Self::error("Rename-Item: Specify a path and new name.\n");
                };
                if new_name.is_empty()
                    || new_name.contains(['/', '\\', ':'])
                    || new_name == "."
                    || new_name == ".."
                {
                    return Self::error("Rename-Item: NewName must be a file or directory name.\n");
                }
                let parent = source
                    .rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("/C");
                let target = format!("{parent}/{new_name}");
                if self.is_protected_path(&source) || self.is_protected_path(&target) {
                    return Self::error("Rename-Item : Access to the requested path is denied.\n");
                }
                if self.fs.exists(&target)
                    && !args.iter().any(|word| word.eq_ignore_ascii_case("-Force"))
                {
                    return Self::error(
                        "Rename-Item : Cannot create a file when that file already exists.\n",
                    );
                }
                match self.fs.rename(&source, &target, now) {
                    Ok(()) => {
                        let mut output = ShellOutput::default();
                        output.fs_actions.push(FsAction {
                            kind: FsActionKind::Modified,
                            operation: "rename",
                            path: target,
                        });
                        output
                    }
                    Err(error) => Self::error(format!("Rename-Item: {error}\n")),
                }
            }
            "get-service" | "gsv" | "start-service" | "stop-service" => {
                self.service(&cmd, arg, args, now)
            }
            "sc.exe" | "sc" => self.sc_command(args, now),
            "get-acl" => self.get_acl(arg),
            "icacls" => self.icacls(arg, args),
            "get-itemproperty" | "gp" => self.registry(arg, args),
            "get-itempropertyvalue" => self.registry_value(args),
            "set-itemproperty" | "sp" => self.set_registry(args, now),
            "get-process" | "gps" | "tasklist" | "tasklist.exe" => {
                let mut result = self.process_command(&cmd, args);
                let filter = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                    .and_then(|index| args.get(index + 1))
                    .or_else(|| args.iter().find(|arg| !arg.starts_with('-')));
                for process in self.processes.iter().filter(|process| {
                    filter.is_none_or(|name| name.eq_ignore_ascii_case(&process.name))
                }) {
                    if process.running {
                        result.bait_opens.push(BaitOpen {
                            id: process.id,
                            name: process.title.clone(),
                            path: process.command.clone(),
                            operation: "process_list".into(),
                            kind: process.kind,
                        });
                    }
                }
                result
            }
            "exit" | "logout" => ShellOutput {
                close: true,
                ..ShellOutput::default()
            },
            _ => Self::error(format!(
                "{}: The term '{}' is not recognized as the name of a cmdlet, function, script file, or operable program.\n",
                command, command
            )),
        }
    }

    fn is_protected_path(&self, path: &str) -> bool {
        let path = path.to_ascii_lowercase();
        if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
            && path == "/c/programdata/opsbackup/backup.exe"
        {
            return false;
        }
        if path.starts_with("/registry/hkcu/") || path == "/registry/hkcu" {
            return false;
        }
        if path.starts_with("/registry/") {
            return true;
        }
        if !path.starts_with("/c") {
            return true;
        }
        let home = format!("/c/users/{}", self.user.to_ascii_lowercase());
        let public = "/c/users/public";
        let windows_temp = "/c/windows/temp";
        let allowed = path == home
            || path.starts_with(&(home + "/"))
            || path == public
            || path.starts_with(&(public.to_owned() + "/"))
            || path == windows_temp
            || path.starts_with(&(windows_temp.to_owned() + "/"));
        !allowed
    }

    fn is_read_restricted_path(&self, path: &str) -> bool {
        let path = path.to_ascii_lowercase();
        if path.starts_with("/c/windows/system32/config/") {
            return true;
        }
        if let Some(rest) = path.strip_prefix("/c/users/") {
            let user = rest.split('/').next().unwrap_or_default();
            return !user.eq_ignore_ascii_case(&self.user) && !user.eq_ignore_ascii_case("public");
        }
        false
    }

    fn protected_registry(path: &str) -> bool {
        let path = path.to_ascii_lowercase();
        path == "/registry/hklm/sam"
            || path.starts_with("/registry/hklm/sam/")
            || path == "/registry/hklm/security"
            || path.starts_with("/registry/hklm/security/")
    }

    fn registry_read_allowed(&self, path: &str) -> bool {
        !Self::protected_registry(path)
    }

    fn processes_state(&self) -> Vec<WinProcess> {
        serde_json::from_slice(self.fs.read("/State/processes.json").unwrap_or_default())
            .unwrap_or_default()
    }

    fn services_state(&self) -> Vec<WinService> {
        serde_json::from_slice(self.fs.read("/State/services.json").unwrap_or_default())
            .unwrap_or_default()
    }

    fn network_state(&self) -> WinNetwork {
        serde_json::from_slice(self.fs.read("/State/network.json").unwrap_or_default())
            .unwrap_or_default()
    }

    fn cim_values(&self, class: &str, args: &[String]) -> Vec<PsValue> {
        if class.eq_ignore_ascii_case("Win32_BIOS") {
            return vec![PsValue::Object(BTreeMap::from([
                (
                    "SMBIOSBIOSVersion".into(),
                    PsValue::String("Hyper-V UEFI Release v4.1".into()),
                ),
                (
                    "Manufacturer".into(),
                    PsValue::String("Microsoft Corporation".into()),
                ),
                (
                    "Name".into(),
                    PsValue::String("Hyper-V UEFI Release v4.1".into()),
                ),
                (
                    "SerialNumber".into(),
                    PsValue::String("VM-20348-7F2A91C4".into()),
                ),
                ("Version".into(), PsValue::String("VRTUAL - 1".into())),
                (
                    "ReleaseDate".into(),
                    PsValue::String("20240101000000.000000+000".into()),
                ),
            ]))];
        }
        if class.eq_ignore_ascii_case("Win32_Process") {
            let name_filter = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                .and_then(|index| args.get(index + 1))
                .cloned()
                .or_else(|| {
                    args.iter()
                        .position(|arg| arg.eq_ignore_ascii_case("-Filter"))
                        .and_then(|index| args.get(index + 1))
                        .and_then(|filter| {
                            filter
                                .split_once('=')
                                .filter(|(key, _)| key.trim().eq_ignore_ascii_case("Name"))
                                .map(|(_, value)| value.trim().trim_matches('\'').to_owned())
                        })
                });
            let id_filter = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("-Id"))
                .and_then(|index| args.get(index + 1))
                .and_then(|id| id.parse::<u32>().ok());
            return self
                .processes_state()
                .into_iter()
                .filter(|process| process.running)
                .filter(|process| {
                    name_filter.as_ref().is_none_or(|name| {
                        process
                            .name
                            .eq_ignore_ascii_case(name.trim_matches(['\'', '"']))
                            || process.name.trim_end_matches(".exe").eq_ignore_ascii_case(
                                name.trim_matches(['\'', '"']).trim_end_matches(".exe"),
                            )
                    })
                })
                .filter(|process| id_filter.is_none_or(|id| id == process.id))
                .map(|process| {
                    let parent_id = match process.name.to_ascii_lowercase().as_str() {
                        "system" => 0,
                        "registry" | "smss" => 4,
                        "csrss" | "wininit" => 356,
                        "services" => 576,
                        "sshd" => 660,
                        _ => 660,
                    };
                    let executable_path = match process.name.to_ascii_lowercase().as_str() {
                        "system" | "registry" => None,
                        "sshd" => Some("C:\\Windows\\System32\\OpenSSH\\sshd.exe".into()),
                        "powershell" => Some(
                            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(),
                        ),
                        "explorer" => Some("C:\\Windows\\explorer.exe".into()),
                        name => Some(format!("C:\\Windows\\System32\\{name}.exe")),
                    };
                    let process_name = if matches!(
                        process.name.to_ascii_lowercase().as_str(),
                        "system" | "registry"
                    ) || process.name.to_ascii_lowercase().ends_with(".exe")
                    {
                        process.name.clone()
                    } else {
                        format!("{}.exe", process.name)
                    };
                    let command_line = executable_path
                        .clone()
                        .unwrap_or_else(|| process.name.clone());
                    PsValue::Object(BTreeMap::from([
                        ("ProcessId".into(), PsValue::Number(process.id as i64)),
                        ("ParentProcessId".into(), PsValue::Number(parent_id)),
                        ("Name".into(), PsValue::String(process_name)),
                        (
                            "ExecutablePath".into(),
                            executable_path
                                .map(PsValue::String)
                                .unwrap_or(PsValue::Null),
                        ),
                        ("CommandLine".into(), PsValue::String(command_line)),
                        (
                            "WorkingSetSize".into(),
                            PsValue::Number(process.working_set_kb as i64 * 1024),
                        ),
                        ("ThreadCount".into(), PsValue::Number(8)),
                        ("SessionId".into(), PsValue::Number(0)),
                    ]))
                })
                .collect();
        }
        Vec::new()
    }

    fn volume_values(&self, args: &[String]) -> Vec<PsValue> {
        let drive_filter = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-DriveLetter"))
            .and_then(|index| args.get(index + 1));
        if drive_filter.is_some_and(|drive| !drive.eq_ignore_ascii_case("C")) {
            return Vec::new();
        }
        vec![PsValue::Object(BTreeMap::from([
            ("DriveLetter".into(), PsValue::String("C".into())),
            ("FileSystemLabel".into(), PsValue::String("OS".into())),
            ("FileSystem".into(), PsValue::String("NTFS".into())),
            ("DriveType".into(), PsValue::String("Fixed".into())),
            ("HealthStatus".into(), PsValue::String("Healthy".into())),
            ("OperationalStatus".into(), PsValue::String("OK".into())),
            ("SizeRemaining".into(), PsValue::Number(87_520_000_000)),
            ("Size".into(), PsValue::Number(107_374_182_400)),
        ]))]
    }

    fn event_values(&self, command: &str, args: &[String], now: DateTime<Utc>) -> Vec<PsValue> {
        let list_logs = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-ListLog"))
            .is_some()
            || (command.eq_ignore_ascii_case("get-eventlog")
                && args.iter().any(|arg| arg.eq_ignore_ascii_case("-List")));
        if list_logs {
            return [
                "Application",
                "Security",
                "Setup",
                "System",
                "Windows PowerShell",
            ]
            .into_iter()
            .map(|name| {
                PsValue::Object(BTreeMap::from([
                    ("LogName".into(), PsValue::String(name.into())),
                    ("IsEnabled".into(), PsValue::Bool(true)),
                    ("RecordCount".into(), PsValue::Number(1284)),
                    ("LogMode".into(), PsValue::String("Circular".into())),
                    ("MaximumSizeInBytes".into(), PsValue::Number(20_971_520)),
                ]))
            })
            .collect();
        }
        let selected_log = args
            .iter()
            .position(|arg| {
                arg.eq_ignore_ascii_case("-LogName") || arg.eq_ignore_ascii_case("-Log")
            })
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .unwrap_or("System");
        let max_events = args
            .iter()
            .position(|arg| {
                arg.eq_ignore_ascii_case("-MaxEvents") || arg.eq_ignore_ascii_case("-Newest")
            })
            .and_then(|index| args.get(index + 1))
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(20)
            .min(100);
        let log = if selected_log.eq_ignore_ascii_case("Application") {
            "Application"
        } else if selected_log.eq_ignore_ascii_case("Security") {
            "Security"
        } else if selected_log.eq_ignore_ascii_case("Windows PowerShell") {
            "Windows PowerShell"
        } else {
            "System"
        };
        let records: &[(&str, i64, &str, &str, &str)] = match log {
            "Application" => &[
                (
                    "Application",
                    1000,
                    "Error",
                    "Application Error",
                    "Faulting application name: svchost.exe",
                ),
                (
                    "Application",
                    1001,
                    "Information",
                    "Windows Error Reporting",
                    "Fault bucket recorded.",
                ),
            ],
            "Security" => &[
                (
                    "Security",
                    4624,
                    "Information",
                    "Microsoft Windows security auditing.",
                    "An account was successfully logged on.",
                ),
                (
                    "Security",
                    4672,
                    "Information",
                    "Microsoft Windows security auditing.",
                    "Special privileges assigned to new logon.",
                ),
            ],
            "Windows PowerShell" => &[
                (
                    "Windows PowerShell",
                    400,
                    "Information",
                    "PowerShell",
                    "Engine state is changed from None to Available.",
                ),
                (
                    "Windows PowerShell",
                    403,
                    "Information",
                    "PowerShell",
                    "Engine state is changed from Available to Stopped.",
                ),
            ],
            _ => &[
                (
                    "System",
                    7036,
                    "Information",
                    "Service Control Manager",
                    "The OpenSSH SSH Server service entered the running state.",
                ),
                (
                    "System",
                    6005,
                    "Information",
                    "EventLog",
                    "The Windows Event Log service was started.",
                ),
                (
                    "System",
                    7040,
                    "Information",
                    "Service Control Manager",
                    "The start type of a service was changed.",
                ),
            ],
        };
        records
            .iter()
            .take(max_events)
            .enumerate()
            .map(|(index, (log_name, id, level, provider, message))| {
                PsValue::Object(BTreeMap::from([
                    (
                        "TimeCreated".into(),
                        PsValue::String(
                            (now - chrono::Duration::minutes(index as i64 * 17 + 4))
                                .format("%m/%d/%Y %I:%M:%S %p")
                                .to_string(),
                        ),
                    ),
                    ("Id".into(), PsValue::Number(*id)),
                    ("LevelDisplayName".into(), PsValue::String((*level).into())),
                    ("ProviderName".into(), PsValue::String((*provider).into())),
                    ("LogName".into(), PsValue::String((*log_name).into())),
                    ("Message".into(), PsValue::String((*message).into())),
                ]))
            })
            .collect()
    }

    fn counter_values(&self, args: &[String], now: DateTime<Utc>) -> Vec<PsValue> {
        let counters = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Counter"))
            .map(|index| {
                args.iter()
                    .skip(index + 1)
                    .take_while(|arg| !arg.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty())
            .unwrap_or_else(|| vec![r"\Processor(_Total)\% Processor Time".into()]);
        counters
            .into_iter()
            .map(|path| {
                let value = if path.to_ascii_lowercase().contains("memory") {
                    23_104.0
                } else if path.to_ascii_lowercase().contains("disk") {
                    0.4
                } else {
                    4.7
                };
                PsValue::Object(BTreeMap::from([
                    ("Path".into(), PsValue::String(path)),
                    ("InstanceName".into(), PsValue::String("_Total".into())),
                    ("CookedValue".into(), PsValue::String(format!("{value:.3}"))),
                    ("RawValue".into(), PsValue::Number((value * 1000.0) as i64)),
                    (
                        "Timestamp".into(),
                        PsValue::String(now.format("%m/%d/%Y %I:%M:%S %p").to_string()),
                    ),
                    ("Status".into(), PsValue::Number(0)),
                ]))
            })
            .collect()
    }

    fn dns_client_values(&self, args: &[String]) -> Vec<PsValue> {
        let network = self.network_state();
        let family = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-AddressFamily"))
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .unwrap_or("IPv4");
        let servers = if family.eq_ignore_ascii_case("IPv6") {
            Vec::new()
        } else {
            network.dns.iter().cloned().map(PsValue::String).collect()
        };
        vec![PsValue::Object(BTreeMap::from([
            ("InterfaceAlias".into(), PsValue::String(network.adapter)),
            (
                "InterfaceIndex".into(),
                PsValue::Number(network.interface_index as i64),
            ),
            ("AddressFamily".into(), PsValue::String(family.into())),
            ("ServerAddresses".into(), PsValue::Array(servers)),
        ]))]
    }

    fn get_command(&self, args: &[String]) -> ShellOutput {
        let name = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|index| args.get(index + 1))
            .or_else(|| args.iter().find(|arg| !arg.starts_with('-')));
        let commands: &[(&str, &str, &str)] = &[
            ("Get-Command", "Cmdlet", "Get-Command"),
            ("Get-Alias", "Cmdlet", "Get-Alias"),
            ("Get-Date", "Cmdlet", "Get-Date"),
            ("Get-ExecutionPolicy", "Cmdlet", "Get-ExecutionPolicy"),
            ("Get-Location", "Cmdlet", "Get-Location"),
            ("Join-Path", "Cmdlet", "Join-Path"),
            ("Set-Location", "Cmdlet", "Set-Location"),
            ("Test-Path", "Cmdlet", "Test-Path"),
            ("Get-ChildItem", "Cmdlet", "Get-ChildItem"),
            ("Get-Content", "Cmdlet", "Get-Content"),
            ("Set-Content", "Cmdlet", "Set-Content"),
            ("Add-Content", "Cmdlet", "Add-Content"),
            ("New-Item", "Cmdlet", "New-Item"),
            ("Remove-Item", "Cmdlet", "Remove-Item"),
            ("Copy-Item", "Cmdlet", "Copy-Item"),
            ("Rename-Item", "Cmdlet", "Rename-Item"),
            ("Get-Item", "Cmdlet", "Get-Item"),
            ("Get-ItemProperty", "Cmdlet", "Get-ItemProperty"),
            ("Get-ItemPropertyValue", "Cmdlet", "Get-ItemPropertyValue"),
            ("Get-Process", "Cmdlet", "Get-Process"),
            ("Get-CimInstance", "Cmdlet", "Get-CimInstance"),
            ("Get-Volume", "Cmdlet", "Get-Volume"),
            ("Get-WinEvent", "Cmdlet", "Get-WinEvent"),
            ("Get-EventLog", "Cmdlet", "Get-EventLog"),
            ("Get-Counter", "Cmdlet", "Get-Counter"),
            (
                "Get-DnsClientServerAddress",
                "Cmdlet",
                "Get-DnsClientServerAddress",
            ),
            ("Get-Service", "Cmdlet", "Get-Service"),
            ("Get-Module", "Cmdlet", "Get-Module"),
            ("Start-Service", "Cmdlet", "Start-Service"),
            ("Stop-Service", "Cmdlet", "Stop-Service"),
            ("Get-Acl", "Cmdlet", "Get-Acl"),
            ("Select-Object", "Cmdlet", "Select-Object"),
            ("Where-Object", "Cmdlet", "Where-Object"),
            ("Sort-Object", "Cmdlet", "Sort-Object"),
            ("Measure-Object", "Cmdlet", "Measure-Object"),
            ("Out-String", "Cmdlet", "Out-String"),
            ("Select-String", "Cmdlet", "Select-String"),
            ("Get-LocalUser", "Cmdlet", "Get-LocalUser"),
            ("Get-LocalGroup", "Cmdlet", "Get-LocalGroup"),
            ("Get-LocalGroupMember", "Cmdlet", "Get-LocalGroupMember"),
            ("Write-Output", "Cmdlet", "Write-Output"),
            ("Write-Host", "Cmdlet", "Write-Host"),
            ("Get-NetIPConfiguration", "Cmdlet", "Get-NetIPConfiguration"),
            ("Get-NetIPAddress", "Cmdlet", "Get-NetIPAddress"),
            ("Get-NetAdapter", "Cmdlet", "Get-NetAdapter"),
            ("Get-NetTCPConnection", "Cmdlet", "Get-NetTCPConnection"),
            ("arp.exe", "Application", "C:\\Windows\\System32\\arp.exe"),
            (
                "route.exe",
                "Application",
                "C:\\Windows\\System32\\route.exe",
            ),
            ("cmd.exe", "Application", "C:\\Windows\\System32\\cmd.exe"),
            (
                "ssh.exe",
                "Application",
                "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
            ),
            (
                "sshd.exe",
                "Application",
                "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
            ),
            ("reg.exe", "Application", "C:\\Windows\\System32\\reg.exe"),
            (
                "msiexec.exe",
                "Application",
                "C:\\Windows\\System32\\msiexec.exe",
            ),
            (
                "whoami.exe",
                "Application",
                "C:\\Windows\\System32\\whoami.exe",
            ),
            (
                "hostname.exe",
                "Application",
                "C:\\Windows\\System32\\hostname.exe",
            ),
            (
                "ipconfig.exe",
                "Application",
                "C:\\Windows\\System32\\ipconfig.exe",
            ),
            (
                "tasklist.exe",
                "Application",
                "C:\\Windows\\System32\\tasklist.exe",
            ),
            (
                "netstat.exe",
                "Application",
                "C:\\Windows\\System32\\netstat.exe",
            ),
            ("net.exe", "Application", "C:\\Windows\\System32\\net.exe"),
            (
                "where.exe",
                "Application",
                "C:\\Windows\\System32\\where.exe",
            ),
            ("sc.exe", "Application", "C:\\Windows\\System32\\sc.exe"),
            (
                "powershell.exe",
                "Application",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ),
        ];
        let selected = commands.iter().filter(|(command, _, _)| {
            name.is_none_or(|filter| {
                command.eq_ignore_ascii_case(filter)
                    || command
                        .trim_end_matches(".exe")
                        .eq_ignore_ascii_case(filter.trim_end_matches(".exe"))
            })
        });
        let mut output = "CommandType Name                    Source\n----------- ----                    ------\n".to_owned();
        let mut matches = 0usize;
        for (command, kind, source) in selected {
            matches += 1;
            output.push_str(&format!("{kind:<11} {command:<23} {source}\n"));
        }
        if self.vulnerability_profiles.contains("win_guest_share")
            && name.is_none_or(|filter| filter.eq_ignore_ascii_case("Get-SmbShare"))
        {
            matches += 1;
            output.push_str("Cmdlet      Get-SmbShare            Get-SmbShare\n");
        }
        for (alias, definition) in POWERSHELL_ALIASES
            .iter()
            .filter(|(alias, _)| name.is_none_or(|filter| alias.eq_ignore_ascii_case(filter)))
        {
            matches += 1;
            output.push_str(&format!("{:<11} {:<23} {}\n", "Alias", alias, definition));
        }
        if matches == 0 {
            let missing = name.map(String::as_str).unwrap_or_default();
            return Self::error(format!(
                "Get-Command : The term '{}' is not recognized as the name of a cmdlet, function, script file, or operable program.\n",
                missing
            ));
        }
        Self::output(output)
    }

    fn get_alias(&self, args: &[String]) -> ShellOutput {
        let name = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|index| args.get(index + 1))
            .or_else(|| args.iter().find(|arg| !arg.starts_with('-')));
        let mut output = "CommandType Name Definition\n----------- ---- ----------\n".to_owned();
        for (alias, definition) in POWERSHELL_ALIASES
            .iter()
            .filter(|(alias, _)| name.is_none_or(|filter| alias.eq_ignore_ascii_case(filter)))
        {
            output.push_str(&format!("Alias       {alias:<4} {definition}\n"));
        }
        Self::output(output)
    }

    fn where_exe(&self, args: &[String]) -> ShellOutput {
        let Some(program) = args.iter().find(|arg| !arg.starts_with('-')) else {
            return Self::error("ERROR: Invalid syntax.\n");
        };
        let name = if program.to_ascii_lowercase().ends_with(".exe") {
            program.to_owned()
        } else {
            format!("{program}.exe")
        };
        let candidates = [
            format!("/C/Windows/System32/{name}"),
            format!("/C/Windows/System32/OpenSSH/{name}"),
        ];
        if let Some(path) = candidates.iter().find(|path| self.fs.exists(path)) {
            Self::output(format!("{}\n", Self::display_path(path)))
        } else {
            Self::error(format!(
                "INFO: Could not find files for the given pattern(s).\n"
            ))
        }
    }

    fn get_acl(&self, raw_path: &str) -> ShellOutput {
        let Some(path) = self.path(raw_path) else {
            return Self::error("Get-Acl: Specify a valid path.\n");
        };
        let Ok(node) = self.fs.node(&path) else {
            return Self::error(format!(
                "Get-Acl : Cannot find path '{}' because it does not exist.\n",
                raw_path
            ));
        };
        if self.is_read_restricted_path(&path) {
            return Self::error("Get-Acl : Access is denied.\n");
        }
        if self.is_protected_path(&path) && path.to_ascii_lowercase().contains("/config/") {
            return Self::error("Get-Acl : Access is denied.\n");
        }
        let owner = self.owner_principal(&node.owner);
        let owner_ace = format!("{owner} Allow  FullControl");
        let users_rights = if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
            && path.eq_ignore_ascii_case("/C/ProgramData/OpsBackup/backup.exe")
        {
            "Modify"
        } else if path.eq_ignore_ascii_case("/C/Users/Public")
            || path.to_ascii_lowercase().starts_with("/c/users/public/")
        {
            "Modify"
        } else {
            "ReadAndExecute"
        };
        let ace = format!(
            "{owner_ace}; NT AUTHORITY\\SYSTEM Allow  FullControl; {}\\Administrators Allow  FullControl; {}\\Users Allow  {}",
            self.hostname, self.hostname, users_rights
        );
        Self::output(format!(
            "\n\n    Directory: {}\n\nPath  : {}\nOwner : {}\nGroup : {}\nAccess: {}\nAudit :\nSddl  : O:{}G:SYD:(A;;FA;;;SY)(A;;FRFX;;;BU)\n",
            Self::display_path(
                path.rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("/C")
            ),
            Self::display_path(&path),
            owner,
            self.owner_principal(&node.group),
            ace,
            if node.is_dir() { "D" } else { "" }
        ))
    }

    fn icacls(&self, raw_path: &str, args: &[String]) -> ShellOutput {
        let Some(path) = self.path(raw_path) else {
            return Self::error("Invalid parameter.\n");
        };
        if !self.fs.exists(&path) {
            return Self::error(format!(
                "{}: The system cannot find the file specified.\n",
                raw_path
            ));
        }
        if self.is_read_restricted_path(&path) {
            return Self::error("Access is denied.\n");
        }
        if path
            .to_ascii_lowercase()
            .starts_with("/c/windows/system32/config/")
        {
            return Self::error("Access is denied.\n");
        }
        if args.iter().any(|arg| {
            arg.eq_ignore_ascii_case("/grant")
                || arg.eq_ignore_ascii_case("/deny")
                || arg.eq_ignore_ascii_case("/remove")
        }) {
            return Self::error("Access is denied.\n");
        }
        let node = match self.fs.node(&path) {
            Ok(node) => node,
            Err(_) => return Self::error("Access is denied.\n"),
        };
        let owner = self
            .fs
            .node(&path)
            .ok()
            .map(|node| self.owner_principal(&node.owner))
            .unwrap_or_else(|| "NT AUTHORITY\\SYSTEM".into());
        let marker = if node.is_dir() { "(OI)(CI)" } else { "" };
        let users_rights = if self
            .vulnerability_profiles
            .contains("win_writable_service_binary")
            && path.eq_ignore_ascii_case("/C/ProgramData/OpsBackup/backup.exe")
        {
            "M"
        } else if path.eq_ignore_ascii_case("/C/Users/Public")
            || path.to_ascii_lowercase().starts_with("/c/users/public/")
        {
            "M"
        } else {
            "RX"
        };
        Self::output(format!(
            "{} {}:(F) NT AUTHORITY\\SYSTEM:(F) BUILTIN\\Administrators:(F) BUILTIN\\Users:({})\nSuccessfully processed 1 files; Failed processing 0 files\n",
            Self::display_path(&path),
            format!("{owner}{marker}"),
            users_rights,
        ))
    }

    fn registry_item(&self, key: &str, display: &str) -> ShellOutput {
        if !self.registry_read_allowed(key) {
            return Self::error(format!(
                "Get-Item : Requested registry access is not allowed.\n"
            ));
        }
        if self.fs.exists(key) {
            Self::output(format!(
                "\nHive: {}\n\nName                           Property\n----                           --------\n{}\n",
                display
                    .rsplit_once('\\')
                    .map(|(parent, _)| parent)
                    .unwrap_or(display),
                display.rsplit(['\\', '/']).next().unwrap_or(display)
            ))
        } else if self.fs.exists(&format!("{key}.txt")) {
            self.registry(display, &[])
        } else {
            Self::error(format!(
                "Get-Item : Cannot find path '{}' because it does not exist.\n",
                display
            ))
        }
    }

    fn registry_value(&self, args: &[String]) -> ShellOutput {
        let path = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Path"))
            .and_then(|index| args.get(index + 1))
            .or_else(|| args.first())
            .map(String::as_str)
            .unwrap_or("");
        let name = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .unwrap_or("");
        let Some(key) = self.registry_path(path) else {
            return Self::error("Get-ItemPropertyValue: Specify an HKLM: or HKCU: path.\n");
        };
        if !self.registry_read_allowed(&key) {
            return Self::error(
                "Get-ItemPropertyValue : Requested registry access is not allowed.\n",
            );
        }
        let contents =
            String::from_utf8_lossy(self.fs.read(&format!("{key}.txt")).unwrap_or_default())
                .into_owned();
        match contents
            .lines()
            .filter_map(|line| line.split_once('='))
            .find(|(property, _)| property.eq_ignore_ascii_case(name))
        {
            Some((_, value)) => Self::output(format!("{value}\n")),
            None => Self::error(format!(
                "Get-ItemPropertyValue : Property {} does not exist at path {}.\n",
                name, path
            )),
        }
    }

    fn whoami(&self, args: &[String]) -> ShellOutput {
        let sid = format!(
            "S-1-5-21-3967214721-1742538666-854245398-{}",
            if self.user.eq_ignore_ascii_case("administrator") {
                500
            } else {
                1001
            }
        );
        let option = args.first().map(|arg| arg.to_ascii_lowercase());
        if option.as_deref().is_none_or(|arg| !arg.starts_with('/')) {
            return Self::output(format!("{}\\{}\n", self.hostname, self.user));
        }
        let user = format!("{}\\{}", self.hostname, self.user);
        match option.as_deref().unwrap_or("") {
            "/user" => Self::output(format!(
                "USER INFORMATION\n----------------\n\nUser Name             SID\n===================== ============================================\n{user} {sid}\n"
            )),
            "/groups" => {
                let mut groups = "GROUP INFORMATION\n-----------------\n\nGroup Name                                  Type             SID          Attributes\n=========================================== ================ ============ ==================================================\nEveryone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group\n".to_owned();
                if self.user.eq_ignore_ascii_case("administrator") {
                    groups.push_str("BUILTIN\\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group\n");
                }
                groups.push_str("BUILTIN\\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group\nBUILTIN\\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group\nNT AUTHORITY\\INTERACTIVE                  Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group\nNT AUTHORITY\\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group\nMandatory Label\\Medium Mandatory Level     Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group\n");
                Self::output(groups)
            }
            "/priv" => Self::output(
                "PRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                Description                              State\n============================= ======================================== ========\nSeChangeNotifyPrivilege       Bypass traverse checking                 Enabled\nSeShutdownPrivilege           Shut down the system                     Disabled\nSeUndockPrivilege             Remove computer from docking station     Disabled\nSeIncreaseWorkingSetPrivilege Increase a process working set           Disabled\nSeTimeZonePrivilege           Change the time zone                      Disabled\n",
            ),
            "/all" => {
                let mut all = self.whoami(&["/user".into()]).output;
                all.push('\n');
                all.push_str(&self.whoami(&["/groups".into()]).output);
                all.push('\n');
                all.push_str(&self.whoami(&["/priv".into()]).output);
                Self::output(all)
            }
            _ => Self::error("ERROR: Invalid parameter.\n"),
        }
    }

    fn local_users(&self, args: &[String]) -> ShellOutput {
        let users = serde_json::from_slice::<serde_json::Value>(
            self.fs.read("/State/users.json").unwrap_or_default(),
        )
        .unwrap_or_default();
        let entries = users.as_array().cloned().unwrap_or_default();
        let filter = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|i| args.get(i + 1));
        let rows = entries
            .into_iter()
            .filter(|entry| {
                filter.is_none_or(|name| {
                    entry["name"]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(name))
                })
            })
            .map(|entry| {
                format!(
                    "{:<20} {:<8} {}",
                    entry["name"].as_str().unwrap_or(""),
                    entry["enabled"].as_bool().unwrap_or(false),
                    entry["description"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>();
        Self::output(format!(
            "Name                 Enabled  Description\n----                 -------  -----------\n{}\n",
            rows.join("\n")
        ))
    }

    fn local_groups(&self, args: &[String]) -> ShellOutput {
        let groups = [
            "Administrators",
            "Backup Operators",
            "Distributed COM Users",
            "Event Log Readers",
            "Guests",
            "Network Configuration Operators",
            "Remote Desktop Users",
            "Users",
        ];
        let filter = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|i| args.get(i + 1));
        let selected = groups
            .iter()
            .filter(|group| filter.is_none_or(|name| group.eq_ignore_ascii_case(name)))
            .copied()
            .collect::<Vec<_>>();
        Self::output(format!("Name\n----\n{}\n", selected.join("\n")))
    }

    fn local_group_members(&self, args: &[String]) -> ShellOutput {
        let group = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Group"))
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
            .unwrap_or("Users");
        let member_name = format!("{}\\{}", self.hostname, self.user);
        let members: Vec<(&str, String)> = if group.eq_ignore_ascii_case("Administrators") {
            vec![(
                "Administrator",
                "S-1-5-21-3967214721-1742538666-854245398-500".into(),
            )]
        } else if group.eq_ignore_ascii_case("Remote Desktop Users") {
            vec![
                ("NT AUTHORITY\\INTERACTIVE", "S-1-5-4".into()),
                ("current-user", member_name),
            ]
        } else {
            vec![
                ("NT AUTHORITY\\Authenticated Users", "S-1-5-11".into()),
                ("current-user", member_name),
            ]
        };
        let mut output = format!(
            "ObjectClass Name                         PrincipalSource\n----------- ----                         ---------------\n"
        );
        for (name, value) in members {
            output.push_str(&format!(
                "User        {:<28} Local\n",
                if name == "current-user" {
                    value.as_str()
                } else {
                    name
                }
            ));
        }
        Self::output(output)
    }

    fn net_command(&self, args: &[String]) -> ShellOutput {
        let Some(subcommand) = args.first().map(|arg| arg.to_ascii_lowercase()) else {
            return Self::error(
                "The syntax of this command is:\nNET [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP | HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START | STATISTICS | STOP | TIME | USE | USER | VIEW ]\n",
            );
        };
        match subcommand.as_str() {
            "user" => {
                let users: Vec<serde_json::Value> =
                    serde_json::from_slice(self.fs.read("/State/users.json").unwrap_or_default())
                        .unwrap_or_default();
                if let Some(name) = args.get(1).filter(|value| !value.starts_with('/')) {
                    if !users.iter().any(|entry| {
                        entry["name"]
                            .as_str()
                            .is_some_and(|user| user.eq_ignore_ascii_case(name))
                    }) {
                        return Self::error("The user name could not be found.\n");
                    }
                    return Self::output(format!(
                        "User name                    {}\nFull Name                    {}\nComment                      Local user account\nAccount active               Yes\nAccount expires              Never\n\nThe command completed successfully.\n",
                        name, name
                    ));
                }
                let names = users
                    .iter()
                    .filter_map(|entry| entry["name"].as_str())
                    .collect::<Vec<_>>()
                    .join("    ");
                Self::output(format!(
                    "User accounts for \\\\{}\n\n-------------------------------------------------------------------------------\n{}\nThe command completed successfully.\n",
                    self.hostname, names
                ))
            }
            "share" if self.vulnerability_profiles.contains("win_guest_share") => Self::output(
                "Share name   Resource                        Remark\n-------------------------------------------------------------------------------\nPublicShare  C:\\ProgramData\\PublicShare      Operations documents\nThe command completed successfully.\n",
            ),
            "localgroup" => {
                if let Some(group) = args.get(1).filter(|value| !value.starts_with('/')) {
                    let members = if group.eq_ignore_ascii_case("administrators") {
                        "Administrator".to_owned()
                    } else if group.eq_ignore_ascii_case("remote desktop users") {
                        format!("{}\\{}", self.hostname, self.user)
                    } else {
                        format!(
                            "{}\\{}\nNT AUTHORITY\\Authenticated Users",
                            self.hostname, self.user
                        )
                    };
                    return Self::output(format!(
                        "Alias name     {group}\nComment        Members of this group have local access to system resources\n\nMembers\n-------------------------------------------------------------------------------\n{members}\nThe command completed successfully.\n"
                    ));
                }
                Self::output(format!(
                    "Aliases for \\\\{}\n\n-------------------------------------------------------------------------------\n*Administrators          *Backup Operators       *Distributed COM Users\n*Event Log Readers       *Guests                 *Remote Desktop Users\n*Users\nThe command completed successfully.\n",
                    self.hostname
                ))
            }
            _ => Self::error(format!("The syntax of this command is incorrect.\n")),
        }
    }

    fn ipconfig(&self, args: &[String]) -> ShellOutput {
        let network = self.network_state();
        let all = args.iter().any(|arg| arg.eq_ignore_ascii_case("/all"));
        let octets = network.ipv4.split('.').collect::<Vec<_>>();
        let mask = if network.prefix == 24 {
            "255.255.255.0"
        } else if network.prefix == 16 {
            "255.255.0.0"
        } else {
            "255.255.255.255"
        };
        let mut output = format!("Windows IP Configuration\n\n");
        if all {
            output.push_str(&format!("   Host Name . . . . . . . . . . . . : {}\n   Primary Dns Suffix  . . . . . . . : {}\n   Node Type . . . . . . . . . . . . : Hybrid\n   IP Routing Enabled. . . . . . . . : No\n   WINS Proxy Enabled. . . . . . . . : No\n\n", self.hostname, network.dns_suffix));
            output.push_str(&format!("{} adapter {}:\n\n   Connection-specific DNS Suffix  . : {}\n   Description . . . . . . . . . . . : Intel(R) Ethernet Connection\n   Physical Address. . . . . . . . . : {}\n   DHCP Enabled. . . . . . . . . . . : {}\n   Autoconfiguration Enabled . . . . : Yes\n   IPv4 Address. . . . . . . . . . . : {}\n   Subnet Mask . . . . . . . . . . . : {}\n   Lease Obtained. . . . . . . . . . : Tuesday, October 13, 2026 10:15:02 PM\n   Lease Expires . . . . . . . . . . : Wednesday, October 14, 2026 10:15:02 PM\n   Default Gateway . . . . . . . . . : {}\n   DHCP Server . . . . . . . . . . . : {}\n   DNS Servers . . . . . . . . . . . : {}\n", if network.dhcp { "Ethernet" } else { "Ethernet" }, network.adapter, network.dns_suffix, network.mac, if network.dhcp { "Yes" } else { "No" }, network.ipv4, mask, network.gateway, network.gateway, network.dns.join("\n                                       ")));
        } else {
            output.push_str(&format!("Ethernet adapter {}:\n\n   Connection-specific DNS Suffix  . : {}\n   IPv4 Address. . . . . . . . . . . : {}\n   Subnet Mask . . . . . . . . . . . : {}\n   Default Gateway . . . . . . . . . : {}\n", network.adapter, network.dns_suffix, network.ipv4, mask, network.gateway));
        }
        let _ = octets;
        Self::output(output)
    }

    fn network_command(&self, command: &str) -> ShellOutput {
        let network = self.network_state();
        let output = match command {
            "get-netadapter" => format!(
                "Name       InterfaceDescription                  ifIndex Status MacAddress       LinkSpeed\n----       --------------------                  ------- ------ ----------       ---------\n{} Intel(R) Ethernet Connection {}      Up     {} 1 Gbps\n",
                network.adapter, network.interface_index, network.mac
            ),
            "get-netipaddress" => format!(
                "IPAddress         InterfaceIndex InterfaceAlias AddressFamily PrefixLength Type\n---------         -------------- -------------- ------------- ------------ ----\n{} {:<14} {:<14} IPv4          {:<12} Unicast\n",
                network.ipv4, network.interface_index, network.adapter, network.prefix
            ),
            _ => format!(
                "InterfaceAlias       : {}\nInterfaceIndex       : {}\nNetAdapter            : {}\nIPv4Address           : {}\nIPv4DefaultGateway    : {}\nDNSServer             : {}\nNetProfile.Name       : {}\n",
                network.adapter,
                network.interface_index,
                network.adapter,
                network.ipv4,
                network.gateway,
                network.dns.join(", "),
                network.dns_suffix
            ),
        };
        Self::output(output)
    }

    fn route_print(&self) -> ShellOutput {
        let network = self.network_state();
        let octets = network
            .ipv4
            .split('.')
            .filter_map(|part| part.parse::<u8>().ok())
            .collect::<Vec<_>>();
        if octets.len() != 4 {
            return Self::error("The route table could not be read.\n");
        }
        let address = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
        let prefix = network.prefix.min(32);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let subnet = (address & mask).to_be_bytes();
        let mask_octets = mask.to_be_bytes();
        let subnet = format!("{}.{}.{}.{}", subnet[0], subnet[1], subnet[2], subnet[3]);
        let subnet_mask = format!(
            "{}.{}.{}.{}",
            mask_octets[0], mask_octets[1], mask_octets[2], mask_octets[3]
        );
        Self::output(format!(
            "===========================================================================\nInterface List\n {}...{} ......Intel(R) Ethernet Connection\n===========================================================================\n\nIPv4 Route Table\n===========================================================================\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      {:>12}    {:>12}     25\n{:>15}  {:>15}         On-link    {:>12}    281\n{:>15}  255.255.255.255         On-link    {:>12}    281\n===========================================================================\nPersistent Routes:\n  None\n",
            network.interface_index,
            network.mac,
            network.gateway,
            network.ipv4,
            subnet,
            subnet_mask,
            network.ipv4,
            network.ipv4,
            network.ipv4
        ))
    }

    fn arp_table(&self) -> ShellOutput {
        let network = self.network_state();
        let mut entries = vec![(network.gateway.clone(), "00-15-5d-2a-4b-01".to_owned())];
        for (index, address) in network.dns.iter().enumerate() {
            if address != &network.ipv4 && address != &network.gateway {
                entries.push((
                    address.clone(),
                    format!("00-15-5d-2a-4b-{:02x}", 10 + index),
                ));
            }
        }
        let mut output = format!(
            "\nInterface: {} --- 0x{:x}\n  Internet Address      Physical Address      Type\n",
            network.ipv4, network.interface_index
        );
        for (address, mac) in entries {
            output.push_str(&format!("  {address:<21} {mac:<21} dynamic\n"));
        }
        Self::output(output)
    }

    fn process_command(&self, command: &str, args: &[String]) -> ShellOutput {
        let mut processes = self
            .processes_state()
            .into_iter()
            .filter(|process| process.running)
            .collect::<Vec<_>>();
        if command != "tasklist" && command != "tasklist.exe" {
            if let Some(name) = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                .and_then(|index| args.get(index + 1))
                .or_else(|| args.iter().find(|arg| !arg.starts_with('-')))
            {
                processes.retain(|process| {
                    wildcard_match(&process.name, name)
                        || wildcard_match(
                            process.name.trim_end_matches(".exe"),
                            name.trim_end_matches(".exe"),
                        )
                });
            }
            if let Some(id) = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("-Id"))
                .and_then(|index| args.get(index + 1))
                .and_then(|value| value.parse::<u32>().ok())
            {
                processes.retain(|process| process.id == id);
            }
            if processes.is_empty()
                && (args.iter().any(|arg| arg.eq_ignore_ascii_case("-Name"))
                    || args.iter().any(|arg| arg.eq_ignore_ascii_case("-Id")))
            {
                if let Some(name) = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                    .and_then(|index| args.get(index + 1))
                {
                    return Self::error(format!(
                        "Get-Process : Cannot find a process with the name \"{}\". Verify the process name and call the cmdlet again.\n",
                        name.trim_matches(['\'', '"'])
                    ));
                }
                if let Some(id) = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Id"))
                    .and_then(|index| args.get(index + 1))
                {
                    return Self::error(format!(
                        "Get-Process : Cannot find a process with the process identifier {}.\n",
                        id.trim_matches(['\'', '"'])
                    ));
                }
            }
            let values = processes
                .iter()
                .map(|process| {
                    PsValue::Object(BTreeMap::from([
                        (
                            "Handles".into(),
                            PsValue::Number(process_handle_count(process) as i64),
                        ),
                        (
                            "NPM".into(),
                            PsValue::Number(process_nonpaged_pool_kb(process) as i64),
                        ),
                        (
                            "WS".into(),
                            PsValue::Number(process.working_set_kb as i64 * 1024),
                        ),
                        ("CPU".into(), PsValue::Number(process.cpu_seconds as i64)),
                        ("Id".into(), PsValue::Number(process.id as i64)),
                        ("Name".into(), PsValue::String(process.name.clone())),
                        ("ProcessName".into(), PsValue::String(process.name.clone())),
                        ("Path".into(), PsValue::String(process.path.clone())),
                    ]))
                })
                .collect::<Vec<_>>();
            return Self::output(format_values(&values));
        }
        let with_services = args.iter().any(|arg| arg.eq_ignore_ascii_case("/svc"));
        let mut output = if with_services {
            "\nImage Name                     PID Services\n========================= ======== ============================================\n".to_owned()
        } else {
            "\nImage Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\n".to_owned()
        };
        for process in &processes {
            if with_services {
                output.push_str(&format!(
                    "{:<27} {:>8} {}\n",
                    tasklist_image_name(process),
                    process.id,
                    if process.services.is_empty() {
                        "N/A".to_owned()
                    } else {
                        process.services.join(",")
                    }
                ));
            } else {
                output.push_str(&format!(
                    "{:<27} {:>8} {:<16} {:>6} {:>12}\n",
                    tasklist_image_name(process),
                    process.id,
                    tasklist_session(process).0,
                    tasklist_session(process).1,
                    format!("{} K", process.working_set_kb)
                ));
            }
        }
        output.push_str(&format!("\n{} processes\n", processes.len()));
        Self::output(output)
    }

    fn service(
        &mut self,
        command: &str,
        name: &str,
        args: &[String],
        now: DateTime<Utc>,
    ) -> ShellOutput {
        let mut services = self.services_state();
        if command == "get-service" || command == "gsv" {
            let filter = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                .and_then(|index| args.get(index + 1))
                .map(String::as_str)
                .unwrap_or(name);
            let values = services
                .into_iter()
                .filter(|service| {
                    filter.is_empty()
                        || wildcard_match(&service.name, filter)
                        || wildcard_match(&service.display_name, filter)
                })
                .map(service_value)
                .collect::<Vec<_>>();
            if !filter.is_empty() && values.is_empty() {
                return Self::error(format!(
                    "Get-Service : Cannot find any service with service name '{}'. Verify the service name and call the cmdlet again.\n",
                    filter
                ));
            }
            return Self::output(format_values(&values));
        }
        let filter = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("-Name"))
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .unwrap_or(name);
        if !self.user.eq_ignore_ascii_case("administrator") {
            return Self::error(format!(
                "{} : Service control failed to open service '{}'. Access is denied.\n",
                command, filter
            ));
        }
        let Some(service) = services
            .iter_mut()
            .find(|service| service.name.eq_ignore_ascii_case(filter))
        else {
            return Self::error(format!(
                "{} : Cannot find any service with service name '{}'.\n",
                command, filter
            ));
        };
        service.status = if command == "start-service" {
            "Running"
        } else {
            "Stopped"
        }
        .into();
        let changed = service.name.clone();
        if self
            .fs
            .write(
                "/State/services.json",
                serde_json::to_vec(&services).unwrap_or_default(),
                now,
            )
            .is_err()
        {
            return Self::error("Service state could not be updated.\n");
        }
        let services_snapshot = services.clone();
        let mut processes = self.processes_state();
        for process in &mut processes {
            if !process.services.is_empty() {
                process.running = process.services.iter().any(|service_name| {
                    services_snapshot.iter().any(|service| {
                        service.name.eq_ignore_ascii_case(service_name)
                            && service.status.eq_ignore_ascii_case("Running")
                    })
                });
            }
        }
        let _ = self.fs.write(
            "/State/processes.json",
            serde_json::to_vec(&processes).unwrap_or_default(),
            now,
        );
        if let Some(updated) = services_snapshot
            .iter()
            .find(|service| service.name == changed)
        {
            self.write_service_registry(updated, now);
        }
        let mut result = ShellOutput::default();
        result.fs_actions.push(FsAction {
            kind: FsActionKind::Modified,
            operation: "service_state",
            path: "/State/services.json".into(),
        });
        result
    }

    fn write_service_registry(&mut self, service: &WinService, now: DateTime<Utc>) {
        let key = format!(
            "/Registry/HKLM/SYSTEM/CurrentControlSet/Services/{}",
            service.name
        );
        let image_path = if service.name.eq_ignore_ascii_case("Sshd") {
            "C:\\Windows\\System32\\OpenSSH\\sshd.exe"
        } else {
            "C:\\Windows\\System32\\svchost.exe -k netsvcs"
        };
        let props = format!(
            "DisplayName={}\nStart={}\nType=0x10\nImagePath={}\nObjectName=LocalSystem\nState={}\nProcessId={}\n",
            service.display_name,
            if service.start_type.eq_ignore_ascii_case("Automatic") {
                2
            } else {
                3
            },
            image_path,
            service.status,
            service.process_id
        );
        let _ = self
            .fs
            .write(&format!("{key}.txt"), props.into_bytes(), now);
    }

    fn sc_command(&mut self, args: &[String], _now: DateTime<Utc>) -> ShellOutput {
        let Some(action) = args.first().map(|value| value.to_ascii_lowercase()) else {
            return Self::error(
                "DESCRIPTION:\n        SC is a command line program used for communicating with the Service Control Manager.\nUSAGE:\n        sc.exe query [service name]\n",
            );
        };
        if !matches!(action.as_str(), "query" | "qc") {
            return Self::error("[SC] OpenService FAILED 87:\nThe parameter is incorrect.\n");
        }
        let filter = args
            .get(1)
            .filter(|value| !value.starts_with('-'))
            .map(String::as_str);
        let services = self.services_state();
        let Some(service) = services
            .iter()
            .find(|service| filter.is_none_or(|name| service.name.eq_ignore_ascii_case(name)))
        else {
            return Self::error(format!(
                "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\nThe specified service does not exist as an installed service.\n"
            ));
        };
        if action == "qc" {
            let registry_path = format!(
                "/Registry/HKLM/SYSTEM/CurrentControlSet/Services/{}.txt",
                service.name
            );
            let properties =
                String::from_utf8_lossy(self.fs.read(&registry_path).unwrap_or_default());
            let binary_path = properties
                .lines()
                .find_map(|line| line.strip_prefix("ImagePath="))
                .unwrap_or("C:\\Windows\\System32\\svchost.exe -k netsvcs");
            return Self::output(format!(
                "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: {}\n        BINARY_PATH_NAME   : {}\n        SERVICE_START_NAME : LocalSystem\n",
                service.name, binary_path
            ));
        }
        Self::output(format!(
            "\nSERVICE_NAME: {}\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : {}  {}\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n",
            service.name,
            if service.status.eq_ignore_ascii_case("Running") {
                4
            } else {
                1
            },
            service.status.to_ascii_uppercase()
        ))
    }

    fn tcp_connections(&self, args: &[String]) -> ShellOutput {
        let services = self.services_state();
        let processes = self.processes_state();
        let mut rows = vec![(
            "TCP".to_owned(),
            "0.0.0.0:22".to_owned(),
            "0.0.0.0:0".to_owned(),
            "LISTENING".to_owned(),
            3712u32,
        )];
        for (service, local, pid) in [
            ("WinRM", "0.0.0.0:5985", 1088),
            ("LanmanServer", "0.0.0.0:445", 1088),
            ("TermService", "0.0.0.0:3389", 804),
        ] {
            if services.iter().any(|entry| {
                entry.name.eq_ignore_ascii_case(service)
                    && entry.status.eq_ignore_ascii_case("Running")
            }) {
                rows.push((
                    "TCP".into(),
                    local.into(),
                    "0.0.0.0:0".into(),
                    "LISTENING".into(),
                    pid,
                ));
            }
        }
        for process in processes.iter().filter(|process| process.running) {
            if let Some(bait) = self
                .processes
                .iter()
                .find(|bait| bait.name.eq_ignore_ascii_case(&process.name))
            {
                if let Some(port) = bait.listen_port {
                    rows.push((
                        "TCP".into(),
                        format!("127.0.0.1:{port}"),
                        "0.0.0.0:0".into(),
                        "LISTENING".into(),
                        process.id,
                    ));
                }
            }
        }
        if args.iter().any(|arg| arg.eq_ignore_ascii_case("-ano"))
            || args.iter().any(|arg| arg.eq_ignore_ascii_case("-a"))
        {
            if services
                .iter()
                .any(|service| service.name == "W32Time" && service.status == "Running")
            {
                rows.push((
                    "UDP".into(),
                    "0.0.0.0:123".into(),
                    "*: *".into(),
                    "".into(),
                    1088,
                ));
            }
        }
        let mut output = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n".to_owned();
        for (protocol, local, remote, state, pid) in rows {
            output.push_str(&format!(
                "  {protocol:<5} {local:<22} {remote:<22} {state:<15} {pid}\n"
            ));
        }
        Self::output(output)
    }

    fn registry_path(&self, raw: &str) -> Option<String> {
        let value = raw.replace('\\', "/");
        let (hive, rest) = if value
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HKLM:/"))
        {
            ("HKLM", &value[6..])
        } else if value
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HKCU:/"))
        {
            ("HKCU", &value[6..])
        } else {
            return None;
        };
        let path = VirtualFileSystem::normalize("/", &format!("/Registry/{hive}/{rest}")).ok()?;
        if !path.starts_with(&format!("/Registry/{hive}/")) {
            return None;
        }
        let mut canonical = String::new();
        for component in path.split('/').filter(|part| !part.is_empty()) {
            let parent = if canonical.is_empty() {
                "/"
            } else {
                &canonical
            };
            let matched = self.fs.list(parent).ok().and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(component))
                    .map(|(name, _)| name)
            });
            canonical.push('/');
            canonical.push_str(matched.as_deref().unwrap_or(component));
        }
        Some(canonical)
    }

    fn registry_list(&self, path: &str) -> ShellOutput {
        if !self.registry_read_allowed(path) {
            return Self::error("Get-ChildItem : Requested registry access is not allowed.\n");
        }
        match self.fs.list(path) {
            Ok(entries) => {
                let names = entries
                    .into_iter()
                    .filter_map(|(name, _)| {
                        if let Some(base) = name.strip_suffix(".txt") {
                            let key = format!("{path}/{base}");
                            if self.fs.is_dir(&key) {
                                None
                            } else {
                                Some(base.to_owned())
                            }
                        } else {
                            Some(name)
                        }
                    })
                    .collect::<Vec<_>>();
                Self::output(format!("{}\n", names.join("\n")))
            }
            Err(_) => Self::error(format!(
                "Get-ChildItem: Cannot find registry path '{}'.\n",
                path
            )),
        }
    }

    fn set_registry(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        let value_for = |flag: &str| {
            args.iter()
                .position(|arg| arg.eq_ignore_ascii_case(flag))
                .and_then(|index| args.get(index + 1))
                .map(String::as_str)
        };
        let path = value_for("-Path")
            .or_else(|| args.first().map(String::as_str))
            .unwrap_or("");
        let Some(key) = self.registry_path(path) else {
            return Self::error("Set-ItemProperty: Specify an HKLM: or HKCU: path.\n");
        };
        if key.to_ascii_lowercase().starts_with("/registry/hklm/") || Self::protected_registry(&key)
        {
            return Self::error("Set-ItemProperty : Requested registry access is not allowed.\n");
        }
        let target = format!("{key}.txt");
        if !self.fs.exists(&target) {
            return Self::error(format!("Set-ItemProperty: Cannot find path '{}'.\n", path));
        }
        let Some(name) = value_for("-Name") else {
            return Self::error("Set-ItemProperty: Missing -Name.\n");
        };
        let Some(value) = value_for("-Value") else {
            return Self::error("Set-ItemProperty: Missing -Value.\n");
        };
        if name.contains(['\n', '=']) || value.contains('\n') {
            return Self::error("Set-ItemProperty: Invalid property value.\n");
        }
        let previous =
            String::from_utf8_lossy(self.fs.read(&target).unwrap_or_default()).into_owned();
        let mut properties = previous
            .lines()
            .filter(|line| {
                line.split_once('=')
                    .is_none_or(|(key, _)| !key.eq_ignore_ascii_case(name))
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        properties.push(format!("{name}={value}"));
        match self.fs.write(
            &target,
            format!("{}\n", properties.join("\n")).into_bytes(),
            now,
        ) {
            Ok(()) => {
                let mut result = ShellOutput::default();
                result.fs_actions.push(FsAction {
                    kind: FsActionKind::Modified,
                    operation: "registry_write",
                    path: target,
                });
                result
            }
            Err(error) => Self::error(format!("Set-ItemProperty: {error}\n")),
        }
    }

    fn registry(&self, path: &str, args: &[String]) -> ShellOutput {
        let Some(key) = self.registry_path(path) else {
            return Self::error("Get-ItemProperty: Specify an HKLM: or HKCU: path.\n");
        };
        if !self.registry_read_allowed(&key) {
            return Self::error("Get-ItemProperty : Requested registry access is not allowed.\n");
        }
        let target = format!("{key}.txt");
        match self.fs.read(&target) {
            Ok(bytes) => {
                let selected_name = args
                    .iter()
                    .position(|arg| arg.eq_ignore_ascii_case("-Name"))
                    .and_then(|index| args.get(index + 1));
                let values = String::from_utf8_lossy(bytes)
                    .lines()
                    .filter_map(|line| line.split_once('='))
                    .filter(|(name, _)| {
                        selected_name.is_none_or(|selected| name.eq_ignore_ascii_case(selected))
                    })
                    .map(|(name, value)| format!("{name} : {value}"))
                    .collect::<Vec<_>>();
                let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
                let parent = path
                    .rsplit_once(['\\', '/'])
                    .map(|(parent, _)| parent)
                    .unwrap_or(path);
                let output = format!("\n\n{} : {}\n{}\n", parent, name, values.join("\n"));
                let mut result = Self::output(output);
                result.fs_actions.push(FsAction {
                    kind: FsActionKind::Accessed,
                    operation: "registry_read",
                    path: target,
                });
                result
            }
            Err(_) => Self::error(format!("Get-ItemProperty: Cannot find path '{}'.\n", path)),
        }
    }
}
