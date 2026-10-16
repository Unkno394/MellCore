use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
pub(super) struct Settings {
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub shell: Option<String>,
    pub password_hash: Option<String>,
    pub ssh_host_key: Option<String>,
    pub vulnerabilities: Vec<String>,
    pub baits: Vec<Bait>,
}

#[derive(Serialize)]
pub(super) struct Bait {
    pub path: String,
    pub content: String,
}

const QGA_CALL_TIMEOUT_SECONDS: &str = "10s";
const GUEST_CUSTOMIZATION_TIMEOUT: Duration = Duration::from_secs(480);

pub(super) fn apply(instance_id: &str, settings: &Settings) -> anyhow::Result<()> {
    let domain = format!("hf-high-{instance_id}");
    let deadline = Instant::now() + Duration::from_secs(180);
    let started = Instant::now();
    let mut next_report = started + Duration::from_secs(15);
    eprintln!("High: VM started; waiting for QEMU Guest Agent (up to 180 seconds)");
    loop {
        if qga(&domain, &json!({"execute": "guest-ping"})).is_ok() {
            break;
        }
        let now = Instant::now();
        anyhow::ensure!(
            now < deadline,
            "High guest did not expose QEMU Guest Agent within 180 seconds; verify that qemu-guest-agent is installed and enabled in the image, then inspect `virsh -c qemu:///system domstate {domain}` and `virsh -c qemu:///system domiflist {domain}`"
        );
        if now >= next_report {
            eprintln!(
                "High: still waiting for QEMU Guest Agent ({}/180 seconds); guest customization has not started",
                now.duration_since(started).as_secs()
            );
            next_report = now + Duration::from_secs(15);
        }
        thread::sleep(Duration::from_secs(3));
    }

    eprintln!("High: QEMU Guest Agent connected; applying guest settings");
    let payload = STANDARD.encode(serde_json::to_vec(settings)?);
    let command = json!({
        "execute": "guest-exec",
        "arguments": {
            "path": "/usr/bin/python3",
            "arg": ["-c", include_str!("guest-apply.py")],
            "input-data": payload,
            "capture-output": true,
        }
    });
    let response = qga(&domain, &command)?;
    let pid = response
        .pointer("/return/pid")
        .and_then(Value::as_i64)
        .context("QEMU Guest Agent did not return a process ID")?;
    let deadline = Instant::now() + GUEST_CUSTOMIZATION_TIMEOUT;
    loop {
        let status = qga(
            &domain,
            &json!({
                "execute": "guest-exec-status",
                "arguments": {"pid": pid},
            }),
        )?;
        let result = &status["return"];
        if result["exited"].as_bool() == Some(true) {
            if result["exitcode"].as_i64() == Some(0) {
                return Ok(());
            }
            let detail = result["err-data"]
                .as_str()
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .or_else(|| {
                    result["out-data"]
                        .as_str()
                        .and_then(|encoded| STANDARD.decode(encoded).ok())
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                })
                .unwrap_or_else(|| "guest customization failed without diagnostic".into());
            bail!(
                "High guest customization exited with {:?}: {}",
                result["exitcode"],
                detail.trim()
            );
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "High guest customization process {pid} did not finish within {} seconds; inspect its QEMU Guest Agent status with `virsh -c qemu:///system qemu-agent-command {domain} '{{\"execute\":\"guest-exec-status\",\"arguments\":{{\"pid\":{pid}}}}}'`",
            GUEST_CUSTOMIZATION_TIMEOUT.as_secs()
        );
        thread::sleep(Duration::from_secs(2));
    }
}

pub(super) fn read_ssh_journal(instance_id: &str, lines: u16) -> anyhow::Result<String> {
    let domain = format!("hf-high-{instance_id}");
    let response = qga(
        &domain,
        &json!({
            "execute": "guest-exec",
            "arguments": {
                "path": "/usr/bin/journalctl",
                "arg": ["--no-pager", "--output=short-iso", "-n", lines.to_string(),
                        "-u", "ssh.service", "-u", "sshd.service"],
                "capture-output": true,
            }
        }),
    )?;
    let pid = response
        .pointer("/return/pid")
        .and_then(Value::as_i64)
        .context("QEMU Guest Agent did not return a journal process ID")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = qga(
            &domain,
            &json!({
                "execute": "guest-exec-status",
                "arguments": {"pid": pid},
            }),
        )?;
        let result = &status["return"];
        if result["exited"].as_bool() == Some(true) {
            let decode = |key: &str| -> anyhow::Result<String> {
                let bytes = result[key]
                    .as_str()
                    .map(|value| STANDARD.decode(value))
                    .transpose()?
                    .unwrap_or_default();
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            };
            anyhow::ensure!(
                result["exitcode"].as_i64() == Some(0),
                "could not read High SSH journal: {}",
                decode("err-data")?.trim()
            );
            anyhow::ensure!(
                result["out-truncated"].as_bool() != Some(true),
                "High SSH journal output was truncated; retry with fewer --lines"
            );
            return decode("out-data");
        }
        anyhow::ensure!(Instant::now() < deadline, "High SSH journal read timed out");
        thread::sleep(Duration::from_millis(500));
    }
}

pub(super) fn diagnose_ssh(instance_id: &str) -> anyhow::Result<String> {
    let domain = format!("hf-high-{instance_id}");
    let mut report = String::new();
    for args in [
        vec!["list-jobs", "--no-pager"],
        vec!["status", "sshd", "--no-pager"],
        vec!["status", "systemd-time-wait-sync", "--no-pager"],
    ] {
        let response = qga(
            &domain,
            &json!({"execute": "guest-exec", "arguments": {
                "path": "/usr/bin/systemctl", "arg": args, "capture-output": true
            }}),
        )?;
        let pid = response
            .pointer("/return/pid")
            .and_then(Value::as_i64)
            .context("QEMU Guest Agent did not return a diagnostic process ID")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = qga(
                &domain,
                &json!({"execute": "guest-exec-status", "arguments": {"pid": pid}}),
            )?;
            if status["return"]["exited"].as_bool() == Some(true) {
                let output = status["return"]["out-data"].as_str().unwrap_or("");
                let decoded = STANDARD.decode(output)?;
                report.push_str(&format!(
                    "\n$ systemctl {}\n{}",
                    args.join(" "),
                    String::from_utf8_lossy(&decoded)
                        .chars()
                        .take(2000)
                        .collect::<String>()
                ));
                break;
            }
            anyhow::ensure!(Instant::now() < deadline, "guest SSH diagnostic timed out");
            thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(report)
}

fn qga(domain: &str, request: &Value) -> anyhow::Result<Value> {
    let output = Command::new("timeout")
        .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            QGA_CALL_TIMEOUT_SECONDS,
            "virsh",
            "qemu-agent-command",
            domain,
        ])
        .arg(request.to_string())
        .output()
        .with_context(|| {
            format!("cannot run time-limited QEMU Guest Agent command for {domain}")
        })?;
    anyhow::ensure!(
        output.status.success(),
        "QEMU Guest Agent command failed or exceeded {QGA_CALL_TIMEOUT_SECONDS}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let response: Value = serde_json::from_slice(&output.stdout)?;
    anyhow::ensure!(
        response.get("error").is_none(),
        "QEMU Guest Agent returned an error"
    );
    Ok(response)
}
