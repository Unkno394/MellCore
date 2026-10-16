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
    pub vulnerabilities: Vec<String>,
    pub baits: Vec<Bait>,
}

#[derive(Serialize)]
pub(super) struct Bait {
    pub path: String,
    pub content: String,
}

pub(super) fn apply(instance_id: &str, settings: &Settings) -> anyhow::Result<()> {
    let domain = format!("hf-high-{instance_id}");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if qga(&domain, &json!({"execute": "guest-ping"})).is_ok() {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "High guest did not expose QEMU Guest Agent within 180 seconds; verify that qemu-guest-agent is installed and enabled in the image, then inspect `virsh -c qemu:///system domstate {domain}` and `virsh -c qemu:///system domiflist {domain}`"
        );
        thread::sleep(Duration::from_secs(3));
    }

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
    let deadline = Instant::now() + Duration::from_secs(120);
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
            "High guest customization process {pid} did not finish within 120 seconds; inspect its QEMU Guest Agent status with `virsh -c qemu:///system qemu-agent-command {domain} '{{\"execute\":\"guest-exec-status\",\"arguments\":{{\"pid\":{pid}}}}}'`"
        );
        thread::sleep(Duration::from_secs(2));
    }
}

fn qga(domain: &str, request: &Value) -> anyhow::Result<Value> {
    let output = Command::new("virsh")
        .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
        .args(["qemu-agent-command", domain, &request.to_string()])
        .output()
        .with_context(|| format!("cannot call QEMU Guest Agent for {domain}"))?;
    anyhow::ensure!(
        output.status.success(),
        "QEMU Guest Agent did not accept the request"
    );
    let response: Value = serde_json::from_slice(&output.stdout)?;
    anyhow::ensure!(
        response.get("error").is_none(),
        "QEMU Guest Agent returned an error"
    );
    Ok(response)
}
