use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hf_core::{BaitImplementation, BaitKind, HighGuestConfig};
use serde_json::{Value, json};

use crate::sandbox::HighVm;

fn qga(domain: &str, request: &Value) -> anyhow::Result<Value> {
    let output = Command::new("virsh")
        .env("LC_ALL", "C")
        .args(["-c", "qemu:///system", "qemu-agent-command", domain, &request.to_string()])
        .output()
        .context("could not call QEMU Guest Agent")?;
    ensure!(
        output.status.success(),
        "QEMU Guest Agent command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let reply: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        reply.get("error").is_none(),
        "QEMU Guest Agent rejected command: {}",
        reply
    );
    Ok(reply)
}

fn password_hash(password: &str) -> anyhow::Result<String> {
    let mut child = Command::new("openssl")
        .args(["passwd", "-6", "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("openssl is required for High SSH credentials")?;
    child
        .stdin
        .take()
        .context("openssl stdin unavailable")?
        .write_all(password.as_bytes())?;
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "could not hash High SSH password");
    let hash = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(
        hash.starts_with("$6$"),
        "openssl returned an unexpected password hash"
    );
    Ok(hash)
}

fn validate(guest: &HighGuestConfig) -> anyhow::Result<()> {
    ensure!(
        guest.ssh_credentials.len() <= 1,
        "High VM supports one SSH credential"
    );
    for profile in &guest.vulnerability_profiles {
        ensure!(
            matches!(
                profile.as_str(),
                "ssh_weak_credentials" | "ssh_root_login_enabled" | "sudo_nopasswd"
            ),
            "unsupported High vulnerability profile: {profile}"
        );
    }
    hf_core::validate_bait_files(&guest.baits).map_err(anyhow::Error::msg)?;
    for bait in &guest.baits {
        let path = bait.path.as_deref().context("High bait has no path")?;
        let allowed = path.starts_with("/srv/")
            || path.starts_with("/opt/")
            || path.starts_with("/var/backups/")
            || guest
                .username
                .as_ref()
                .is_some_and(|name| path.starts_with(&format!("/home/{name}/")));
        ensure!(
            bait.kind != BaitKind::Account
                && bait
                    .implementation
                    .is_none_or(|kind| kind == BaitImplementation::VirtualFile)
                && allowed,
            "unsupported High bait path or kind: {path}"
        );
    }
    Ok(())
}

pub fn apply(vm: &HighVm) -> anyhow::Result<()> {
    let guest = &vm.guest;
    if guest.hostname.is_none()
        && guest.username.is_none()
        && guest.ssh_credentials.is_empty()
        && guest.vulnerability_profiles.is_empty()
        && guest.baits.is_empty()
    {
        return Ok(());
    }
    validate(guest)?;
    let domain = format!("hf-high-{}", vm.instance_id);
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if qga(&domain, &json!({"execute": "guest-ping"})).is_ok() {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "High guest did not expose QEMU Guest Agent in 180 seconds"
        );
        thread::sleep(Duration::from_secs(3));
    }
    let hash = guest
        .ssh_credentials
        .first()
        .map(|credential| password_hash(&credential.password))
        .transpose()?;
    let baits: Vec<_> = guest
        .baits
        .iter()
        .map(|bait| json!({"path": bait.path, "content": bait.content}))
        .collect();
    let payload = json!({
        "hostname": guest.hostname,
        "username": guest.username,
        "shell": "/bin/bash",
        "password_hash": hash,
        "vulnerabilities": guest.vulnerability_profiles,
        "baits": baits,
    });
    let command = json!({
        "execute": "guest-exec",
        "arguments": {
            "path": "/usr/bin/python3",
            "arg": ["-c", include_str!("high_guest_apply.py")],
            "input-data": STANDARD.encode(serde_json::to_vec(&payload)?),
            "capture-output": true,
        }
    });
    let response = qga(&domain, &command)?;
    let pid = response
        .pointer("/return/pid")
        .and_then(Value::as_u64)
        .context("QEMU Guest Agent did not return a customization process ID")?;
    let deadline = Instant::now() + Duration::from_secs(480);
    loop {
        let status = qga(
            &domain,
            &json!({"execute": "guest-exec-status", "arguments": {"pid": pid}}),
        )?;
        let result = &status["return"];
        if result["exited"].as_bool() == Some(true) {
            if result["exitcode"].as_i64() == Some(0) {
                return Ok(());
            }
            let detail = result["err-data"]
                .as_str()
                .or_else(|| result["out-data"].as_str())
                .and_then(|value| STANDARD.decode(value).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_else(|| "no guest diagnostic".into());
            bail!(
                "High guest customization failed (exit {}): {}",
                result["exitcode"],
                detail.trim()
            );
        }
        ensure!(
            Instant::now() < deadline,
            "High guest customization timed out after 480 seconds"
        );
        thread::sleep(Duration::from_secs(2));
    }
}
