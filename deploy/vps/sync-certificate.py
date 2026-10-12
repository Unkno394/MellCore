#!/usr/bin/env python3
"""Copy the domain certificate managed by Hysteria and reload nginx after renewal."""
import hashlib
import os
from pathlib import Path
import subprocess

DOMAIN = "yourpasswordforemail.ru"
DEST = Path("/etc/honeyforge/tls")


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def main():
    candidates = []
    for cert in Path("/var/lib/hysteria/acme").rglob("*.crt"):
        key = cert.with_suffix(".key")
        if not key.is_file():
            continue
        result = command("openssl", "x509", "-in", str(cert), "-noout", "-checkhost", DOMAIN)
        if b"does match certificate" not in result:
            continue
        command("openssl", "x509", "-in", str(cert), "-noout", "-checkend", "0")
        public_cert = command("openssl", "x509", "-in", str(cert), "-pubkey", "-noout")
        public_key = command("openssl", "pkey", "-in", str(key), "-pubout")
        if public_cert == public_key:
            candidates.append((cert.stat().st_mtime, cert, key))
    if not candidates:
        raise SystemExit("Не найден действующий сертификат Hysteria для " + DOMAIN)
    _, cert, key = max(candidates)
    DEST.mkdir(mode=0o700, parents=True, exist_ok=True)
    changed = False
    for source, name in [(cert, "fullchain.pem"), (key, "privkey.pem")]:
        target = DEST / name
        content = source.read_bytes()
        if target.exists() and hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(content).digest():
            continue
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(content)
        temporary.chmod(0o600)
        os.replace(temporary, target)
        changed = True
    if changed:
        subprocess.run(["nginx", "-t"], check=True)
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
    print("Сертификат nginx синхронизирован с Hysteria.")


if __name__ == "__main__":
    main()
