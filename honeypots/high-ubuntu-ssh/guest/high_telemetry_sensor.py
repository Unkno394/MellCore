#!/usr/bin/python3
"""Forward guest journal and audit records to the host over a private virtio-serial port.

Records stay in the durable outbox until the host acknowledges persistence. The host has no
command channel into the guest sensor.
"""

import json
import logging
import os
import re
import select
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path

from high_telemetry_audit import AuditAssembler

VERSION = 1
CHANNEL = Path("/dev/virtio-ports/org.honeyforge.telemetry.0")
STATE_DIR = Path("/var/lib/honeyforge-high-telemetry")
OUTBOX = STATE_DIR / "outbox.jsonl"
KNOWN = STATE_DIR / "known-events.jsonl"
SEQUENCE = STATE_DIR / "next-sequence"
CURSOR = STATE_DIR / "journal.cursor"
BOOT_MARKER = STATE_DIR / "boot-id"
DIAGNOSTICS = STATE_DIR / "diagnostic-counters.json"
AUDIT_CURSOR = STATE_DIR / "audit.cursor"
AUDIT_LOG = Path("/var/log/audit/audit.log")
MAX_FRAME_BYTES = 16 * 1024
MAX_LOG_MESSAGE_BYTES = 12 * 1024
MAX_LOG_PAYLOAD_BYTES = MAX_FRAME_BYTES - 2048
MAX_OUTBOX_BYTES = 16 * 1024 * 1024
MAX_OUTBOX_EVENTS = 10_000
MAX_KNOWN_EVENTS = 20_000
ACK_TIMEOUT_SECONDS = 10

AUTH_FAILURE = re.compile(
    r"Failed (?P<method>\S+) for (?:(?:invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
AUTH_SUCCESS = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
SESSION_OPEN = re.compile(r"session opened for user (?P<user>[^\s(]+)")
SESSION_CLOSE = re.compile(r"session closed for user (?P<user>[^\s(]+)")
NAMESPACE = uuid.UUID("c93b2f74-ce26-4dc9-a594-50902672f0db")

logging.basicConfig(level=logging.INFO, format="high-telemetry: %(levelname)s %(message)s")
LOG = logging.getLogger("high-telemetry")


def _fsync_directory(path):
    directory_fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _atomic_text(path, text):
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _load_json_lines(path, maximum_bytes=None):
    if not path.exists():
        return []
    if maximum_bytes is not None and path.stat().st_size > maximum_bytes:
        raise RuntimeError(f"{path} exceeds its persisted byte limit")
    records = []
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            if len(line) > MAX_FRAME_BYTES + 1:
                raise RuntimeError(f"{path}:{number} exceeds the frame limit")
            records.append(json.loads(line))
    return records


class DurableGuestOutbox:
    def __init__(self, state_dir=STATE_DIR):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.outbox_path = self.state_dir / OUTBOX.name
        self.known_path = self.state_dir / KNOWN.name
        self.sequence_path = self.state_dir / SEQUENCE.name
        self.diagnostics_path = self.state_dir / DIAGNOSTICS.name
        self.lock = threading.RLock()
        self.outbox = _load_json_lines(self.outbox_path, MAX_OUTBOX_BYTES)
        known = _load_json_lines(self.known_path)
        if len(known) > MAX_KNOWN_EVENTS:
            raise RuntimeError("persisted known-event index exceeds configured event limit")
        self.known = {record["guest_event_id"]: record for record in known}
        if len(self.outbox) > MAX_OUTBOX_EVENTS:
            raise RuntimeError("persisted guest outbox exceeds configured event limit")
        self.next_sequence = self._read_sequence()
        try:
            self.diagnostics = json.loads(self.diagnostics_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.diagnostics = {}

    def _read_sequence(self):
        try:
            value = int(self.sequence_path.read_text(encoding="ascii").strip())
        except FileNotFoundError:
            return 1
        if value < 1:
            raise RuntimeError("invalid persisted guest sequence")
        return value

    def _write_outbox(self):
        body = "".join(_encode(record).decode("utf-8") + "\n" for record in self.outbox)
        _atomic_text(self.outbox_path, body)
        os.chmod(self.outbox_path, 0o600)

    def _write_known(self):
        records = list(self.known.values())[-MAX_KNOWN_EVENTS:]
        self.known = {record["guest_event_id"]: record for record in records}
        body = "".join(_encode(record).decode("utf-8") + "\n" for record in records)
        _atomic_text(self.known_path, body)
        os.chmod(self.known_path, 0o600)

    def enqueue(self, stable_id, event_type, occurred_at_ms, session_id=None,
                source_ip=None, source_port=None, destination_ip=None,
                destination_port=None, transport=None, event_origin="sensor",
                event_confidence="observed", payload=None):
        stable_id = str(stable_id)
        with self.lock:
            existing = self.known.get(stable_id)
            if existing is not None:
                if not any(item["guest_event_id"] == stable_id for item in self.outbox):
                    encoded = _encode(existing)
                    if not self._has_capacity(len(encoded) + 1):
                        return False
                    self.outbox.append(existing)
                    self._write_outbox()
                return True
            event = {
                "version": VERSION,
                "guest_event_id": stable_id,
                "guest_sequence": self.next_sequence,
                "occurred_at_unix_ms": int(occurred_at_ms),
                "event_type": event_type,
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "event_origin": event_origin,
                "event_confidence": event_confidence,
                "transport": transport,
                "payload": payload or {},
            }
            encoded = _encode(event)
            if not self._has_capacity(len(encoded) + 1):
                LOG.error("guest telemetry outbox is full; event %s was not queued", stable_id)
                self.record_diagnostic("outbox_capacity_rejections")
                return False
            self.next_sequence += 1
            _atomic_text(self.sequence_path, f"{self.next_sequence}\n")
            os.chmod(self.sequence_path, 0o600)
            self.known[stable_id] = event
            self._write_known()
            self.outbox.append(event)
            with open(self.outbox_path, "ab") as handle:
                handle.write(encoded + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_directory(self.outbox_path.parent)
            os.chmod(self.outbox_path, 0o600)
            return True

    def _has_capacity(self, additional_bytes):
        current_bytes = self.outbox_path.stat().st_size if self.outbox_path.exists() else 0
        return (
            len(self.outbox) < MAX_OUTBOX_EVENTS
            and current_bytes + additional_bytes <= MAX_OUTBOX_BYTES
        )

    def peek(self):
        with self.lock:
            return dict(self.outbox[0]) if self.outbox else None

    def acknowledge(self, guest_event_id):
        with self.lock:
            if not self.outbox or self.outbox[0]["guest_event_id"] != guest_event_id:
                return False
            self.outbox.pop(0)
            self._write_outbox()
            return True

    def record_diagnostic(self, code, increment=1):
        with self.lock:
            self.diagnostics[code] = min(
                int(self.diagnostics.get(code, 0)) + max(1, int(increment)), 2**63 - 1
            )
            _atomic_text(
                self.diagnostics_path,
                json.dumps(self.diagnostics, separators=(",", ":")) + "\n",
            )

    def flush_diagnostics(self):
        with self.lock:
            if not self.diagnostics:
                return True
            counters = dict(self.diagnostics)
            stable = uuid.uuid5(
                NAMESPACE,
                "diagnostics:" + json.dumps(counters, sort_keys=True, separators=(",", ":")),
            )
            if not self.enqueue(
                stable,
                "sensor.diagnostic",
                int(time.time() * 1000),
                transport="local",
                event_origin="sensor",
                event_confidence="observed",
                payload={"code": "sensor_counters", "counters": counters},
            ):
                return False
            self.diagnostics = {}
            _atomic_text(self.diagnostics_path, "{}\n")
            return True


def _encode(record):
    encoded = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_FRAME_BYTES:
        raise ValueError("telemetry event exceeds frame limit")
    return encoded


def _occurred_at_ms(record):
    raw = record.get("_SOURCE_REALTIME_TIMESTAMP") or record.get("__REALTIME_TIMESTAMP")
    try:
        return int(raw) // 1000
    except (TypeError, ValueError):
        return int(time.time() * 1000)


def parse_journal_record(record, boot_id):
    message = str(record.get("MESSAGE", ""))
    pid = str(record.get("_PID") or record.get("SYSLOG_PID") or "unknown")
    session_id = f"sshd:{pid}"
    event_type = None
    match = AUTH_FAILURE.search(message)
    if match:
        event_type = "ssh.auth.failed"
    else:
        match = AUTH_SUCCESS.search(message)
        if match:
            event_type = "ssh.auth.succeeded"
    if event_type:
        values = match.groupdict()
        return {
            "event_type": event_type,
            "session_id": session_id,
            "source_ip": values["ip"],
            "source_port": int(values["port"]),
            "destination_ip": None,
            "destination_port": 22,
            "transport": "tcp",
            "event_origin": "systemd_journal",
            "event_confidence": "observed",
            "payload": {"username": values["user"], "method": values["method"]},
            "occurred_at_ms": _occurred_at_ms(record),
        }
    match = SESSION_OPEN.search(message)
    if match:
        event_type = "ssh.session.opened"
    else:
        match = SESSION_CLOSE.search(message)
        if match:
            event_type = "ssh.session.closed"
    if event_type:
        return {
            "event_type": event_type,
            "session_id": session_id,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": 22,
            "transport": "tcp",
            "event_origin": "systemd_journal",
            "event_confidence": "observed",
            "payload": {"username": match.group("user")},
            "occurred_at_ms": _occurred_at_ms(record),
        }
    return None


def stable_journal_event_id(boot_id, cursor, event_type):
    return uuid.uuid5(NAMESPACE, f"{boot_id}:{cursor}:{event_type}")


def _bounded_message(value):
    message = value if isinstance(value, str) else str(value)
    encoded = message.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_LOG_MESSAGE_BYTES:
        return message, False
    return encoded[:MAX_LOG_MESSAGE_BYTES].decode("utf-8", errors="ignore"), True


def _fit_log_payload(payload, message_key, truncated_key):
    while len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_LOG_PAYLOAD_BYTES:
        payload[message_key] = payload[message_key][:len(payload[message_key]) // 2]
        payload[truncated_key] = True
    return payload


def raw_journal_event(record):
    message, truncated = _bounded_message(record.get("MESSAGE", ""))
    fields = (
        "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "PRIORITY", "_PID", "_UID", "_GID",
        "_TRANSPORT", "_BOOT_ID", "__CURSOR",
    )
    payload = {key: str(record[key])[:128] for key in fields if key in record}
    payload.update({"message": message, "message_truncated": truncated})
    _fit_log_payload(payload, "message", "message_truncated")
    return {
        "event_type": "guest.journal",
        "occurred_at_ms": _occurred_at_ms(record),
        "transport": "local",
        "event_origin": "systemd_journal",
        "event_confidence": "observed",
        "payload": payload,
    }


def _audit_session_for_record(record):
    pid = record.get("_PID") or record.get("SYSLOG_PID")
    if not pid or not str(pid).isdigit():
        return None
    try:
        session = int(Path(f"/proc/{pid}/sessionid").read_text(encoding="ascii").strip())
    except (FileNotFoundError, PermissionError, ValueError, OSError):
        return None
    if session == 4294967295:
        return None
    return f"audit:{session}"


def _diagnostic(outbox, boot_id, code, detail):
    event_id = uuid.uuid5(NAMESPACE, f"{boot_id}:diagnostic:{code}")
    outbox.enqueue(
        event_id,
        "sensor.diagnostic",
        int(time.time() * 1000),
        event_origin="sensor",
        event_confidence="observed",
        transport="local",
        payload={"code": code, "detail": detail},
    )


def audit_collector(outbox, boot_id, stop):
    reported_dropped_groups = 0
    unavailable_reported = False
    while not stop.is_set():
        if not AUDIT_LOG.is_file():
            if not unavailable_reported:
                _diagnostic(outbox, boot_id, "audit_log_unavailable", str(AUDIT_LOG))
                unavailable_reported = True
            stop.wait(30)
            continue
        unavailable_reported = False
        try:
            # The persisted cursor points to a completed audit group. Replaying from it must
            # start with a fresh assembler so a prior partial group is not appended twice.
            assembler = AuditAssembler()
            stat = AUDIT_LOG.stat()
            offset = 0
            if AUDIT_CURSOR.exists():
                cursor = json.loads(AUDIT_CURSOR.read_text(encoding="utf-8"))
                if cursor.get("device") == stat.st_dev and cursor.get("inode") == stat.st_ino:
                    offset = min(int(cursor.get("offset", 0)), stat.st_size)
            with open(AUDIT_LOG, encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while not stop.is_set():
                    line_offset = handle.tell()
                    line = handle.readline()
                    if not line:
                        try:
                            current = AUDIT_LOG.stat()
                            if current.st_dev != stat.st_dev or current.st_ino != stat.st_ino:
                                break
                        except FileNotFoundError:
                            break
                        stop.wait(0.5)
                        continue
                    message, truncated = _bounded_message(line.rstrip("\n"))
                    raw_id = uuid.uuid5(
                        NAMESPACE, f"{boot_id}:audit:{stat.st_dev}:{stat.st_ino}:{line_offset}"
                    )
                    if not outbox.enqueue(
                        raw_id,
                        "guest.audit",
                        int(time.time() * 1000),
                        transport="local",
                        event_origin="kernel_audit",
                        event_confidence="observed",
                        payload=_fit_log_payload(
                            {"line": message, "line_truncated": truncated},
                            "line", "line_truncated",
                        ),
                    ):
                        stop.wait(2)
                        break
                    events = assembler.feed(line)
                    if assembler.dropped_groups > reported_dropped_groups:
                        outbox.record_diagnostic(
                            "audit_incomplete_groups_dropped",
                            assembler.dropped_groups - reported_dropped_groups,
                        )
                        reported_dropped_groups = assembler.dropped_groups
                    durable = True
                    for event in events:
                        source_key = event.pop("source_key")
                        event_id = uuid.uuid5(NAMESPACE, f"{boot_id}:{source_key}")
                        if not outbox.enqueue(event_id, **event):
                            durable = False
                            break
                    if not durable:
                        stop.wait(2)
                        break
                    if line.startswith("type=EOE "):
                        _atomic_text(
                            AUDIT_CURSOR,
                            json.dumps(
                                {"device": stat.st_dev, "inode": stat.st_ino, "offset": handle.tell()},
                                separators=(",", ":"),
                            )
                            + "\n",
                        )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            _diagnostic(outbox, boot_id, "audit_reader_error", str(error)[:512])
            stop.wait(5)


def _read_ack(device_fd):
    deadline = time.monotonic() + ACK_TIMEOUT_SECONDS
    data = bytearray()
    while time.monotonic() < deadline and len(data) <= MAX_FRAME_BYTES:
        ready, _, _ = select.select([device_fd], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(device_fd, 4096)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if b"\n" not in data or len(data) > MAX_FRAME_BYTES + 1:
        raise RuntimeError("missing or oversized host acknowledgement")
    acknowledgement = json.loads(bytes(data).split(b"\n", 1)[0])
    if not isinstance(acknowledgement, dict) or set(acknowledgement) != {
        "version",
        "acknowledged_guest_event_id",
        "event_id",
        "host_sequence",
        "duplicate",
    }:
        raise RuntimeError("host acknowledgement has an invalid schema")
    if type(acknowledgement["version"]) is not int or acknowledgement["version"] != VERSION:
        raise RuntimeError("host acknowledgement has an invalid version")
    try:
        uuid.UUID(acknowledgement["acknowledged_guest_event_id"])
        uuid.UUID(acknowledgement["event_id"])
    except (ValueError, TypeError, AttributeError) as error:
        raise RuntimeError("host acknowledgement has an invalid UUID") from error
    if (
        not isinstance(acknowledgement["host_sequence"], int)
        or isinstance(acknowledgement["host_sequence"], bool)
        or acknowledgement["host_sequence"] < 1
        or not isinstance(acknowledgement["duplicate"], bool)
    ):
        raise RuntimeError("host acknowledgement has invalid persistence fields")
    return acknowledgement


def _write_all(device_fd, data):
    view = memoryview(data)
    while view:
        written = os.write(device_fd, view)
        if written <= 0:
            raise OSError("virtio channel accepted zero bytes")
        view = view[written:]


def sender(outbox, stop):
    last_failure_counter = 0.0
    drain_deadline = None
    while True:
        if stop.is_set() and drain_deadline is None:
            drain_deadline = time.monotonic() + 3
        if drain_deadline is not None and time.monotonic() >= drain_deadline:
            return
        event = outbox.peek()
        if event is None:
            if stop.is_set():
                return
            stop.wait(1)
            continue
        if not CHANNEL.exists():
            if drain_deadline is not None:
                time.sleep(0.2)
            else:
                stop.wait(1)
            continue
        device_fd = None
        try:
            device_fd = os.open(CHANNEL, os.O_RDWR | os.O_NOCTTY)
            _write_all(device_fd, _encode(event) + b"\n")
            acknowledgement = _read_ack(device_fd)
            if (
                acknowledgement.get("version") != VERSION
                or acknowledgement.get("acknowledged_guest_event_id")
                != event["guest_event_id"]
            ):
                raise RuntimeError("host acknowledgement does not match the oldest event")
            outbox.acknowledge(event["guest_event_id"])
            outbox.flush_diagnostics()
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
            LOG.warning("telemetry delivery unavailable: %s", error)
            if time.monotonic() - last_failure_counter >= 60:
                outbox.record_diagnostic("delivery_failures")
                last_failure_counter = time.monotonic()
            if drain_deadline is not None:
                time.sleep(0.2)
            else:
                stop.wait(2)
        finally:
            if device_fd is not None:
                os.close(device_fd)


def heartbeat(outbox, boot_id, stop):
    while not stop.wait(60):
        bucket = int(time.time() // 60)
        event_id = uuid.uuid5(NAMESPACE, f"{boot_id}:heartbeat:{bucket}")
        with outbox.lock:
            pending_events = len(outbox.outbox)
        outbox.enqueue(
            event_id,
            "sensor.heartbeat",
            int(time.time() * 1000),
            transport="local",
            event_origin="sensor",
            event_confidence="observed",
            payload={"outbox_events": pending_events},
        )


def _boot_time_ms():
    with open("/proc/stat", encoding="ascii") as handle:
        for line in handle:
            if line.startswith("btime "):
                return int(line.split()[1]) * 1000
    return int(time.time() * 1000)


def run():
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    outbox = DurableGuestOutbox()
    marker = BOOT_MARKER.read_text(encoding="ascii").strip() if BOOT_MARKER.exists() else None
    if marker != boot_id:
        boot_event_id = uuid.uuid5(NAMESPACE, f"{boot_id}:boot")
        if outbox.enqueue(
            boot_event_id,
            "guest.boot",
            _boot_time_ms(),
            transport="local",
            event_origin="sensor",
            event_confidence="observed",
            payload={},
        ):
            _atomic_text(BOOT_MARKER, boot_id + "\n")
    stop = threading.Event()
    shutdown_emitted = threading.Event()

    def request_stop(_signum, _frame):
        if not shutdown_emitted.is_set():
            shutdown_emitted.set()
            shutdown_id = uuid.uuid5(NAMESPACE, f"{boot_id}:shutdown")
            outbox.enqueue(
                shutdown_id,
                "guest.shutdown",
                int(time.time() * 1000),
                transport="local",
                event_origin="sensor",
                event_confidence="observed",
                payload={},
            )
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    delivery = threading.Thread(target=sender, args=(outbox, stop), daemon=True)
    delivery.start()
    audit = threading.Thread(target=audit_collector, args=(outbox, boot_id, stop), daemon=True)
    audit.start()
    heartbeat_worker = threading.Thread(target=heartbeat, args=(outbox, boot_id, stop), daemon=True)
    heartbeat_worker.start()

    cursor = CURSOR.read_text(encoding="utf-8").strip() if CURSOR.exists() else None
    command = ["journalctl", "--follow", "--output=json", "--all"]
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append("--boot")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in process.stdout:
            if stop.is_set():
                break
            try:
                record = json.loads(line)
                record_cursor = record.get("__CURSOR")
                if record.get("_SYSTEMD_UNIT") == "honeyforge-high-telemetry.service":
                    if record_cursor:
                        _atomic_text(CURSOR, record_cursor + "\n")
                    continue
                if record_cursor:
                    raw_id = stable_journal_event_id(boot_id, record_cursor, "guest.journal")
                    if not outbox.enqueue(raw_id, **raw_journal_event(record)):
                        break
                parsed = parse_journal_record(record, boot_id)
                if (
                    parsed and record_cursor
                    and record.get("_SYSTEMD_UNIT") in ("ssh.service", "sshd.service")
                ):
                    audit_session = _audit_session_for_record(record)
                    if audit_session:
                        parsed["session_id"] = audit_session
                        parsed["payload"]["audit_session_id"] = int(audit_session.split(":", 1)[1])
                    stable_id = stable_journal_event_id(boot_id, record_cursor, parsed["event_type"])
                    if not outbox.enqueue(stable_id, **parsed):
                        # Do not advance past an event that was not made durable. systemd restarts
                        # us and journalctl resumes from the last persisted cursor.
                        break
                if record_cursor:
                    _atomic_text(CURSOR, record_cursor + "\n")
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                LOG.warning("ignored malformed journal record: %s", error)
                outbox.record_diagnostic("journal_parse_errors")
    finally:
        stop.set()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        delivery.join(timeout=3)
        audit.join(timeout=3)
        heartbeat_worker.join(timeout=3)


if __name__ == "__main__":
    run()
