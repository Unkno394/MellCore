"""Parser for Linux audit records used by the High guest sensor.

It intentionally reports kernel observations, not inferred shell input. One audit event can span
SYSCALL, EXECVE, PATH, CWD and SOCKADDR records; EOE closes the group.
"""

import ipaddress
import os
import pwd
import re

HEADER = re.compile(
    r"^type=(?P<type>[A-Z_]+) msg=audit\((?P<seconds>\d+(?:\.\d+)?):(?P<serial>\d+)\): ?(?P<body>.*)$"
)
FIELD = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"(?:\\.|[^\"])*\"|'[^']*'|\S+)")
UNSET_AUDIT_ID = 4294967295
MAX_TEXT_CHARACTERS = 512
MAX_EXEC_ARGUMENTS = 32
MAX_ARGUMENT_CHARACTERS = 256
MAX_FILE_PATHS = 8
MAX_PENDING_AUDIT_GROUPS = 1024


def _fields(body):
    result = {}
    for match in FIELD.finditer(body):
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[match.group("key")] = value
    return result


def _text(value):
    if value is None:
        return None
    if value and len(value) % 2 == 0 and all(character in "0123456789abcdefABCDEF" for character in value):
        try:
            decoded = bytes.fromhex(value).decode("utf-8", errors="strict")
            if decoded.isprintable():
                return decoded[:MAX_TEXT_CHARACTERS]
        except (ValueError, UnicodeDecodeError):
            pass
    return value.replace('\\"', '"')[:MAX_TEXT_CHARACTERS]


def _integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _username(uid):
    if uid is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _audit_session(fields):
    session = _integer(fields.get("ses"))
    if session is None or session == UNSET_AUDIT_ID:
        return None
    return f"audit:{session}"


def _base_payload(syscall, cwd):
    uid = _integer(syscall.get("uid"))
    return {
        "pid": _integer(syscall.get("pid")),
        "ppid": _integer(syscall.get("ppid")),
        "uid": uid,
        "euid": _integer(syscall.get("euid")),
        "audit_uid": _integer(syscall.get("auid")),
        "username": _username(uid),
        "audit_session_id": _integer(syscall.get("ses")),
        "executable": _text(syscall.get("exe")),
        "syscall": syscall.get("syscall"),
        "cwd": _text(cwd.get("cwd")) if cwd else None,
        "kernel_success": syscall.get("success"),
        "kernel_exit": _integer(syscall.get("exit")),
    }


def _exec_arguments(records):
    arguments = {}
    for record_type, fields in records:
        if record_type != "EXECVE":
            continue
        for key, value in fields.items():
            if key.startswith("a") and key[1:].isdigit():
                arguments[int(key[1:])] = _text(value)
    ordered = [arguments[index] for index in sorted(arguments)]
    truncated = len(ordered) > MAX_EXEC_ARGUMENTS
    bounded = []
    for argument in ordered[:MAX_EXEC_ARGUMENTS]:
        truncated = truncated or len(argument) > MAX_ARGUMENT_CHARACTERS
        bounded.append(argument[:MAX_ARGUMENT_CHARACTERS])
    return bounded, truncated


def _decode_sockaddr(value):
    if not value:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if len(raw) < 4:
        return None
    family = int.from_bytes(raw[0:2], "little")
    port = int.from_bytes(raw[2:4], "big")
    try:
        if family == 2 and len(raw) >= 8:
            return str(ipaddress.ip_address(raw[4:8])), port
        if family == 10 and len(raw) >= 24:
            return str(ipaddress.ip_address(raw[8:24])), port
    except ValueError:
        return None
    return None


def _exit_code(value):
    if value is None:
        return None
    try:
        raw = int(value, 16)
    except ValueError:
        return None
    if raw & (1 << 31):
        raw -= 1 << 32
    return raw


class AuditAssembler:
    def __init__(self):
        self.pending = {}
        self.dropped_groups = 0

    def feed(self, line):
        match = HEADER.match(line.strip())
        if not match:
            return []
        serial = match.group("serial")
        if serial not in self.pending and len(self.pending) >= MAX_PENDING_AUDIT_GROUPS:
            self.pending.pop(next(iter(self.pending)))
            self.dropped_groups += 1
        group = self.pending.setdefault(
            serial,
            {
                "serial": serial,
                "occurred_at_ms": int(float(match.group("seconds")) * 1000),
                "records": [],
            },
        )
        record_type = match.group("type")
        if record_type == "EOE":
            self.pending.pop(serial, None)
            return normalize_group(group)
        group["records"].append((record_type, _fields(match.group("body"))))
        return []


def normalize_group(group):
    records = group["records"]
    syscall = next((fields for record_type, fields in records if record_type == "SYSCALL"), None)
    if syscall is None:
        return []
    cwd = next((fields for record_type, fields in records if record_type == "CWD"), None)
    key = syscall.get("key", "").strip('"')
    occurred = group["occurred_at_ms"]
    session_id = _audit_session(syscall)
    base = _base_payload(syscall, cwd)
    events = []

    if key == "hf_exec":
        payload = dict(base)
        payload["arguments"], payload["arguments_truncated"] = _exec_arguments(records)
        events.append(_event("process.exec", occurred, session_id, payload, "observed"))
        executable = payload.get("executable") or (payload["arguments"][0] if payload["arguments"] else "")
        if executable.endswith("/sudo") or executable == "sudo":
            events.append(_event("privilege.sudo", occurred, session_id, payload, "observed"))
        elif executable.endswith("/su") or executable == "su":
            events.append(_event("privilege.su", occurred, session_id, payload, "observed"))

    elif key == "hf_exit":
        payload = dict(base)
        payload["requested_exit_code"] = _exit_code(syscall.get("a0"))
        payload["exit_observation"] = "exit_or_exit_group_syscall"
        events.append(_event("process.exit", occurred, session_id, payload, "observed"))

    elif key.startswith("hf_file_"):
        paths = []
        paths_truncated = False
        for record_type, fields in records:
            if record_type == "PATH":
                path = _text(fields.get("name"))
                if path and not path.startswith("/var/lib/honeyforge-high-telemetry"):
                    if len(paths) < MAX_FILE_PATHS:
                        paths.append({"path": path, "name_type": fields.get("nametype")})
                    else:
                        paths_truncated = True
        if paths:
            syscall_name = syscall.get("syscall", "")
            name_types = {item["name_type"] for item in paths}
            if "CREATE" in name_types:
                event_type = "file.created"
            elif "DELETE" in name_types:
                event_type = "file.deleted"
            elif syscall_name in {"rename", "renameat", "renameat2"}:
                event_type = "file.renamed"
            elif syscall_name in {"chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat"}:
                event_type = "file.permissions"
            else:
                event_type = "file.modified"
            payload = dict(base)
            payload["paths"] = paths
            payload["paths_truncated"] = paths_truncated
            payload["watch_key"] = key
            events.append(_event(event_type, occurred, session_id, payload, "inferred"))

    elif key == "hf_net_connect":
        address = None
        for record_type, fields in records:
            if record_type == "SOCKADDR":
                address = _decode_sockaddr(fields.get("saddr"))
                if address:
                    break
        if address:
            destination_ip, destination_port = address
            event_type = "network.connect" if syscall.get("success") == "yes" else "network.connect.failed"
            payload = dict(base)
            payload["transport_resolution"] = "unknown_from_connect_syscall"
            event = _event(event_type, occurred, session_id, payload, "observed")
            event["destination_ip"] = destination_ip
            event["destination_port"] = destination_port
            event["transport"] = "unknown"
            events.append(event)

    for index, event in enumerate(events):
        event["source_key"] = f"audit:{group['serial']}:{event['event_type']}:{index}"
    return events


def _event(event_type, occurred_at_ms, session_id, payload, confidence):
    return {
        "event_type": event_type,
        "occurred_at_ms": occurred_at_ms,
        "session_id": session_id,
        "source_ip": None,
        "source_port": None,
        "destination_ip": None,
        "destination_port": None,
        "transport": "local",
        "event_origin": "kernel_audit",
        "event_confidence": confidence,
        "payload": payload,
    }
