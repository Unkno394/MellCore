import importlib.util
import json
import os
import tempfile
import unittest
import uuid
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("high_telemetry_sensor.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("high_telemetry_sensor", MODULE_PATH)
sensor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sensor)


class GuestTelemetrySensorTests(unittest.TestCase):
    def test_parses_authentication_and_session_events(self):
        failed = sensor.parse_journal_record(
            {
                "MESSAGE": "Failed password for invalid user admin from 203.0.113.7 port 50123 ssh2",
                "_PID": "42",
                "_SOURCE_REALTIME_TIMESTAMP": "1760000000000000",
            },
            "boot",
        )
        self.assertEqual(failed["event_type"], "ssh.auth.failed")
        self.assertEqual(failed["source_ip"], "203.0.113.7")
        self.assertEqual(failed["payload"]["username"], "admin")
        opened = sensor.parse_journal_record(
            {"MESSAGE": "pam_unix(sshd:session): session opened for user root(uid=0)", "_PID": "43"},
            "boot",
        )
        self.assertEqual(opened["event_type"], "ssh.session.opened")
        self.assertEqual(opened["session_id"], "sshd:43")

    def test_event_id_is_stable_for_journal_retry(self):
        first = sensor.stable_journal_event_id("boot", "cursor", "ssh.auth.failed")
        second = sensor.stable_journal_event_id("boot", "cursor", "ssh.auth.failed")
        self.assertEqual(first, second)

    def test_outbox_recovers_and_reuses_immutable_event_after_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            event_id = uuid.uuid4()
            outbox = sensor.DurableGuestOutbox(directory)
            self.assertTrue(
                outbox.enqueue(
                    event_id,
                    "ssh.auth.succeeded",
                    1760000000000,
                    session_id="sshd:7",
                    source_ip="192.0.2.4",
                    source_port=50000,
                    payload={"username": "root", "method": "password"},
                )
            )
            original = outbox.peek()
            recovered = sensor.DurableGuestOutbox(directory)
            self.assertEqual(recovered.peek(), original)
            self.assertTrue(recovered.acknowledge(str(event_id)))
            self.assertIsNone(recovered.peek())
            self.assertTrue(
                recovered.enqueue(
                    event_id,
                    "ignored-on-replay",
                    0,
                    payload={"different": True},
                )
            )
            self.assertEqual(recovered.peek(), original)

    def test_outbox_overflow_is_bounded_and_becomes_a_diagnostic_event(self):
        original_limit = sensor.MAX_OUTBOX_EVENTS
        sensor.MAX_OUTBOX_EVENTS = 1
        try:
            with tempfile.TemporaryDirectory() as directory:
                outbox = sensor.DurableGuestOutbox(directory)
                first_id = uuid.uuid4()
                self.assertTrue(outbox.enqueue(first_id, "guest.boot", 1, payload={}))
                self.assertFalse(outbox.enqueue(uuid.uuid4(), "guest.boot", 2, payload={}))
                self.assertEqual(outbox.diagnostics["outbox_capacity_rejections"], 1)
                self.assertTrue(outbox.acknowledge(str(first_id)))
                self.assertTrue(outbox.flush_diagnostics())
                self.assertEqual(outbox.peek()["event_type"], "sensor.diagnostic")
        finally:
            sensor.MAX_OUTBOX_EVENTS = original_limit

    def test_persisted_outbox_byte_limit_is_enforced(self):
        original_limit = sensor.MAX_OUTBOX_BYTES
        sensor.MAX_OUTBOX_BYTES = 32
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / sensor.OUTBOX.name
                path.write_bytes(b"x" * 33)
                with self.assertRaisesRegex(RuntimeError, "persisted byte limit"):
                    sensor.DurableGuestOutbox(directory)
        finally:
            sensor.MAX_OUTBOX_BYTES = original_limit

    def test_ack_schema_rejects_spoofed_or_incomplete_ack(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(
                write_fd,
                json.dumps(
                    {
                        "version": 1,
                        "acknowledged_guest_event_id": str(uuid.uuid4()),
                    }
                ).encode("utf-8")
                + b"\n",
            )
            with self.assertRaisesRegex(RuntimeError, "invalid schema"):
                sensor._read_ack(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)


if __name__ == "__main__":
    unittest.main()
