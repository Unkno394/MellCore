import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from high_telemetry_audit import MAX_PENDING_AUDIT_GROUPS, AuditAssembler


class AuditParserTests(unittest.TestCase):
    def test_exec_is_kernel_observation_with_process_and_session_context(self):
        parser = AuditAssembler()
        lines = [
            'type=SYSCALL msg=audit(1760000000.125:77): arch=c000003e syscall=execve success=yes exit=0 a0=0 pid=120 ppid=100 auid=1000 uid=1000 euid=1000 ses=9 exe="/usr/bin/id" key="hf_exec"',
            'type=EXECVE msg=audit(1760000000.125:77): argc=2 a0="id" a1="-u"',
            'type=CWD msg=audit(1760000000.125:77): cwd="/home/analyst"',
            'type=EOE msg=audit(1760000000.125:77):',
        ]
        events = []
        for line in lines:
            events.extend(parser.feed(line))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "process.exec")
        self.assertEqual(events[0]["session_id"], "audit:9")
        self.assertEqual(events[0]["payload"]["arguments"], ["id", "-u"])
        self.assertEqual(events[0]["event_origin"], "kernel_audit")

    def test_file_and_network_records_are_normalized_without_contents(self):
        parser = AuditAssembler()
        file_lines = [
            'type=SYSCALL msg=audit(1760000001.0:78): syscall=openat success=yes exit=3 pid=12 ppid=1 auid=0 uid=0 euid=0 ses=4 exe="/usr/bin/touch" key="hf_file_etc"',
            'type=PATH msg=audit(1760000001.0:78): item=0 name="/etc/persist.conf" nametype=CREATE',
            'type=EOE msg=audit(1760000001.0:78):',
        ]
        events = []
        for line in file_lines:
            events.extend(parser.feed(line))
        self.assertEqual(events[0]["event_type"], "file.created")
        self.assertNotIn("contents", events[0]["payload"])

        # sockaddr_in: AF_INET, port 443, address 203.0.113.10.
        network_lines = [
            'type=SYSCALL msg=audit(1760000002.0:79): syscall=connect success=yes exit=0 pid=13 ppid=1 auid=0 uid=0 euid=0 ses=4 exe="/usr/bin/curl" key="hf_net_connect"',
            'type=SOCKADDR msg=audit(1760000002.0:79): saddr=020001BBCB00710A0000000000000000',
            'type=EOE msg=audit(1760000002.0:79):',
        ]
        events = []
        for line in network_lines:
            events.extend(parser.feed(line))
        self.assertEqual(events[0]["event_type"], "network.connect")
        self.assertEqual(events[0]["destination_ip"], "203.0.113.10")
        self.assertEqual(events[0]["destination_port"], 443)

    def test_exec_arguments_are_bounded_and_report_truncation(self):
        parser = AuditAssembler()
        arguments = " ".join(f'a{index}="{"x" * 400}"' for index in range(40))
        lines = [
            'type=SYSCALL msg=audit(1760000003.0:80): syscall=execve success=yes exit=0 pid=14 ppid=1 auid=1000 uid=1000 euid=1000 ses=5 exe="/bin/tool" key="hf_exec"',
            f"type=EXECVE msg=audit(1760000003.0:80): argc=40 {arguments}",
            'type=EOE msg=audit(1760000003.0:80):',
        ]
        events = []
        for line in lines:
            events.extend(parser.feed(line))
        self.assertEqual(len(events[0]["payload"]["arguments"]), 32)
        self.assertTrue(events[0]["payload"]["arguments_truncated"])
        self.assertLessEqual(max(map(len, events[0]["payload"]["arguments"])), 256)

    def test_incomplete_audit_groups_are_bounded_and_counted(self):
        parser = AuditAssembler()
        for serial in range(MAX_PENDING_AUDIT_GROUPS + 1):
            parser.feed(
                f"type=SYSCALL msg=audit(1760000004.0:{serial}): "
                'syscall=execve success=yes pid=1 ppid=0 auid=0 uid=0 euid=0 ses=1 key="hf_exec"'
            )
        self.assertEqual(len(parser.pending), MAX_PENDING_AUDIT_GROUPS)
        self.assertEqual(parser.dropped_groups, 1)


if __name__ == "__main__":
    unittest.main()
