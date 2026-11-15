"""Exercise the optional conditions using only synthetic input and loopback TLS."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from freeze_exit_snapshot import INCLUDE, UTC_FORMAT, freeze
from test_lab import HERE, LOOPBACK, Links, NginxLabTestCase


SOURCE_NAME = "2026-11-13-00-15-00"
NOW = datetime(2026, 11, 13, 1, tzinfo=timezone.utc)
BATCH_END = NOW + timedelta(hours=1)
# These public-format IPv4 entries are fabricated source records, never test
# destinations. The HTTP fixtures below use only local loopback addresses.
SOURCE = b"""@type tordnsel 1.0
Downloaded 2026-11-13 00:15:00
ExitNode 0000000000000000000000000000000000000000
Published 2026-11-12 23:30:00
LastStatus 2026-11-13 00:00:00
ExitAddress 23.0.0.1 2026-11-12 00:00:00
ExitAddress 23.0.0.2 2026-11-12 02:00:00
ExitAddress 23.0.0.3 2026-11-12 03:00:00
ExitAddress 23.0.0.3 2026-11-13 00:10:00
ExitAddress 23.0.0.4 2026-11-13 00:10:00
"""


def source_digest(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def stage(prefix, *names):
    for name in names:
        shutil.copyfile(HERE / name, prefix / name)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="check-tor-snapshot-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / SOURCE_NAME
        self.source.write_bytes(SOURCE)

    def test_uses_observation_times_deduplicates_and_pins_batch_deadline(self):
        config = freeze(self.source, source_digest(SOURCE), BATCH_END, NOW)
        self.assertNotIn("23.0.0.1", config)
        self.assertNotIn("23.0.0.2", config)
        self.assertEqual(config.count("23.0.0.3/32 listed;"), 1)
        self.assertIn("23.0.0.4/32 listed;", config)
        self.assertIn("oldest selected observation UTC: 2026-11-13T00:10:00Z", config)
        self.assertIn("frozen deadline UTC: 2026-11-13T02:00:00Z", config)
        self.assertIn(f"source SHA-256 (Base64): {source_digest(SOURCE)}", config)

    def test_invalid_missing_and_stale_source(self):
        digest = source_digest(SOURCE)
        with self.assertRaisesRegex(ValueError, "does not match"):
            freeze(self.source, source_digest(b"different source"), BATCH_END, NOW)
        for invalid in ("!", "AAAA", digest.rstrip("="), hashlib.sha256(SOURCE).hexdigest()):
            with self.subTest(digest=invalid), self.assertRaisesRegex(ValueError, "Base64"):
                freeze(self.source, invalid, BATCH_END, NOW)
        with self.assertRaisesRegex(ValueError, "stale by"):
            freeze(self.source, digest, NOW + timedelta(hours=3), NOW)
        with self.assertRaisesRegex(ValueError, "stale by"):
            freeze(self.source, digest, BATCH_END + timedelta(hours=4), NOW + timedelta(hours=4))
        for old, invalid in (
            (b"tordnsel 1.0", b"tordnsel 2.0"),
            (b"Downloaded 2026-11-13 00:15:00", b"Downloaded 2026-11-13 00:16:00"),
            (b"23.0.0.4", b"23.0.0.999"),
            (b"23.0.0.4", b"23.0.0.4/24"),
            (b"23.0.0.4", b"127.0.0.1"),
            (b"23.0.0.4", b"::1"),
            (b"23.0.0.4", b"23.0.0.4; }"),
            (b"2026-11-13 00:10:00", b"2026-11-13 00:16:00"),
            (b"2026-11-13 00:10:00", b"2026-11-12 00:10:00"),
            (b"2026-11-13 00:10:00", b"2026-15-13 00:10:00"),
        ):
            data = SOURCE.replace(old, invalid)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.source.write_bytes(data)
                freeze(self.source, source_digest(data), BATCH_END, NOW)
        self.source.unlink()
        with self.assertRaises(FileNotFoundError):
            freeze(self.source, digest, BATCH_END, NOW)

    def test_command_installs_private_include_once_and_refuses_replacement(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        list_time = now - timedelta(minutes=1)
        source = self.directory / list_time.strftime("%Y-%m-%d-%H-%M-%S")
        previous = datetime(2026, 11, 13, tzinfo=timezone.utc)
        data = SOURCE
        for old in (previous + timedelta(minutes=15), previous + timedelta(minutes=10)):
            data = data.replace(old.strftime("%Y-%m-%d %H:%M:%S").encode("ascii"),
                                list_time.strftime("%Y-%m-%d %H:%M:%S").encode("ascii"))
        source.write_bytes(data)
        output = self.directory / INCLUDE
        command = [
            sys.executable, str(HERE / "freeze_exit_snapshot.py"), str(source),
            "--prefix", str(self.directory), "--batch-end",
            (now + timedelta(minutes=5)).strftime(UTC_FORMAT),
            "--sha256", source_digest(data),
        ]
        bad_digest = subprocess.run(command[:-1] + ["0" * 64], capture_output=True, timeout=10)
        self.assertEqual(bad_digest.returncode, 1)
        self.assertFalse(output.exists())
        first = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        preserved = output.read_bytes()
        second = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(output.read_bytes(), preserved)


class ConditionTests(NginxLabTestCase):
    listen_ipv6 = True

    @classmethod
    def stage_conditions(cls, prefix):
        stage(prefix, "condition-http-client.conf", "condition-routes-client.conf",
              "condition-routes-tor-diff.conf", "condition-tor-diff-gate.inc",
              "condition-task-start.inc", "condition-task-complete.inc")
        # Exercise both families of nginx's real peer-address lookup. The
        # production compiler only marks IPv4 addresses as eligible.
        (prefix / INCLUDE).write_text(
            "geo $remote_addr $reference_exit_membership {\n"
            "    default unlisted;\n"
            "    127.0.0.1/32 listed;\n"
            "    ::1/128 listed;\n"
            "}\n",
            encoding="ascii",
        )

    def assert_task(self, route, headers=None, host=LOOPBACK):
        status, response_headers, body = self.request("GET", route, headers=headers, host=host)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", response_headers["Content-Security-Policy"])
        self.assertNotIn("Location", response_headers)
        self.assertNotIn("Set-Cookie", response_headers)
        self.assertIn(b"open from 9 a.m. to 5 p.m.", body)
        self.assertLess(len(body), 1024)
        links = Links()
        links.feed(body.decode("utf-8"))
        self.assertEqual(links.destinations, [f"{route}/complete"])
        status, _, body = self.request("GET", links.destinations[0], headers=headers, host=host)
        self.assertEqual(status, 200)
        self.assertIn(b"reading room is on the ground floor", body)

    def test_expected_header_independent_of_listed_source(self):
        for host in (LOOPBACK, "::1"):
            with self.subTest(host=host):
                self.assert_task("/client", headers={"sec-fetch-mode": "navigate"}, host=host)

    def test_missing_unexpected_and_malformed_header(self):
        for path in ("/client", "/client/complete"):
            for value in (None, "", "Navigate", "cors", '"navigate"', "navigate, navigate",
                          "navigate;parameter", "navigate\textra"):
                with self.subTest(path=path, value=value):
                    headers = {} if value is None else {"Sec-Fetch-Mode": value}
                    self.assertEqual(self.request("GET", path, headers=headers)[0], 403)
            for values in (("navigate", "cors"), ("cors", "navigate"), ("navigate", "navigate")):
                with self.subTest(path=path, values=values):
                    client = http.client.HTTPSConnection(LOOPBACK, self.port,
                                                         context=self.context, timeout=2)
                    try:
                        client.putrequest("GET", path)
                        for value in values:
                            client.putheader("Sec-Fetch-Mode", value)
                        client.endheaders()
                        self.assertEqual(client.getresponse().status, 403)
                    finally:
                        client.close()

    def test_unchanged_probe_is_refused(self):
        record = self.probe("/client")
        self.assertIsNone(record["local_error"], record)
        self.assertEqual(record["curl_exit"], 0, record)
        self.assertEqual(record["http_status"], 403, record)
        self.assertEqual(record["verdict"], "FAIL", record)

    def test_listed_peers_ignore_forged_forwarding_headers(self):
        for host in (LOOPBACK, "::1"):
            for path in ("/tor-diff", "/tor-diff/complete"):
                headers = {
                    "Forwarded": "for=192.0.2.99",
                    "X-Forwarded-For": "192.0.2.99",
                    "X-Real-IP": "192.0.2.99",
                    "Sec-Fetch-Mode": "navigate",
                }
                with self.subTest(host=host, path=path):
                    self.assertEqual(self.request("GET", path, headers=headers, host=host)[0], 403)

    def test_route_limits_and_no_runtime_snapshot_refresh(self):
        self.assertEqual(self.request("POST", "/client")[0], 405)
        self.assertEqual(self.request("GET", "/tor-diff", body=b"x")[0], 400)
        self.assertEqual(self.request("GET", f"/{INCLUDE}")[0], 404)
        self.assertEqual(self.request("GET", "/client/other")[0], 404)
        snapshot = self.prefix / INCLUDE
        replacement = snapshot.with_suffix(".tmp")
        replacement.write_text(
            "geo $remote_addr $reference_exit_membership { default unlisted; }\n",
            encoding="ascii",
        )
        replacement.replace(snapshot)
        self.assertEqual(self.request("GET", "/tor-diff")[0], 403)
        self.assertEqual(self.request("GET", "/tor-diff", host="::1")[0], 403)


class SupportedFamiliesTests(NginxLabTestCase):
    listen_ipv6 = True

    @classmethod
    def stage_conditions(cls, prefix):
        stage(prefix, "condition-routes-tor-diff.conf", "condition-tor-diff-gate.inc",
              "condition-task-start.inc", "condition-task-complete.inc")
        source = prefix / SOURCE_NAME
        source.write_bytes(SOURCE)
        config = freeze(source, source_digest(SOURCE), BATCH_END, NOW)
        (prefix / INCLUDE).write_text(config, encoding="ascii")

    def test_unlisted_ipv4_and_unsupported_ipv6(self):
        for route in ("/tor-diff", "/tor-diff/complete"):
            headers = {
                "Forwarded": "for=23.0.0.3",
                "X-Forwarded-For": "23.0.0.3",
                "X-Real-IP": "23.0.0.3",
            }
            self.assertEqual(self.request("GET", route, headers=headers)[0], 200)
            self.assertEqual(self.request("GET", route, headers=headers, host="::1")[0], 503)


class UnlistedIPv6Tests(NginxLabTestCase):
    listen_ipv6 = True

    @classmethod
    def stage_conditions(cls, prefix):
        stage(prefix, "condition-routes-tor-diff.conf", "condition-tor-diff-gate.inc",
              "condition-task-start.inc", "condition-task-complete.inc")
        (prefix / INCLUDE).write_text(
            "geo $remote_addr $reference_exit_membership {\n"
            "    default unavailable;\n"
            "    ::/0 unlisted;\n"
            "    2001:db8::1/128 listed;\n"
            "}\n",
            encoding="ascii",
        )

    def test_unlisted_ipv6_ignores_forwarding_headers(self):
        headers = {"Forwarded": 'for="[2001:db8::1]"', "X-Forwarded-For": "2001:db8::1"}
        for route in ("/tor-diff", "/tor-diff/complete"):
            self.assertEqual(self.request("GET", route, headers=headers, host="::1")[0], 200)


if __name__ == "__main__":
    unittest.main(catchbreak=True)
