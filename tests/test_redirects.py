"""Offline redirect chains, contact boundaries, and hostile metadata evidence."""

import importlib.util
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import threading
import unittest

import test_measurement as measurement

SPEC = importlib.util.spec_from_file_location(
    "redirect_subject", measurement.ROOT / "check_tor_measure.py"
)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)
A = "https://a.example.test/"
B = "https://b.example.test/"
C = "https://c.example.test/"


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.fixture = measurement.MeasurementTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def scan(self, chain, *args):
        self.fixture.clear_logs()
        status, rows, error = self.fixture.run_scan(
            *args, targets=[A], plan={A: [{"chain": chain}]}
        )
        self.assertEqual(status, 0, error)
        self.fixture.assert_accounting(rows)
        self.fixture.assert_clean()
        ends = self.fixture.select(rows, "attempt_end", "target")
        return rows, ends, self.fixture.calls("contacts")

    def test_zero_one_and_exact_budget_terminal(self):
        chain = {A: {"code": 302, "location": B},
                 B: {"code": 301, "location": C}, C: {"code": 200}}
        for limit, visited, next_url, code in ((0, [A], B, 302), (1, [A, B], C, 301),
                                              (2, [A, B, C], None, 200)):
            with self.subTest(limit=limit):
                rows, ends, contacts = self.scan(chain, "--max-redirects", limit)
                self.assertEqual(len(ends), 1)  # no failure retry or conditional control
                end = ends[0]
                self.assertEqual(contacts[0]["contacts"], visited)
                self.assertEqual(end["http_status"], code)
                self.assertEqual(end["final_url"], visited[-1])
                self.assertEqual(end["redirect_count"], limit)
                self.assertEqual(end["verdict"], "WARN" if next_url else "PASS")
                self.assertEqual(end["curl_exit"], 47 if next_url else 0)
                self.assertEqual(end["stop_reason"], "redirect_limit" if next_url else None)
                evidence = end["redirect_evidence"]
                self.assertEqual(evidence["state"], "complete")
                self.assertEqual(evidence["next_destination"], next_url)
                self.assertEqual([hop["destination"] for hop in evidence["followed"]], visited[1:])
                self.assertEqual([hop["response_url"] for hop in evidence["followed"]], visited[:-1])
                self.assertEqual([hop["hop"] for hop in evidence["followed"]], list(range(1, limit + 1)))
                self.assertEqual([hop["http_status"] for hop in evidence["followed"]], [302, 301][:limit])
                self.assertEqual(rows[0]["settings"]["request_profile"]["redirect_limit"], limit)
                self.assertEqual(rows[0]["settings"]["max_redirects"], limit)
                self.assertNotIn("--max-redirs", self.fixture.calls()[0]["args"])

    def test_default_ten_long_finite_chain_and_cycle(self):
        urls = ["https://hop.example.test/" + str(i) for i in range(12)]
        chain = {url: {"code": 302, "location": following}
                 for url, following in zip([A] + urls[:-1], urls)}
        chain[urls[-1]] = {"code": 200}
        for args in ((), ("--max-redirects=10",)):
            rows, ends, contacts = self.scan(chain, *args)
            self.assertEqual(contacts[0]["contacts"], [A] + urls[:10])
            self.assertNotIn(urls[10], contacts[0]["contacts"])
            self.assertEqual(ends[0]["redirect_evidence"]["next_destination"], urls[10])
            self.assertEqual(rows[0]["settings"]["request_profile"]["redirect_limit"], 10)
        _, ends, contacts = self.scan(
            {A: {"code": 302, "location": B}, B: {"code": 302, "location": A}},
            "--max-redirects=1",
        )
        self.assertEqual(contacts[0]["contacts"], [A, B])
        self.assertEqual(ends[0]["redirect_evidence"]["next_destination"], A)
        self.assertNotIn("loop", ends[0]["detail"])

    def test_terminal_zero_and_supported_upper_bound(self):
        for option, expected in (("--max-redirects=000", 0), ("--max-redirects=100", 100)):
            rows, ends, contacts = self.scan({A: {"code": 200}}, option)
            self.assertEqual(contacts[0]["contacts"], [A])
            self.assertEqual(ends[0]["verdict"], "PASS")
            self.assertIsNone(ends[0]["stop_reason"])
            self.assertEqual(rows[0]["settings"]["request_profile"]["redirect_limit"], expected)

    def test_native_cutoff_metadata_is_authoritative_and_bounded(self):
        # Native metadata is independent of header reconstruction. In particular,
        # do not replace a missing native destination with a guessed Location.
        headers = b"HTTP/1.1 302\r\nLocation: /guessed\r\n\r\n"
        unavailable = self.evidence(headers)
        self.assertIsNone(unavailable["next_destination"])
        self.assertEqual(unavailable["next_destination_state"], "unavailable")
        native = self.evidence(headers, next_url=B)
        self.assertEqual(native["next_destination"], B)
        for next_url, expected in (("https://:synthetic-secret@b.example.test/", "available"),
                ("https://b.example.test/" + "x" * 9000, "truncated"),
                ("https://[broken", "invalid"), ("file:///tmp/example", "unsupported")):
            result = self.evidence(headers, next_url=next_url)
            self.assertEqual(result["next_destination_state"], expected)
            self.assertNotIn("synthetic-secret", json.dumps(result))
        _, ends, _ = self.scan({A: {"code": 302, "location": "/" + "x" * 9000}},
                               "--max-redirects=0")
        self.assertEqual(ends[0]["curl_exit"], 47)
        self.assertEqual(ends[0]["redirect_evidence"]["next_destination_state"], "truncated")
        self.assertNotIn("x" * 100, json.dumps(ends))

    def test_reconstruction_rejects_ambiguous_references_before_later_absolute_hop(self):
        # Terminal URL agreement cannot validate a wrong intermediate URL when
        # a later absolute Location rejoins the expected chain. Empty queries
        # before fragments also differ on supported Python 3.9's urljoin.
        for reference in ("///b.example.test/path", "#new", "?#new", "path?#new",
                          "next?", "next#", "https:other/path", "a//b",
                          "https:///b.example.test/path"):
            with self.subTest(reference=reference):
                value, state = SUBJECT.redirect_url(reference, A + "?original=1#old")
                self.assertIsNone(value)
                self.assertEqual(state, "unsupported")
                headers = ("HTTP/1.1 302\r\nLocation: " + reference
                           + "\r\n\r\nHTTP/1.1 300\r\nLocation: " + C
                           + "\r\n\r\nHTTP/1.1 200\r\n\r\n").encode()
                evidence = self.evidence(headers, count=2, code=200, exit_code=0, final_url=C)
                self.assertEqual(evidence["state"], "unsupported")
                self.assertEqual(evidence["followed"], [])

    def test_relative_destinations_and_nonredirect_header_blocks(self):
        path = "https://a.example.test/other/page"
        _, ends, contacts = self.scan({
            A: {"code": 302, "location": "/other/page",
                "prefix": "HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style>\r\n\r\n"},
            path: {"code": 307, "location": "../next?q=public#section"},
        }, "--max-redirects=1")
        self.assertEqual(contacts[0]["contacts"], [A, path])
        self.assertEqual(ends[0]["redirect_evidence"]["next_destination"],
                         "https://a.example.test/next?q=public#section")

    def test_fixed_trials_and_always_controls_preserve_schedules_and_routes(self):
        chain = {A: {"code": 302, "location": B}}
        for scope, count in (("target", 3), ("trial", 4)):
            _, ends, contacts = self.scan(chain, "--max-redirects=0", "--trials=2",
                                         "--control=always", "--control-scope=" + scope)
            self.assertEqual(len(ends), count)
            self.assertEqual({end["route"] for end in ends}, {"tor", "direct"})
            for call in contacts:
                self.assertEqual(call["contacts"], [A])
                self.assertEqual(call["args"][call["args"].index("--max-redirs") + 1], "0")
            self.assertTrue(all(end["stop_reason"] == "redirect_limit" for end in ends))
        _, ends, _ = self.scan(chain, "--max-redirects=0", "--trials=2",
                               "--control-scope=trial")
        self.assertEqual(len(ends), 2)  # fixed trials survive, conditional controls do not

    def test_redirect_userinfo_and_private_headers_never_exported(self):
        secret_url = "https://synthetic-user:synthetic-password@b.example.test/"
        stopped = "https://:synthetic-next-secret@c.example.test/?q=public#fragment"
        _, ends, _ = self.scan({
            A: {"code": 302, "location": secret_url,
                "headers": "Set-Cookie: synthetic-cookie\r\nAuthorization: synthetic-auth\r\n"},
            secret_url: {"code": 302, "location": stopped},
        }, "--max-redirects=1")
        serialized = json.dumps(ends)
        for marker in ("synthetic-user", "synthetic-password", "synthetic-next-secret",
                       "synthetic-cookie", "synthetic-auth", "Location:"):
            self.assertNotIn(marker, serialized)
        self.assertEqual(ends[0]["final_url"], B)
        evidence = ends[0]["redirect_evidence"]
        self.assertEqual(evidence["followed"][0]["destination"], B)
        self.assertEqual(evidence["next_destination"], C + "?q=public#fragment")

    def test_legacy_text_and_v1_contact_boundaries_and_contract(self):
        f = self.fixture
        f.input.write_text(A + "\n")
        chain = {A: {"code": 302, "location": B},
                 B: {"code": 302, "location": C}, C: {"code": 200}}
        for fmt in ("text", "jsonl"):
            for limit in (0, 1, 2, None):
                with self.subTest(fmt=fmt, limit=limit):
                    f.clear_logs()
                    args = [] if limit is None else ["--max-redirects", str(limit)]
                    result = subprocess.run(
                        [str(measurement.SCANNER), "--format", fmt, *args, str(f.input)],
                        env=dict(f.environment, MEASUREMENT_TEST_PLAN=json.dumps({A: [{"chain": chain}]})),
                        text=True, capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    contacts = f.calls("contacts")
                    self.assertEqual(len(contacts), 1)
                    visited = [A, B, C] if limit is None else [A, B, C][:limit + 1]
                    self.assertEqual(contacts[0]["contacts"], visited)
                    if fmt == "jsonl":
                        target, summary = map(json.loads, result.stdout.splitlines())
                        self.assertEqual(set(target), {"schema_version", "type", "target", "verdict", "detail",
                            "tor_attempts", "tor_attempt_limit", "clearnet_control", "tor_specific", "body_limited"})
                        self.assertEqual(target["schema_version"], 1)
                        self.assertEqual(summary["complete"], True)
                    if limit in (0, 1):
                        self.assertIn("subsequent access unobserved", result.stdout)
                        self.assertNotIn("loop", result.stdout)
                    self.assertNotIn("--max-redirs", f.calls()[0]["args"])

    def test_legacy_retry_and_control_use_selected_limit(self):
        f = self.fixture
        f.input.write_text(A + "\n")
        chain = {A: {"code": 302, "location": B}, B: {"code": 403}}
        result = subprocess.run(
            [str(measurement.SCANNER), "--format=jsonl", "--max-redirects=1", str(f.input)],
            env=dict(f.environment, MEASUREMENT_TEST_PLAN=json.dumps({A: [{"chain": chain}]})),
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = f.calls("contacts")
        self.assertEqual([call["route"] for call in calls], ["tor", "tor", "tor", "direct"])
        self.assertTrue(all(call["contacts"] == [A, B] for call in calls))

    def test_invalid_arguments_make_no_requests(self):
        f = self.fixture
        for fmt in ("text", "jsonl", "jsonl-v2"):
            for value in ("-1", "101", "unlimited", "1.5", "", "999999999999999999999999", "+1", "1e2"):
                for option in (["--max-redirects=" + value], ["--max-redirects", value]):
                    with self.subTest(fmt=fmt, option=option):
                        result = subprocess.run(
                            [str(measurement.SCANNER), "--format", fmt, *option, str(f.input)],
                            env=f.environment, text=True, capture_output=True, timeout=5,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("--max-redirects", result.stderr)
        self.assertEqual(f.calls(), [])

    def evidence(self, headers, count=0, code=302, exit_code=47, final_url=A, next_url=None):
        directory = self.fixture.temp / "evidence"
        directory.mkdir(exist_ok=True)
        (directory / "headers").write_bytes(headers)
        return SUBJECT.redirect_evidence(directory, A, dict(
            redirect_count=count, http_status=code, curl_exit=exit_code,
            final_url=final_url, next_redirect_url=next_url,
        ))

    def test_unavailable_invalid_unsupported_and_oversized_metadata(self):
        for location, expected in ((None, "absent"), (b"", "invalid"),
                (b"http://[broken", "invalid"), (b"javascript:alert(1)", "unsupported"),
                (b"/unsafe\x1bvalue", "invalid"), (b"/" + b"x" * 8192, "truncated"),
                (b"/bad\xff", "invalid"), (b"https://a.example.test:99999/", "invalid"),
                (b"/ok\r\nLocation: /other", "invalid")):
            with self.subTest(expected=expected, prefix=location and location[:30]):
                header = b"" if location is None else b"Location: " + location + b"\r\n"
                evidence = self.evidence(b"HTTP/1.1 302\r\n" + header + b"\r\n")
                self.assertEqual(evidence["next_destination_state"], expected)
                self.assertIsNone(evidence["next_destination"])
        self.assertEqual(self.evidence(b"")["state"], "unavailable")
        self.assertEqual(self.evidence(b"not HTTP\r\n\r\n")["state"], "invalid")
        mismatch = self.evidence(b"HTTP/1.1 302\r\nLocation: /b\r\n\r\n", count=1)
        self.assertEqual(mismatch["state"], "unavailable")
        self.assertEqual(mismatch["followed"], [])

    def test_evidence_read_and_serialized_bounds(self):
        url = b"/" + b"x" * 4000
        block = b"HTTP/1.1 302\r\nLocation: " + url + b"\r\n\r\n"
        evidence = self.evidence(block * 51, count=50,
                                 final_url="https://a.example.test/" + "x" * 4000)
        self.assertEqual(evidence["state"], "truncated")
        self.assertLess(len(evidence["followed"]), 50)
        self.assertLessEqual(len(json.dumps(evidence).encode()), SUBJECT.MAX_REDIRECT_EVIDENCE_BYTES)
        evidence = self.evidence(block * 101, count=100)
        self.assertEqual(evidence["state"], "truncated")
        self.assertEqual(evidence["next_destination_state"], "truncated")
        self.assertIsNone(evidence["next_destination"])

    def test_native_curl_cutoff_resolution_and_contact_boundary(self):
        # Unlike the fake, this fixture independently exercises curl's URL
        # resolution. All synthetic authorities are pinned to loopback, ambient
        # proxies are disabled, and the bridge uses direct routing (no Tor).
        contacts = []
        responses = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                contacts.append((self.headers["Host"], self.path))
                code, location = responses[self.path]
                self.send_response(code)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        class LoopbackServer(http.server.HTTPServer):
            def server_bind(self):
                # HTTPServer normally reverse-resolves its address here. Keep
                # even fixture setup independent of DNS and its timeout policy.
                socketserver.TCPServer.server_bind(self)
                self.server_name = "synthetic-loopback"
                self.server_port = self.server_address[1]

        server = LoopbackServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        port = server.server_port
        initial = "http://a.example.test:" + str(port) + "/start"
        native_curl = shutil.which("curl")
        wrapper = self.fixture.bin / "curl"
        wrapper.write_text(
            "#!" + sys.executable + "\nimport os,sys\n"
            + "os.execv(" + repr(native_curl) + ", [" + repr(native_curl)
            + ", '-q', '--noproxy', '*', '--resolve', "
            + repr("a.example.test:" + str(port) + ":127.0.0.1")
            + ", '--resolve', " + repr("b.example.test:" + str(port) + ":127.0.0.1")
            + "] + sys.argv[1:])\n"
        )
        wrapper.chmod(0o755)
        for limit, location, visited in (
            (0, "/middle", [("a.example.test:" + str(port), "/start")]),
            (0, "///b.example.test:" + str(port) + "/middle",
             [("a.example.test:" + str(port), "/start")]),
            (0, "#new", [("a.example.test:" + str(port), "/start")]),
            (0, "http://b.example.test:" + str(port) + "/unsafe\tvalue",
             [("a.example.test:" + str(port), "/start")]),
            (1, "/middle", [("a.example.test:" + str(port), "/start"),
                             ("a.example.test:" + str(port), "/middle")]),
            (1, "///b.example.test:" + str(port) + "/middle",
             [("a.example.test:" + str(port), "/start"),
              ("b.example.test:" + str(port), "/middle")]),
        ):
            with self.subTest(limit=limit, location=location):
                contacts.clear()
                responses.update({"/start": (302, location), "/middle": (399, "/never")})
                directory = self.fixture.temp / "native-request"
                directory.mkdir(exist_ok=True)
                process = subprocess.run(
                    ["zsh", str(measurement.ROOT / "check_tor_probe.zsh"),
                     str(directory), "direct", initial, "3", "1", "target"],
                    env=dict(self.fixture.environment, CHECK_TOR_MAX_REDIRECTS=str(limit)),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(process.stdout)
                self.assertEqual(result["curl_exit"], 47, result)
                self.assertEqual(contacts, visited)
                evidence = SUBJECT.redirect_evidence(directory, initial, result)
                if "\t" in location:
                    self.assertIn("\t", result["next_redirect_url"])
                    self.assertIsNone(evidence["next_destination"])
                    self.assertEqual(evidence["next_destination_state"], "invalid")
                    continue
                self.assertEqual(evidence["next_destination"], result["next_redirect_url"])
                self.assertEqual(evidence["next_destination_state"], "available")
                if limit == 1 and location.startswith("///"):
                    self.assertEqual(evidence["state"], "unsupported")
                    self.assertEqual(evidence["followed"], [])
                else:
                    self.assertEqual(evidence["state"], "complete")


if __name__ == "__main__":
    unittest.main()
