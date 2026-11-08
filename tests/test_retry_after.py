"""Deterministic private-header Retry-After evidence; no live network access."""

import contextlib
import datetime
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import test_measurement as measurement

SPEC = importlib.util.spec_from_file_location(
    "retry_after_subject", measurement.ROOT / "check_tor_retry.py"
)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)
A = "https://a.example.test/"
B = "https://b.example.test/next"
ENDED = "2026-11-07T12:00:00.250Z"


class RetryAfterTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="check-tor-retry-tests-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def evidence(self, value=b"60", headers=None, **native):
        if headers is None:
            field = b"" if value is None else b"Retry-After: " + value + b"\r\n"
            headers = b"HTTP/2 429\r\n" + field + b"\r\n"
        (self.directory / "headers").write_bytes(headers)
        result = dict(http_status=429, redirect_count=0, final_url=A, curl_exit=0)
        ended_at = native.pop("ended_at", ENDED)
        result.update(native)
        return SUBJECT.retry_after_evidence(self.directory, A, result, ended_at)

    def assert_reason(self, evidence, state, reason):
        self.assertEqual((evidence["state"], evidence["reason"]), (state, reason))
        self.assertNotIn("wait_seconds", evidence)

    def test_delay_zero_and_maximum_are_completion_relative(self):
        for raw, expected in ((b"0", 0), (b"00060", 60), (b"2147483647", 2147483647)):
            with self.subTest(raw=raw):
                evidence = self.evidence(raw)
                self.assertEqual(evidence["state"], "usable")
                self.assertEqual(evidence["wait_seconds"], expected)
                self.assertEqual(evidence["reference_time_utc"], ENDED)
                self.assertEqual(evidence["form"], "delay_seconds")
                self.assertEqual(evidence["units"], "seconds")
                self.assertEqual(evidence["reference_basis"], "observation_completion_conservative")
                self.assertEqual(evidence["clock_uncertainty"], "receipt_precedes_completion")

    def test_all_standard_http_date_forms_and_fractional_completion(self):
        for raw in (b"Sat, 07 Nov 2026 12:01:00 GMT",
                    b"Saturday, 07-Nov-26 12:01:00 GMT",
                    b"Sat Nov  7 12:01:00 2026"):
            with self.subTest(raw=raw):
                evidence = self.evidence(raw)
                self.assertEqual(evidence["state"], "usable")
                self.assertEqual(evidence["form"], "http_date")
                self.assertEqual(evidence["wait_seconds"], 60)  # ceil(59.750)
                self.assertEqual(evidence["not_before_utc"], "2026-11-07T12:01:00Z")
                self.assertFalse(evidence["past_date"])
                self.assertEqual(evidence["reference_basis"], "local_observation_completion_clock")
                self.assertEqual(evidence["clock_uncertainty"], "local_server_clock_offset_unknown")

    def test_past_and_equal_dates_do_not_promise_request_success(self):
        for date, past in ((b"Sat, 07 Nov 2026 11:59:00 GMT", True),
                           (b"Sat, 07 Nov 2026 12:00:00 GMT", False)):
            evidence = self.evidence(date, ended_at="2026-11-07T12:00:00Z")
            self.assertEqual(evidence["wait_seconds"], 0)
            self.assertEqual(evidence["past_date"], past)
            self.assertEqual(evidence["reason"], "past_date" if past else "valid_date")

    def test_obsolete_two_digit_year_uses_http_fifty_year_rule(self):
        evidence = self.evidence(b"Sunday, 06-Nov-94 08:49:37 GMT")
        self.assertEqual(evidence["not_before_utc"], "1994-11-06T08:49:37Z")
        evidence = self.evidence(b"Wednesday, 06-Nov-75 08:49:37 GMT")
        self.assertEqual(evidence["not_before_utc"], "2075-11-06T08:49:37Z")
        # Weekdays are not an independent clock: stdlib parsing accepts them.
        self.assertEqual(evidence["state"], "usable")
        evidence = self.evidence(b"Sunday, 08-Nov-76 08:49:37 GMT")
        self.assertEqual(evidence["not_before_utc"], "1976-11-08T08:49:37Z")

    def test_obsolete_year_crosses_century_relative_to_completion(self):
        for completion_year, expected_year in ((1994, 2006), (2094, 2106)):
            reference = datetime.datetime(completion_year, 1, 1, tzinfo=datetime.timezone.utc)
            parsed, reason = SUBJECT._date("Sunday, 01-Jan-06 00:00:00 GMT", reference)
            self.assertIsNone(reason)
            self.assertEqual(parsed.year, expected_year)

    def test_malformed_values_are_not_waits(self):
        for value in (b"", b"-1", b"+1", b"1.5", b"1e3", b"0x10", b"60, 120",
                      b"Sat, 7 Nov 2026 12:01:00 GMT", b"Sat, 07 Nov 2026 12:01:00 UTC",
                      b"Sat, 07 Nov 2026 12:01:00 +0000", b"\xff", b"secret-sentinel"):
            with self.subTest(value=value):
                self.assert_reason(self.evidence(value), "invalid", "malformed_syntax")

    def test_numeric_and_date_overflow_have_distinct_reasons(self):
        for value in (b"2147483648", b"9" * 256):
            self.assert_reason(self.evidence(value), "invalid", "numeric_overflow")
        self.assert_reason(self.evidence(b"Sat, 07 Nov 0000 12:01:00 GMT"),
                           "invalid", "date_overflow")
        self.assert_reason(self.evidence(b"Sat, 31 Feb 2026 12:01:00 GMT"),
                           "invalid", "invalid_date")
        self.assert_reason(self.evidence(b"Fri, 31 Dec 9999 23:59:59 GMT"),
                           "invalid", "date_wait_overflow")

    def test_503_has_evidence_other_statuses_do_not_read_headers(self):
        self.assertEqual(self.evidence(headers=b"HTTP/2 503\r\nRetry-After: 20\r\n\r\n",
                                       http_status=503)["wait_seconds"], 20)
        for code in (200, 302, 403, 500, None):
            self.assert_reason(self.evidence(http_status=code), "not_applicable", "http_status")

    def test_absent_and_missing_are_distinct(self):
        self.assert_reason(self.evidence(None), "absent", "field_absent")
        result = dict(http_status=429, redirect_count=0, final_url=A)
        (self.directory / "headers").unlink()
        missing = SUBJECT.retry_after_evidence(self.directory, A, result, ENDED)
        self.assert_reason(missing, "unavailable", "headers_unavailable")
        self.assert_reason(self.evidence(headers=b""), "unavailable", "headers_unavailable")

    def test_completion_clock_cannot_be_replaced_by_plausible_zero(self):
        for ended_at in (None, "secret-sentinel", "2026-11-07T12:00:00", "9" * 100):
            for value in (b"60", b"Sat, 07 Nov 2026 12:01:00 GMT"):
                self.assert_reason(self.evidence(value, ended_at=ended_at),
                                   "unavailable", "completion_clock_unavailable")
        evidence = self.evidence(ended_at="2026-11-07T07:00:00.250-05:00")
        self.assertEqual(evidence["reference_time_utc"], ENDED)

    def test_interim_connect_and_previous_redirect_retry_are_ignored(self):
        prefix = (b"HTTP/1.1 200 Connection established\r\nRetry-After: 900\r\n\r\n"
                  b"HTTP/1.1 103 Early Hints\r\nRetry-After: 800\r\n\r\n"
                  b"HTTP/1.1 302 Found\r\nLocation: " + B.encode() +
                  b"\r\nRetry-After: 700\r\n\r\nHTTP/2 100\r\n\r\n")
        final = b"HTTP/2 429\r\nRetry-After: 60\r\n\r\n"
        evidence = self.evidence(headers=prefix + final, redirect_count=1, final_url=B)
        self.assertEqual(evidence["wait_seconds"], 60)
        evidence = self.evidence(headers=prefix + b"HTTP/2 429\r\n\r\n",
                                 redirect_count=1, final_url=B)
        self.assert_reason(evidence, "absent", "field_absent")

    def test_native_facts_and_complete_final_block_are_required(self):
        self.assert_reason(self.evidence(headers=b"HTTP/2 503\r\nRetry-After: 60\r\n\r\n"),
                           "invalid", "final_status_mismatch")
        self.assert_reason(self.evidence(final_url=B), "invalid", "final_url_mismatch")
        self.assert_reason(self.evidence(redirect_count=1), "unavailable", "response_count_mismatch")
        for count in (None, -1, 101, True, "0"):
            self.assert_reason(self.evidence(redirect_count=count), "unavailable", "native_redirect_count")
        for url in (None, "http://[broken", "https://a.example.test:99999/", "x" * 9000, "https://a.example.test/\ud800"):
            self.assert_reason(self.evidence(final_url=url), "unavailable", "native_url_unavailable")
        for raw in (b"HTTP/2 429\r\nRetry-After: 60", b"HTTP/2 429\r\n\r\nHTTP/2 429"):
            self.assert_reason(self.evidence(headers=raw), "unavailable", "incomplete_final_block")

    def test_redirect_metadata_cannot_invent_final_visited_response(self):
        prefix = b"HTTP/2 302\r\nLocation: /wrong\r\nRetry-After: 500\r\n\r\n"
        final = b"HTTP/2 429\r\nRetry-After: 60\r\n\r\n"
        self.assert_reason(self.evidence(headers=prefix + final, redirect_count=1, final_url=B),
                           "invalid", "final_url_mismatch")
        prefix = b"HTTP/2 302\r\nLocation: /next\r\n\r\n"
        evidence = self.evidence(headers=prefix + final, redirect_count=1,
                                 final_url="https://a.example.test/next")
        self.assertEqual(evidence["state"], "usable")
        evidence = self.evidence(headers=prefix + final)  # native says no follow
        self.assert_reason(evidence, "unavailable", "response_count_mismatch")

    def test_resolved_url_bound_applies_before_a_later_short_redirect(self):
        raw = b"".join(
            b"HTTP/1.1 302 Found\r\nLocation: " + location + b"\r\n\r\n"
            for location in (b"/" + b"a" * 4500 + b"/", b"b" * 4500 + b"/", b"/end")
        )
        raw += b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n\r\n"
        self.assert_reason(
            self.evidence(headers=raw, redirect_count=3, final_url=A + "end"),
            "unavailable", "redirect_chain_unavailable",
        )

    def test_duplicate_conflicting_folded_and_hostile_fields(self):
        for value in (b"60", b"70"):
            raw = b"HTTP/2 429\r\nRetry-After: 60\r\nrEtRy-AfTeR: " + value + b"\r\n\r\n"
            self.assert_reason(self.evidence(headers=raw), "invalid", "duplicate_fields")
        for field in (b"Retry-After: 60\r\n continuation", b"Retry-After : 60",
                      b"Retry-After: 6\x000", b"Retry-After: 6\x1b0", b"Retry-After: 6\r0"):
            evidence = self.evidence(headers=b"HTTP/2 429\r\n" + field + b"\r\n\r\n")
            self.assertEqual(evidence["state"], "invalid")
            self.assertNotIn("wait_seconds", evidence)

    def test_finite_capture_value_block_line_and_serialized_bounds(self):
        bound = SUBJECT.BOUNDS
        self.assert_reason(self.evidence(b"0" * (bound["value_bytes"] + 1)),
                           "truncated", "value_bytes_limit")
        self.assertEqual(self.evidence(b"0" * bound["value_bytes"])["wait_seconds"], 0)
        self.assert_reason(self.evidence(headers=b"x" * (bound["header_bytes"] + 1)),
                           "truncated", "header_bytes_limit")
        interim = b"HTTP/2 100\r\n\r\n"
        final = b"HTTP/2 429\r\nRetry-After: 60\r\n\r\n"
        self.assertEqual(self.evidence(headers=interim * (bound["response_blocks"] - 1) + final)["state"], "usable")
        self.assert_reason(self.evidence(headers=interim * bound["response_blocks"] + final),
                           "truncated", "response_blocks_limit")
        raw = b"HTTP/2 429\r\n" + b"X: x\r\n" * bound["header_lines"] + b"\r\n"
        self.assert_reason(self.evidence(headers=raw), "truncated", "header_lines_limit")
        with mock.patch.dict(SUBJECT.BOUNDS, evidence_bytes=1):
            self.assert_reason(self.evidence(), "truncated", "serialized_evidence_limit")

    def test_bounded_read_even_with_large_private_file(self):
        reader = mock.MagicMock()
        reader.__enter__.return_value.read.return_value = b"x" * (SUBJECT.BOUNDS["header_bytes"] + 1)
        with mock.patch.object(Path, "open", return_value=reader):
            result = dict(http_status=429, redirect_count=0, final_url=A)
            evidence = SUBJECT.retry_after_evidence(self.directory, A, result, ENDED)
        reader.__enter__.return_value.read.assert_called_once_with(SUBJECT.BOUNDS["header_bytes"] + 1)
        self.assertEqual(evidence["state"], "truncated")

    def test_private_values_and_other_headers_never_leave_evidence(self):
        secret = b"synthetic-private-sentinel"
        raw = (b"HTTP/2 429\r\nRetry-After: " + secret + b"\r\nSet-Cookie: " + secret
               + b"\r\nAuthorization: " + secret + b"\r\n\r\n")
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            evidence = self.evidence(headers=raw)
        retained = json.dumps(evidence) + output.getvalue() + error.getvalue()
        for marker in (secret.decode(), "Retry-After:", "Set-Cookie:", "Authorization:"):
            self.assertNotIn(marker, retained)
        self.assertLessEqual(len(json.dumps(evidence).encode()), SUBJECT.BOUNDS["evidence_bytes"])


class RetryAfterProbeTests(unittest.TestCase):
    """Exercise real shell/header capture with the existing synthetic curl."""

    def setUp(self):
        self.fixture = measurement.MeasurementTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_both_routes_capture_final_retry_and_keep_private_headers_private(self):
        f = self.fixture
        secret = "synthetic-private-sentinel"
        for route in ("tor", "direct"):
            for code in (429, 503):
                with self.subTest(route=route, code=code):
                    directory = f.temp / (route + str(code))
                    directory.mkdir()
                    chain = {A: {"code": 302, "location": B, "headers": "Retry-After: 999\r\n"},
                             B: {"code": code, "headers": "Retry-After: 60\r\nSet-Cookie: " + secret + "\r\n"}}
                    result = subprocess.run(
                        ["zsh", str(measurement.ROOT / "check_tor_probe.zsh"), str(directory),
                         route, A, "5", "1", "target"],
                        env=dict(f.environment, MEASUREMENT_TEST_PLAN=json.dumps({A: [{"chain": chain}]})),
                        text=True, capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    native = json.loads(result.stdout)
                    self.assertEqual(native["http_status"], code)
                    self.assertEqual(native["final_url"], B)
                    evidence = SUBJECT.retry_after_evidence(directory, A, native, ENDED)
                    self.assertEqual(evidence["state"], "usable")
                    self.assertEqual(evidence["wait_seconds"], 60)
                    for retained in (result.stdout, result.stderr, json.dumps(evidence)):
                        self.assertNotIn(secret, retained)
                        self.assertNotIn("Retry-After:", retained)
                    self.assertEqual(f.calls("contacts")[-1]["contacts"], [A, B])


    def test_coordinator_retains_evidence_and_policy_is_independent(self):
        f = self.fixture
        for policy in ("legacy", "paired-cautious"):
            for route in ("tor", "direct"):
                for code in (429, 503):
                    with self.subTest(policy=policy, route=route, code=code):
                        f.clear_logs()
                        secret = "synthetic-retry-secret"
                        status, rows, error = f.run_scan(
                            "--execution-policy", policy, "--trials", 2,
                            "--control", "always", "--control-scope", "trial",
                            targets=[A], plan={A + "|" + route: [{
                                "code": code, "headers": "Retry-After: 30\r\nSet-Cookie: " + secret + "\r\n"
                            }]},
                        )
                        stopped = policy == "paired-cautious" and code == 429
                        self.assertEqual(status, 3 if stopped else 0, error)
                        ends = f.select(rows, "attempt_end", "target")
                        triggering = next(r for r in ends if r["http_status"] == code)
                        evidence = triggering["retry_after"]
                        self.assertEqual(evidence["state"], "usable")
                        self.assertEqual(evidence["wait_seconds"], 30)
                        self.assertEqual(
                            datetime.datetime.fromisoformat(evidence["reference_time_utc"].replace("Z", "+00:00")),
                            datetime.datetime.fromisoformat(triggering["ended_at"].replace("Z", "+00:00")),
                        )
                        self.assertEqual(rows[0]["settings"]["retry_after_bounds"], SUBJECT.BOUNDS)
                        self.assertNotIn(secret, json.dumps(rows) + error)
                        self.assertNotIn("Retry-After:", json.dumps(rows) + error)
                        f.assert_accounting(rows)
                        f.assert_clean()


if __name__ == "__main__":
    unittest.main()
