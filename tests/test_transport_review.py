"""Offline regressions for literal URLs and unavailable response inspection."""

import json
import os
import shutil
import subprocess
import sys
import unittest

import test_measurement as measurement


class TransportReviewTests(unittest.TestCase):
    def setUp(self):
        # Reuse the fake transport fixture without inheriting its test cases.
        self.fixture = measurement.MeasurementTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_real_curl_reads_literal_url_glob_characters_once(self):
        fixture = self.fixture
        for filename in ("fixture{one,two}.txt", "fixture[1-2].txt"):
            for reproducible in ("0", "1"):
                with self.subTest(filename=filename, reproducible=reproducible):
                    literal = fixture.temp / filename
                    literal.write_text("the literal URL response")
                    for expanded in (
                        "fixtureone.txt",
                        "fixturetwo.txt",
                        "fixture1.txt",
                        "fixture2.txt",
                    ):
                        (fixture.temp / expanded).write_text(
                            "incorrect expanded response"
                        )
                    request = fixture.temp / ("probe-" + filename + reproducible)
                    request.mkdir()
                    # Invoke the real installed curl through the bridge, using
                    # only file:// fixtures. No Tor or network service runs.
                    result = subprocess.run(
                        [
                            shutil.which("zsh"),
                            str(measurement.ROOT / "check_tor_probe.zsh"),
                            str(request),
                            "direct",
                            "file://" + str(literal),
                            "3",
                            reproducible,
                            "target",
                        ],
                        env=os.environ.copy(),
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    record = json.loads(result.stdout)
                    self.assertEqual(record["curl_exit"], 0, record)
                    self.assertIsNone(record["local_error"])
                    self.assertEqual(record["final_url"], "file://" + str(literal))
                    self.assertEqual(
                        (request / "body").read_text(), "the literal URL response"
                    )

    def test_globoff_is_in_v2_requests_and_effective_profile(self):
        fixture = self.fixture
        for arguments in (("--circuits", "1"), ("--trials", "1")):
            with self.subTest(arguments=arguments):
                fixture.clear_logs()
                status, rows, error = fixture.run_scan(
                    *arguments,
                    "--control",
                    "always",
                    targets=["https://alpha.example.test/{one,two}/[1-2]"],
                )
                self.assertEqual(status, 0, error)
                self.assertEqual(
                    rows[0]["settings"]["request_profile"]["url_globbing"], "disabled"
                )
                calls = [
                    call
                    for call in fixture.calls()
                    if call["url"] != measurement.PREFLIGHT
                ]
                self.assertEqual(len(calls), 2)
                for call in calls:
                    self.assertIn("--globoff", call["args"])
                    self.assertEqual(call["args"][0], "-q")
                fixture.assert_accounting(rows)
                fixture.assert_clean()

    def test_classifier_grep_errors_preserve_facts_and_stop_schedule(self):
        fixture = self.fixture
        executable = shutil.which("grep")
        failures = [
            ("-aom1", "error code: 1[0-9]{3}", "Just a moment", ""),
            ("-qia", "^cf-mitigated:.*challenge", "Just a moment", ""),
            ("-qa", "Just a moment", "Just a moment", ""),
            ("-qa", "cf-chl", "cf-chl synthetic challenge", ""),
            ("-qia", "^cf-error-type:", "", "cf-error-type: synthetic\r\n"),
            ("-aim1", "^cf-error-type:", "", "cf-error-type: synthetic\r\n"),
            ("-qia", "^cf-ray:", "", "cf-ray: synthetic\r\n"),
            ("-qia", "AkamaiGHost", "", "Server: AkamaiGHost\r\n"),
            ("-qiaE", "^x-sucuri-(id|cache):", "", "x-sucuri-id: synthetic\r\n"),
            ("-qia", "^x-iinfo:", "", "x-iinfo: synthetic\r\n"),
            ("-qia", "incap_ses", "", "Set-Cookie: incap_ses=synthetic\r\n"),
        ]
        for option, pattern, body, headers in failures:
            with self.subTest(option=option, pattern=pattern):
                fixture.clear_logs()
                wrapper = fixture.bin / "grep"
                wrapper.write_text(
                    "#!"
                    + sys.executable
                    + "\nimport subprocess,sys\n"
                    + "if "
                    + repr(option)
                    + " in sys.argv[1:] and "
                    + repr(pattern)
                    + " in sys.argv[1:]:\n"
                    + "    sys.exit(2)\n"
                    + "sys.exit(subprocess.run(["
                    + repr(executable)
                    + "] + sys.argv[1:], check=False).returncode)\n"
                )
                wrapper.chmod(0o755)
                try:
                    status, rows, error = fixture.run_scan(
                        "--trials",
                        "2",
                        "--control",
                        "always",
                        targets=["alpha.example.test", "must-not-run.example.test"],
                        plan={
                            "https://alpha.example.test": [
                                {"body": body, "headers": headers}
                            ]
                        },
                    )
                finally:
                    wrapper.unlink()
                self.assertNotEqual(status, 0, error)
                self.assertEqual(
                    [call["url"] for call in fixture.calls()],
                    [measurement.PREFLIGHT, "https://alpha.example.test"],
                )
                attempts = fixture.select(rows, "attempt_end", "target")
                self.assertEqual(len(attempts), 1)
                attempt = attempts[0]
                self.assertEqual(attempt["status"], "error")
                self.assertIs(attempt["complete"], False)
                self.assertIsNone(attempt["verdict"])
                self.assertIsNone(attempt["detail"])
                self.assertEqual(
                    attempt["local_error"], "local_response_processing_failed"
                )
                self.assertEqual(attempt["http_status"], 200)
                self.assertEqual(attempt["curl_exit"], 0)
                self.assertEqual(attempt["final_url"], "https://alpha.example.test")
                self.assertEqual(attempt["redirect_count"], 0)
                self.assertIs(attempt["body_limited"], False)
                end = fixture.assert_accounting(rows)
                self.assertEqual(end["state"], "error")
                self.assertEqual(end["counts"]["target"], {"issued": 1, "completed": 0})
                fixture.assert_clean()


if __name__ == "__main__":
    unittest.main()
