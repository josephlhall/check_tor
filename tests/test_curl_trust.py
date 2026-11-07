"""Offline checks for the measurement curl trust preflight using fake curl."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parent.parent
HOSTS = [
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    "dv-g3b-noct-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com",
]


class CurlTrustTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        self.log = self.temp / "requests.jsonl"
        fake = self.temp / "curl"
        fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent("""
            import json, os, sys
            with open(os.environ["TRUST_TEST_LOG"], "a") as log:
                log.write(json.dumps(sys.argv[1:]) + "\\n")
            url = sys.argv[-1]
            if url == "https://github.com/":
                sys.exit(int(os.environ.get("TRUST_TEST_POSITIVE_RC", "0")))
            if url == os.environ.get("TRUST_TEST_FAILURE_URL"):
                sys.exit(int(os.environ.get("TRUST_TEST_FAILURE_RC", "0")))
            sys.exit(60)
        """))
        fake.chmod(0o755)
        self.environment = {**os.environ, "PATH": str(self.temp) + os.pathsep + os.environ["PATH"],
                            "TRUST_TEST_LOG": str(self.log)}

    def run_checker(self, *arguments, **settings):
        return subprocess.run([shutil.which("zsh"), str(ROOT / "scripts/check-curl-trust.zsh"), *arguments],
                              env={**self.environment, **settings}, text=True, capture_output=True,
                              timeout=10, check=False)

    def test_success_uses_actual_curl_without_replacing_trust(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call[-1] for call in calls],
                         ["https://github.com/", *[f"https://{host}/" for host in HOSTS]])
        for call in calls:
            self.assertEqual(call[0], "-q")
            self.assertNotIn("--cacert", call)
            self.assertNotIn("--insecure", call)
            self.assertIn("--max-time", call)
        self.assertIn(str(self.temp / "curl"), result.stdout)

    def test_every_negative_control_must_reject_its_certificate(self):
        for host in HOSTS:
            for code in (0, 5, 6, 7, 28, 35, 77):
                with self.subTest(host=host, code=code):
                    result = self.run_checker(TRUST_TEST_FAILURE_URL=f"https://{host}/",
                                              TRUST_TEST_FAILURE_RC=str(code))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("expected certificate rejection (60)", result.stderr)

    def test_positive_control_failure_does_not_count_as_rejection(self):
        result = self.run_checker(TRUST_TEST_POSITIVE_RC="60")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive control failed", result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_help_and_invalid_arguments_make_no_requests(self):
        self.assertEqual(self.run_checker("--help").returncode, 0)
        self.assertNotEqual(self.run_checker("unexpected").returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
