"""Offline checks: all curl traffic is replaced by a deterministic executable."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
HOSTS = [
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    "dv-g3b-noct-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com",
]
SOURCES = {
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
}
SAFE_PEM = (ROOT / "tests/fixtures/retained-root.pem").read_text()


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


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        self.environment_file = self.temp / "environment"
        self.workflow = (ROOT / ".github/workflows/offline-tests.yml").read_text()
        self.source = textwrap.dedent(self.workflow.split("          python3 - <<'PY'\n", 1)[1]
                                     .split("          PY\n", 1)[0])

    def bootstrap(self, content, missing=()):
        read_text = Path.read_text
        is_file = Path.is_file
        def fixture_read(path, *args, **kwargs):
            return content if str(path) in SOURCES else read_text(path, *args, **kwargs)
        def fixture_exists(path):
            return str(path) not in missing if str(path) in SOURCES else is_file(path)
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.temp), "GITHUB_ENV": str(self.environment_file)}), \
             patch.object(Path, "read_text", fixture_read), patch.object(Path, "is_file", fixture_exists), \
             contextlib.redirect_stdout(io.StringIO()):
            exec(compile(self.source, "workflow trust bootstrap", "exec"), {})

    def test_removes_both_real_roots_and_deduplicates_other_certificates(self):
        roots = (ROOT / "tests/fixtures/distrusted-roots.pem").read_text()
        self.bootstrap(roots + SAFE_PEM)
        bundle = self.temp / "check-tor-trust/cert.pem"
        self.assertEqual(bundle.read_text(), SAFE_PEM)
        settings = dict(line.split("=", 1) for line in self.environment_file.read_text().splitlines())
        self.assertEqual(settings["CURL_CA_BUNDLE"], str(bundle))
        self.assertEqual(settings["GIT_SSL_CAINFO"], str(bundle))
        self.assertEqual(settings["SSL_CERT_FILE"], str(bundle))
        self.assertEqual(list(Path(settings["SSL_CERT_DIR"]).iterdir()), [])
        self.assertNotIn("NODE_OPTIONS", settings)  # GITHUB_ENV rejects this name.

    def test_no_remaining_roots_fails_before_export(self):
        with self.assertRaisesRegex(SystemExit, "empty CA bundle"):
            self.bootstrap((ROOT / "tests/fixtures/distrusted-roots.pem").read_text())
        self.assertFalse(self.environment_file.exists())

    def test_malformed_bundle_fails_before_export(self):
        with self.assertRaises(SystemExit):
            self.bootstrap("not a certificate")
        self.assertFalse(self.environment_file.exists())

    def test_missing_required_apple_bundle_fails_before_export(self):
        with self.assertRaisesRegex(SystemExit, "Required Apple CA bundle is missing"):
            self.bootstrap(SAFE_PEM, missing=("/etc/ssl/cert.pem",))
        self.assertFalse(self.environment_file.exists())

    def test_incomplete_pem_blocks_fail_before_export(self):
        for fragment in ("-----BEGIN CERTIFICATE-----\nYWJj\n", "-----END CERTIFICATE-----\n"):
            with self.subTest(fragment=fragment):
                with self.assertRaisesRegex(SystemExit, "Incomplete certificate block"):
                    self.bootstrap(SAFE_PEM + fragment)
                self.assertFalse(self.environment_file.exists())

    def test_invalid_retained_der_fails_before_export(self):
        invalid = ("-----BEGIN CERTIFICATE-----\n"
                   + base64.b64encode(b"not an X.509 certificate").decode()
                   + "\n-----END CERTIFICATE-----\n")
        with self.assertRaises(ssl.SSLError):
            self.bootstrap(SAFE_PEM + invalid)
        self.assertFalse(self.environment_file.exists())

    def test_bootstrap_and_negative_controls_precede_checkout(self):
        names = ["Prepare restricted macOS trust", "Verify macOS trust before checkout", "Check out repository"]
        offsets = [self.workflow.index(name) for name in names]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("NODE_OPTIONS: ${{ runner.os == 'macOS' && '--use-openssl-ca' || '' }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        for host in HOSTS:
            self.assertIn(host, self.workflow)


if __name__ == "__main__":
    unittest.main()
