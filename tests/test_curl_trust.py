"""Offline checks: curl and Git traffic use deterministic fake executables."""
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


class GitTrustTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        self.log = self.temp / "git-queries.jsonl"
        self.responses = self.temp / "responses.json"
        self.responses.write_text("{}")
        self.fake = self.temp / "git"
        self.fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""
            import json, os, sys
            from pathlib import Path
            with open({str(self.log)!r}, "a") as log:
                log.write(json.dumps({{"argv": sys.argv[1:], "env": dict(os.environ), "cwd": os.getcwd()}}) + "\\n")
            remote = sys.argv[-2]
            response = json.loads(Path({str(self.responses)!r}).read_text()).get(remote)
            if response is None:
                response = [0, ""] if remote.startswith("https://github.com/") else [
                    128, f"fatal: unable to access '{{remote}}/': SSL certificate problem: unable to get local issuer certificate"]
            print(response[1], file=sys.stderr)
            sys.exit(response[0])
        """))
        self.fake.chmod(0o755)
        workflow = (ROOT / ".github/workflows/offline-tests.yml").read_text()
        source = textwrap.dedent(workflow.split("          python3 - <<'PYGITTRUST'\n", 1)[1]
                                 .split("          PYGITTRUST\n", 1)[0])
        self.guard = {"__name__": "git_trust_test"}
        exec(compile(source, "workflow Git trust controls", "exec"), self.guard)
        self.environment = {
            "PATH": str(self.temp) + os.pathsep + os.environ["PATH"],
            "GIT_SSL_CAINFO": str(self.temp / "cert.pem"), "GIT_SSL_CAPATH": str(self.temp / "empty"),
            "SSL_CERT_FILE": str(self.temp / "cert.pem"), "SSL_CERT_DIR": str(self.temp / "empty"),
            "NODE_OPTIONS": "--use-openssl-ca",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader", "GIT_CONFIG_VALUE_0": "synthetic",
            "GIT_SSL_NO_VERIFY": "1", "GIT_EXEC_PATH": "synthetic", "HTTPS_PROXY": "synthetic",
            "https_proxy": "synthetic", "ALL_PROXY": "synthetic", "GIT_ASKPASS": "synthetic",
        }

    def run_guard(self):
        with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(io.StringIO()):
            self.guard["main"]()

    def test_selected_git_rejects_all_chains_without_ambient_credentials_or_config(self):
        self.run_guard()
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call["argv"][-2] for call in calls],
                         ["https://github.com/git/git.git", *[f"https://{host}/check.git" for host in HOSTS]])
        for call in calls:
            env, argv = call["env"], call["argv"]
            self.assertEqual(env["GIT_SSL_CAINFO"], self.environment["GIT_SSL_CAINFO"])
            self.assertEqual(env["GIT_SSL_CAPATH"], self.environment["GIT_SSL_CAPATH"])
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(env["GIT_CONFIG_SYSTEM"], "/dev/null")
            self.assertEqual(env["GIT_CONFIG_COUNT"], "0")
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["GIT_ASKPASS"], "/usr/bin/false")
            self.assertEqual(Path(env["HOME"]).resolve(), Path(call["cwd"]).resolve())
            self.assertNotEqual(env["HOME"], os.environ["HOME"])
            for key in ("GIT_SSL_NO_VERIFY", "GIT_EXEC_PATH", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                        "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "NODE_OPTIONS"):
                self.assertNotIn(key, env)
            for setting in ("credential.helper=", "http.extraHeader=", "http.proxy=", "http.sslVerify=true",
                            "http.followRedirects=false"):
                self.assertIn(setting, argv)
            self.assertEqual(argv[-1], "HEAD")

    def test_acceptance_and_noncertificate_errors_fail_closed(self):
        for host in HOSTS:
            remote = f"https://{host}/check.git"
            for code, diagnostic in ((0, ""), (128, "Could not resolve host"), (128, "Failed to connect"),
                                     (128, "Authentication failed"), (128, "The requested URL returned error: 404"),
                                     (128, "The requested URL returned error: 302"),
                                     (128, "remote: SSL certificate problem: spoofed server text"),
                                     (128, f"remote: fatal: unable to access '{remote}': SSL certificate problem: spoofed"),
                                     (1, f"fatal: unable to access '{remote}': SSL certificate problem: issuer")):
                with self.subTest(host=host, code=code, diagnostic=diagnostic):
                    self.responses.write_text(json.dumps({remote: [code, diagnostic]}))
                    with self.assertRaisesRegex(SystemExit, "expected certificate rejection"):
                        self.run_guard()

    def test_positive_failure_and_timeouts_are_not_rejection(self):
        self.responses.write_text(json.dumps({"https://github.com/git/git.git": [128, "SSL certificate problem"]}))
        with self.assertRaisesRegex(SystemExit, "positive control failed"):
            self.run_guard()
        with patch.object(self.guard["subprocess"], "run", side_effect=subprocess.TimeoutExpired("git", 30)):
            with self.assertRaisesRegex(SystemExit, "timed out"):
                self.run_guard()

    def test_gnutls_certificate_diagnostic_is_accepted(self):
        remote = f"https://{HOSTS[0]}/check.git"
        self.responses.write_text(json.dumps({remote: [128, f"fatal: unable to access '{remote}/': server certificate verification failed. CAfile: test"]}))
        self.run_guard()

    def test_openssl_verify_result_requires_nonzero_code_and_matching_fatal_line(self):
        remote = f"https://{HOSTS[0]}/check.git"
        genuine = f"fatal: unable to access '{remote}/': SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)"
        self.responses.write_text(json.dumps({remote: [128, genuine]}))
        self.run_guard()
        for code, diagnostic in (
            (0, genuine), (1, genuine), (128, genuine.replace("(20)", "(0)")),
            (128, genuine.replace("(20)", "(unknown)")),
            (128, "remote: " + genuine), (128, genuine.replace(HOSTS[0], "other.example.test")),
            (128, genuine + "server content"),
        ):
            with self.subTest(code=code, diagnostic=diagnostic):
                self.responses.write_text(json.dumps({remote: [code, diagnostic]}))
                with self.assertRaisesRegex(SystemExit, "expected certificate rejection"):
                    self.run_guard()

    def test_missing_git_refuses_without_queries(self):
        with patch.object(self.guard["shutil"], "which", return_value=None):
            with self.assertRaisesRegex(SystemExit, "Git is unavailable"):
                self.run_guard()
        self.assertFalse(self.log.exists())


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        self.environment_file = self.temp / "environment"
        self.output_file = self.temp / "output"
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
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.temp), "GITHUB_ENV": str(self.environment_file),
                                     "GITHUB_OUTPUT": str(self.output_file)}), \
             patch.object(Path, "read_text", fixture_read), patch.object(Path, "is_file", fixture_exists), \
             contextlib.redirect_stdout(io.StringIO()):
            exec(compile(self.source, "workflow trust bootstrap", "exec"), {})

    def test_removes_both_real_roots_and_deduplicates_other_certificates(self):
        roots = (ROOT / "tests/fixtures/distrusted-roots.pem").read_text()
        self.bootstrap(roots + SAFE_PEM)
        bundle = self.temp / "check-tor-trust/cert.pem"
        self.assertEqual(bundle.read_text(), SAFE_PEM)
        capath = bundle.parent / "empty-ca-directory"
        name, settings = self.output_file.read_text().strip().split("=", 1)
        self.assertEqual(name, "checkout_env")
        self.assertEqual(json.loads(settings), {
            "SSL_CERT_FILE": str(bundle),
            "SSL_CERT_DIR": str(capath),
            "GIT_SSL_CAINFO": str(bundle),
            "GIT_SSL_CAPATH": str(capath),
            "NODE_OPTIONS": "--use-openssl-ca",
        })
        self.assertEqual(list(capath.iterdir()), [])
        self.assertFalse(self.environment_file.exists())

    def test_no_remaining_roots_fails_before_output(self):
        with self.assertRaisesRegex(SystemExit, "empty CA bundle"):
            self.bootstrap((ROOT / "tests/fixtures/distrusted-roots.pem").read_text())
        self.assertFalse(self.output_file.exists())

    def test_malformed_bundle_fails_before_output(self):
        with self.assertRaises(SystemExit):
            self.bootstrap("not a certificate")
        self.assertFalse(self.output_file.exists())

    def test_missing_required_apple_bundle_fails_before_output(self):
        with self.assertRaisesRegex(SystemExit, "Required Apple CA bundle is missing"):
            self.bootstrap(SAFE_PEM, missing=("/etc/ssl/cert.pem",))
        self.assertFalse(self.output_file.exists())

    def test_incomplete_pem_blocks_fail_before_output(self):
        for fragment in ("-----BEGIN CERTIFICATE-----\nYWJj\n", "-----END CERTIFICATE-----\n"):
            with self.subTest(fragment=fragment):
                with self.assertRaisesRegex(SystemExit, "Incomplete certificate block"):
                    self.bootstrap(SAFE_PEM + fragment)
                self.assertFalse(self.output_file.exists())

    def test_invalid_retained_der_fails_before_output(self):
        invalid = ("-----BEGIN CERTIFICATE-----\n"
                   + base64.b64encode(b"not an X.509 certificate").decode()
                   + "\n-----END CERTIFICATE-----\n")
        with self.assertRaises(ssl.SSLError):
            self.bootstrap(SAFE_PEM + invalid)
        self.assertFalse(self.output_file.exists())

    def test_bootstrap_and_negative_controls_precede_checkout(self):
        names = ["Prepare restricted macOS trust", "Verify macOS trust before checkout",
                 "Verify checkout Git trust before checkout", "Check out repository"]
        offsets = [self.workflow.index(name) for name in names]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("persist-credentials: false", self.workflow)
        for host in HOSTS:
            self.assertIn(host, self.workflow)

    def test_restricted_settings_apply_only_to_checkout_and_its_git_guard(self):
        environments = {}
        for block in self.workflow.split("\n      - name: ")[1:]:
            name, *lines = block.splitlines()
            for line in lines:
                if line.startswith("        env:") and "checkout_env" in line:
                    environments[name] = line.strip()
        settings = "env: ${{ fromJSON(runner.os != 'macOS' && '{}' || steps.macos-trust.outputs.checkout_env) }}"
        self.assertEqual(environments, {
            "Verify checkout Git trust before checkout": settings,
            "Check out repository": settings,
        })


if __name__ == "__main__":
    unittest.main()
