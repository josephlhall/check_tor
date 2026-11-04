"""Offline tests for the checkout-free macOS default-trust workflow."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import textwrap
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/macos-tls-defaults.yml"
TEXT = WORKFLOW.read_text()
SOURCE = textwrap.dedent(TEXT.split("        run: |\n", 1)[1])
PROBE = {"__name__": "default_trust_probe"}
exec(compile(SOURCE, str(WORKFLOW), "exec"), PROBE)


class DefaultTrustTests(unittest.TestCase):
    def test_workflow_is_unmodified_checkout_free_and_narrow(self):
        self.assertIn("permissions: {}", TEXT)
        self.assertIn("workflow_dispatch:", TEXT)
        self.assertIn("pull_request:\n    paths:", TEXT)
        self.assertIn("tests/macos_tls_defaults_test.py", TEXT)
        self.assertIn("timeout-minutes: 7", TEXT)
        self.assertIn("shell: /usr/bin/python3 -I -S {0}", TEXT)
        for forbidden in ("uses:", "continue-on-error", "sudo ", "brew install", "brew update", "pip install", "actions/checkout"):
            self.assertNotIn(forbidden, TEXT)

    def test_environment_never_inherits_ca_auth_proxy_or_config(self):
        private = {key: "PRIVATE" for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO", "GIT_CONFIG_COUNT", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "TOKEN", "BASH_ENV", "PYTHONPATH", "DYLD_LIBRARY_PATH")}
        with patch.dict(os.environ, private, clear=True):
            env = PROBE["clean_environment"]("/empty", "/usr/bin:/bin")
        self.assertFalse(private.keys() & env.keys())
        self.assertEqual(env["HOME"], "/empty")
        self.assertEqual(env["CURL_HOME"], "/empty")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("PRIVATE", json.dumps(env))

    def test_discovery_deduplicates_and_retains_required_aliases(self):
        def which(name, path):
            return "/usr/bin/" + name
        with patch.object(PROBE["shutil"], "which", side_effect=which), patch.object(Path, "is_file", return_value=False), patch.object(Path, "glob", return_value=[]):
            clients = PROBE["discover"]("/usr/bin")
        self.assertEqual(len(clients), 3)
        self.assertTrue(all(client["required"] for client in clients))
        self.assertTrue(all(len(client["labels"]) == 2 for client in clients))
        with patch.object(PROBE["shutil"], "which", return_value=None), patch.object(Path, "is_file", return_value=False), patch.object(Path, "glob", return_value=[]):
            clients = PROBE["discover"]("/empty")
        missing = [client for client in clients if client["command"] is None]
        self.assertEqual(len(missing), 3)
        for client in missing:
            self.assertFalse(PROBE["probe_client"](client, {}, "/empty", 0)["ok"])

    def test_discovery_includes_keg_only_tools_and_excludes_python_config(self):
        installed = {"/usr/local/bin/curl", "/opt/homebrew/opt/curl/bin/curl", "/usr/local/opt/git/bin/git", "/opt/homebrew/opt/python@3.14/bin/python3.14", "/opt/homebrew/opt/python@3.14/bin/python3.14-config"}
        def glob(prefix, pattern):
            return [Path(path) for path in installed if path.startswith(str(prefix)) and "python" in path]
        with patch.object(PROBE["shutil"], "which", return_value=None), patch.object(Path, "is_file", lambda path: str(path) in installed), patch.object(Path, "glob", glob):
            clients = PROBE["discover"]("/empty")
        commands = {client["command"] for client in clients}
        self.assertTrue((installed - {"/opt/homebrew/opt/python@3.14/bin/python3.14-config"}) <= commands)
        self.assertNotIn("/opt/homebrew/opt/python@3.14/bin/python3.14-config", commands)

    def test_curl_certificate_only_and_http_positive_controls(self):
        classify = PROBE["classify"]
        for code in (0, 6, 7, 28, 35, 51):
            self.assertFalse(classify("curl", "bad", False, {"returncode": code})["ok"])
        self.assertTrue(classify("curl", "bad", False, {"returncode": 60})["ok"])
        for status in ("", "301", "403", "PRIVATE200"):
            self.assertFalse(classify("curl", "github.com", True, {"returncode": 0, "stdout": status})["ok"])
        self.assertTrue(classify("curl", "github.com", True, {"returncode": 0, "stdout": "200"})["ok"])

    def test_git_requires_128_exact_url_and_client_generated_certificate_error(self):
        host = PROBE["BAD_HOSTS"][0]
        genuine = "fatal: unable to access 'https://" + host + "/': SSL certificate problem: unable to get local issuer certificate\n"
        classify = PROBE["classify"]
        self.assertTrue(classify("git", host, False, {"returncode": 128, "stderr": genuine})["ok"])
        for code, diagnostic in ((1, genuine), (0, genuine), (128, "server says " + genuine), (128, genuine + "server content"), (128, genuine.replace(host, "other.example.test")), (128, "fatal: Could not resolve host"), (128, "fatal: Authentication failed")):
            self.assertFalse(classify("git", host, False, {"returncode": code, "stderr": diagnostic})["ok"])
        self.assertFalse(classify("git", "github.com", True, {"returncode": 0, "stdout": ""})["ok"])
        self.assertTrue(classify("git", "github.com", True, {"returncode": 0, "stdout": "a" * 40 + "\tHEAD\n"})["ok"])

    def python_result(self, error=None, status=200):
        opener = MagicMock()
        if error is not None:
            opener.open.side_effect = error
        else:
            opener.open.return_value.__enter__.return_value.status = status
        output = io.StringIO()
        with patch("urllib.request.build_opener", return_value=opener) as build, patch("sys.argv", ["probe", "https://example.test/"]), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as exited:
                exec(compile(PROBE["PYTHON_PROBE"], "python probe", "exec"), {})
        self.handlers = build.call_args.args
        return {"returncode": exited.exception.code, "stdout": output.getvalue()}

    def test_python_http_redirect_dns_and_certificate_classification(self):
        classify = PROBE["classify"]
        for status in (302, 403, 404, 429):
            raw = self.python_result(urllib.error.HTTPError("https://PRIVATE.invalid", status, "PRIVATE", {}, None))
            self.assertEqual(raw["returncode"], 0)
            self.assertFalse(classify("python", "bad", False, raw)["ok"])
            self.assertFalse(classify("python", "github.com", True, raw)["ok"])
            self.assertNotIn("PRIVATE", raw["stdout"])
        redirects = [handler for handler in self.handlers if isinstance(handler, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirects), 1)
        self.assertIsNone(redirects[0].redirect_request(None, None, 302, None, None, "https://other.invalid"))
        for reason in (OSError(8, "PRIVATE DNS"), ssl.SSLError(1, "PRIVATE SSL")):
            raw = self.python_result(urllib.error.URLError(reason))
            self.assertFalse(classify("python", "bad", False, raw)["ok"])
            self.assertNotIn("PRIVATE", raw["stdout"])
        raw = self.python_result(urllib.error.URLError(ssl.SSLCertVerificationError(1, "PRIVATE")))
        self.assertTrue(classify("python", "bad", False, raw)["ok"])

    def test_commands_disable_redirects_configs_and_credentials(self):
        command = PROBE["command"]
        curl = command("curl", "/curl", "bad")
        self.assertEqual(curl[1], "-q")
        self.assertNotIn("-L", curl)
        self.assertNotIn("--location", curl)
        for option in ("--cacert", "--capath", "--insecure", "--ca-native"):
            self.assertNotIn(option, curl)
        git = command("git", "/git", "bad")
        self.assertIn("http.followRedirects=false", git)
        self.assertIn("credential.helper=", git)
        self.assertIn("http.extraHeader=", git)
        self.assertEqual(command("python", "/python", "bad")[1:3], ["-I", "-S"])

    def test_each_control_runs_after_positive_or_negative_failure(self):
        client = {"kind": "curl", "command": "/curl", "labels": ["curl"], "paths": ["/curl"], "required": True}
        for first in ({"returncode": 6}, {"returncode": 0, "stdout": "200"}):
            results = [first, {"returncode": 0}, {"returncode": 60}, {"returncode": 60}, {"returncode": 60}]
            with patch.dict(PROBE, {"version": lambda *args: ("fixture", True), "run": MagicMock(side_effect=results)}):
                report = PROBE["probe_client"](client, {}, "/empty", 0)
                self.assertEqual(len(report["controls"]), 5)
                self.assertFalse(report["ok"])
                self.assertEqual(PROBE["run"].call_count, 5)

    def test_timeout_kills_and_reaps_owned_process_group(self):
        child = MagicMock(pid=123)
        child.communicate.side_effect = [subprocess.TimeoutExpired([], 1), ("PRIVATE", "PRIVATE")]
        with patch.object(PROBE["subprocess"], "Popen", return_value=child) as popen, patch.object(PROBE["time"], "monotonic", return_value=10), patch.object(PROBE["os"], "killpg") as kill:
            result = PROBE["run"](["/fixture"], {}, "/empty", 11)
        self.assertEqual(result["error"], "deadline")
        self.assertNotIn("PRIVATE", json.dumps(result))
        kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertEqual(child.communicate.call_count, 2)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        with patch.object(PROBE["subprocess"], "Popen", side_effect=OSError("PRIVATE")):
            self.assertEqual(PROBE["run"](["/missing"], {}, "/empty", float("inf"))["error"], "client_unavailable")

    def test_image_identity_required_and_invalid_values_not_echoed(self):
        valid = {"ImageOS": "macos26", "ImageVersion": "20261026.0455.2", "RUNNER_ARCH": "ARM64"}
        with patch.dict(os.environ, valid, clear=True):
            self.assertTrue(PROBE["image_metadata"]()["identified"])
        for key in valid:
            data = dict(valid, **{key: "PRIVATE invalid value"})
            with patch.dict(os.environ, data, clear=True):
                result = PROBE["image_metadata"]()
                self.assertFalse(result["identified"])
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_main_reports_every_client_after_failure_without_raw_errors(self):
        clients = [{"kind": "curl", "command": "/fixture" + str(i), "labels": [str(i)], "paths": [], "required": True} for i in range(3)]
        def probe(client, *args):
            if client["labels"] == ["1"]:
                raise RuntimeError("PRIVATE")
            return dict(client, ok=True, controls=[])
        output = io.StringIO()
        mocks = {"image_metadata": lambda: {"identified": True}, "discover": lambda path: clients, "probe_client": probe, "run": lambda *args: {"returncode": 0, "stdout": "one\ntwo\nthree\n"}}
        with patch.dict(PROBE, mocks), contextlib.redirect_stdout(output):
            self.assertEqual(PROBE["main"](), 1)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        reports = [record for record in records if "labels" in record]
        self.assertEqual({tuple(record["labels"]) for record in reports}, {("0",), ("1",), ("2",)})
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertFalse(records[-1]["summary"]["ok"])


if __name__ == "__main__":
    unittest.main()
