"""Check the public offline experiment entry point and its containment."""

import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from lab_fixture import HERE, ROOT


COMMAND = [sys.executable, str(HERE / "experiments.py")]
CASES = {
    "normal", "accepted", "tls-handshake-stall", "tls-response-stall", "preflight-failure",
}


class ExperimentsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="check-tor-experiment-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.scratch = self.directory / "scratch"
        self.scratch.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.scratch), PYTHONDONTWRITEBYTECODE="1")

    def invoke(self, *args, env=None):
        return subprocess.run(COMMAND + list(args), capture_output=True, text=True,
                              env=env or self.env, timeout=20)

    def read_run(self, case, *options, env=None):
        destination = self.directory / (case + "-result")
        result = self.invoke("run", case, "--output-dir", str(destination), *options, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual({path.name for path in destination.iterdir()},
                         {"manifest.json", "observations.jsonl"})
        for path in destination.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        manifest = json.loads((destination / "manifest.json").read_text())
        observations = [json.loads(line) for line in
                        (destination / "observations.jsonl").read_text().splitlines()]
        self.assertEqual(manifest["condition"]["case"], case)
        self.assertEqual(manifest["schema"], "check_tor.experiment.v1")
        self.assertIn("check_tor_probe.zsh", manifest["source_sha256"])
        self.assertIn("python", manifest["runtime"])
        self.assertEqual(list(self.scratch.iterdir()), [])
        return result.stdout, manifest, observations

    def test_list_has_no_external_tool_dependencies_and_run_accepts_fixed_cases(self):
        env = dict(self.env, PATH=str(self.directory))
        listing = self.invoke("list", env=env)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual({line.split()[0] for line in listing.stdout.splitlines()}, CASES)
        arbitrary = self.invoke("run", "https://target.example.invalid/", env=env)
        self.assertEqual(arbitrary.returncode, 2)
        self.assertIn("invalid choice", arbitrary.stderr)
        missing = self.invoke("run", "normal", env=env)
        self.assertEqual(missing.returncode, 1)
        for tool in ("nginx", "openssl", "curl", "zsh"):
            self.assertIn(tool, missing.stderr)
        self.assertIn("install", missing.stderr)

    def test_timeout_bounds(self):
        for value in ("0", "61", "a", ".5", "２", "1" * 4500):
            with self.subTest(value=value):
                result = self.invoke("run", "tls-response-stall", "--timeout", value)
                self.assertEqual(result.returncode, 2)
                self.assertIn("1 to 60 seconds", result.stderr)
        result = self.invoke("run", "preflight-failure", "--timeout", "1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("only to the local target probe", result.stderr)

    def test_exclusive_output_rejects_checkouts_and_symlinks(self):
        checkout = self.directory / "checkout"
        checkout.mkdir()
        (checkout / ".git").write_text("gitdir: placeholder\n")
        link = self.directory / "link"
        link.symlink_to(checkout, target_is_directory=True)
        reserved = self.directory / "reserved"
        reserved.mkdir()
        preserved = reserved / "preserved"
        preserved.write_text("leave this alone\n")
        dangling = self.directory / "dangling"
        dangling.symlink_to(self.directory / "absent")
        for path, error in (
            (ROOT / "do-not-create", "outside Git"),
            (checkout / "new", "outside Git"),
            (link / "new", "outside Git"),
            (reserved, "already exists"),
            (dangling, "already exists"),
        ):
            with self.subTest(path=path):
                result = self.invoke("run", "preflight-failure", "--output-dir", str(path))
                self.assertEqual(result.returncode, 1)
                self.assertIn(error, result.stderr)
        self.assertEqual(sorted(preserved.parent.iterdir()), [preserved])
        self.assertEqual(preserved.read_text(), "leave this alone\n")
        self.assertFalse((checkout / "new").exists())
        self.assertFalse((self.directory / "absent").exists())

    def test_normal_and_accepted_retain_probe_facts_without_browser_claims(self):
        # Even a deliberately unusable ambient HTTP proxy cannot redirect the lab probe.
        env = dict(self.env, HTTPS_PROXY="http://127.0.0.1:1", http_proxy="http://127.0.0.1:1")
        for case, expected in (("normal", [(200, "PASS"), (200, "PASS")]),
                               ("accepted", [(202, "CHALLENGE")])):
            with self.subTest(case=case):
                stdout, manifest, rows = self.read_run(case, env=env)
                self.assertEqual(manifest["provenance"]["observation_format"], "check_tor.lab_probe.v1")
                self.assertEqual([(row["probe"]["http_status"], row["probe"]["verdict"])
                                  for row in rows], expected)
                for row in rows:
                    self.assertEqual(row["schema"], "check_tor.lab_probe.v1")
                    self.assertEqual(row["experiment_id"], manifest["experiment_id"])
                    self.assertEqual(row["probe"]["curl_exit"], 0)
                    self.assertGreater(row["response_body_bytes"], 0)
                    self.assertNotIn("condition", row)
                    self.assertNotIn("expected", row)
                self.assertIn("Browser actions and task completion were not measured", stdout)

    def test_stalls_distinguish_transport_stage_and_honor_local_deadline(self):
        for case, after_tls in (("tls-handshake-stall", False), ("tls-response-stall", True)):
            with self.subTest(case=case):
                _, manifest, rows = self.read_run(case, "--timeout", "1")
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(manifest["provenance"]["probe_timeout_seconds"], 1)
                self.assertEqual(row["requested_timeout_seconds"], 1)
                self.assertGreaterEqual(row["elapsed_seconds"], 0.9)
                self.assertEqual(row["probe"]["curl_exit"], 28)
                self.assertIsNone(row["probe"]["http_status"])
                self.assertEqual(row["probe"]["verdict"], "TIMEOUT")
                self.assertEqual("TLS completed" in row["probe"]["detail"], after_tls)
                self.assertEqual(row["loopback_listener"], {
                    "tcp_accepted": True, "tls_handshake_record_started": True,
                    "tls_completed": after_tls,
                    "request_bytes_received": after_tls,
                })

    def test_synthetic_preflight_uses_native_records_even_with_a_startup_path_reset(self):
        # Mimic a system zshenv that replaces PATH before the private one.
        bin_dir = self.directory / "bin"
        bin_dir.mkdir()
        zsh = bin_dir / "zsh"
        zsh.write_text(
            "#!/bin/sh\nexport PATH=/usr/bin:/bin\nexec "
            + shlex.quote(shutil.which("zsh")) + ' "$@"\n'
        )
        zsh.chmod(0o700)
        env = dict(self.env, PATH=str(bin_dir))
        stdout, manifest, rows = self.read_run("preflight-failure", env=env)
        self.assertEqual(manifest["provenance"]["transport"], "synthetic_curl")
        self.assertEqual(manifest["provenance"]["scanner_exit_status"], 1)
        self.assertTrue(all(row["schema_version"] == 2 for row in rows))
        self.assertEqual(rows[0]["execution_id"], manifest["provenance"]["execution_id"])
        observed = [row for row in rows if row["type"] == "attempt_end"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["phase"], "preflight")
        self.assertIs(observed[0]["tor_verified"], False)
        self.assertEqual(rows[-1]["counts"]["target"], {"issued": 0, "completed": 0})
        self.assertIn("Target accessibility is unobserved", stdout)

    def test_int_and_term_end_the_probe_process_group_and_remove_scratch(self):
        # Give curl a descendant which ignores SIGTERM and outlives its parent
        # unless the runner escalates against the owned group.
        process_code = """
import os, signal, sys, time
from pathlib import Path
if sys.argv[1:] == ["--version"]:
    print("offline signal test curl")
    sys.exit(0)
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    pending = Path(pids).with_suffix(".tmp")
    pending.write_text(f"{os.getppid()} {os.getpid()} {os.getpgrp()}\\n")
    pending.replace(pids)
time.sleep(30)
"""
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                bin_dir = self.directory / signum.name
                bin_dir.mkdir()
                pids = bin_dir / "pids"
                child = bin_dir / "sleep.py"
                child.write_text(f"pids = {str(pids)!r}\n" + process_code)
                curl = bin_dir / "curl"
                curl.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                                f"{shlex.quote(str(child))} \"$@\"\n")
                curl.chmod(0o700)
                destination = self.directory / (signum.name + "-result")
                runner = subprocess.Popen(
                    COMMAND + ["run", "tls-handshake-stall", "--timeout", "20",
                               "--output-dir", str(destination)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=dict(self.env, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"]),
                )
                group = None
                try:
                    deadline = time.monotonic() + 12
                    while not pids.exists():
                        self.assertIsNone(runner.poll(), runner.stderr.read() if runner.poll() is not None else "")
                        self.assertLess(time.monotonic(), deadline, "probe did not launch")
                        time.sleep(0.02)
                    parent, child_pid, group = map(int, pids.read_text().split())
                    self.assertNotEqual(group, os.getpgrp())
                    self.assertNotEqual(group, runner.pid)
                    self.assertNotEqual(parent, child_pid)
                    ps = shutil.which("ps")
                    self.assertIsNotNone(ps)
                    runner.send_signal(signum)
                    _, stderr = runner.communicate(timeout=5)
                    self.assertEqual(runner.returncode, 128 + signum, stderr)
                    self.assertIn("interrupted", stderr)
                    deadline = time.monotonic() + 2
                    while True:
                        state = subprocess.run(
                            [ps, "-p", f"{parent},{child_pid}", "-o", "stat="],
                            capture_output=True, text=True, timeout=2,
                        ).stdout.split()
                        if all(code.startswith("Z") for code in state):
                            group = None
                            break
                        self.assertLess(time.monotonic(), deadline, f"live descendants: {state}")
                        time.sleep(0.02)
                    self.assertFalse(destination.exists())
                    self.assertEqual(list(self.scratch.iterdir()), [])
                finally:
                    if runner.poll() is None:
                        runner.terminate()
                    if group is not None and group != os.getpgrp():
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    runner.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
