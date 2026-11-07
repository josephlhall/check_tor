"""Deterministic v2 measurement tests; all curl invocations are synthetic.

Each fake request atomically publishes separate files. Live readers never see
partial JSON, and scheduling assertions use independently observed process
intervals rather than the coordinator's own reported timestamps.
"""

import contextlib
import datetime
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "check_tor.zsh"
PREFLIGHT = "https://check.torproject.org/api/ip"
FAKE = r"""import json, os, re, signal, subprocess, sys, time
from pathlib import Path
from urllib.parse import urljoin
args = sys.argv[1:]
if "--version" in args:
    print("curl 8.7.1 synthetic offline fixture")
    sys.exit(0)
url = next((arg for arg in reversed(args) if arg.startswith(("https://", "http://"))), "")
if not url:
    sys.exit(90)
route = "tor" if "--socks5-hostname" in args else "direct"
logs = Path(os.environ["MEASUREMENT_TEST_LOG"])
def publish(path, value):
    # Readers glob only *.json; rename on the same filesystem publishes one
    # complete record. Tests can widen the incomplete-write interval on purpose.
    pending = path.with_suffix(".pending")
    encoded = json.dumps(value)
    delay = float(os.environ.get("MEASUREMENT_TEST_LOG_WRITE_DELAY", "0"))
    with pending.open("w") as destination:
        middle = len(encoded) // 2
        destination.write(encoded[:middle])
        if delay:
            destination.flush()
            time.sleep(delay)
        destination.write(encoded[middle:])
    pending.replace(path)

plan = json.loads(os.environ.get("MEASUREMENT_TEST_PLAN", "{}"))
previous = []
for path in logs.glob("*.start.json"):
    try:
        previous.append(json.loads(path.read_text()))
    except (OSError, ValueError):
        pass
number = sum(call["url"] == url and call["route"] == route for call in previous)
responses = plan.get(url + "|" + route, plan.get(url, [{}]))
response = responses[min(number, len(responses)-1)]
if url == "https://check.torproject.org/api/ip":
    response = plan.get("preflight", [{}])[0]
record = {"pid": os.getpid(), "url": url, "route": route, "start": time.monotonic(),
          "args": args, "proxy_env": {key: os.environ.get(key) for key in
          ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "no_proxy")},
          "trust_env": os.environ.get("SSL_CERT_FILE")}
publish(logs / (str(os.getpid()) + ".start.json"), record)
if response.get("child"):
    child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"])
    publish(logs / (str(child.pid) + ".child.json"), {"pid": child.pid})
if response.get("release_file"):
    # Hold the first cohort until the test observes every configured worker.
    # Startup speed must not decide whether their intervals overlap.
    deadline = time.monotonic() + 10
    while not Path(response["release_file"]).exists():
        if time.monotonic() >= deadline:
            sys.exit(91)
        time.sleep(0.01)
time.sleep(response.get("delay", 0))
chain_headers = None
if "chain" in response:
    chain = response["chain"]
    limit = int(args[args.index("--max-redirs") + 1]) if "--max-redirs" in args else 0
    current, followed, contacts, chain_headers = url, 0, [], ""
    while True:
        contacts.append(current)
        item = chain[current]
        code = item.get("code", 200)
        headers = item.get("headers", "")
        if "location" in item:
            headers += "Location: " + item["location"] + "\r\n"
        chain_headers += item.get("prefix", "") + "HTTP/1.1 " + str(code) + "\r\n" + headers + "\r\n"
        location = re.search(r"(?im)^Location: *([^\r\n]*)", headers)
        response = dict(item, code=code, redirects=followed, final_url=current)
        if not 300 <= code < 400 or not location or "-L" not in args:
            break
        if followed >= limit:
            response["exit"] = 47
            response["error"] = "Maximum redirects followed"
            response["next_url"] = urljoin(current, location[1])
            break
        current = urljoin(current, location[1])
        followed += 1
    # Record contacts as the fake performs them, separately from reported
    # write-out fields. Tests assert the unvisited endpoint is absent here.
    record["contacts"] = contacts
    publish(logs / (str(os.getpid()) + ".contacts.json"), record)
code = response.get("code", 200)
body = response.get("body", "")
if response.get("body_bytes"):
    body = "x" * response["body_bytes"]
if url == "https://check.torproject.org/api/ip":
    body = '{"IsTor":' + ("false" if response.get("fail") else "true") + ',"IP":"192.0.2.123"}'
headers = chain_headers if chain_headers is not None else "HTTP/2 " + str(code) + "\r\n" + response.get("headers", "") + "\r\n"
if "-D" in args:
    Path(args[args.index("-D") + 1]).write_text(headers)
write_failed = False
if "-o" in args:
    try:
        with open(args[args.index("-o") + 1], "w") as destination:
            destination.write(body)
    except BrokenPipeError:
        write_failed = True
else:
    sys.stdout.write(body)
if "-w" in args and not response.get("omit_writeout"):
    writeout = args[args.index("-w") + 1]
    writeout = writeout.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    values = {"http_code": code, "num_redirects": response.get("redirects", 0),
              "time_appconnect": response.get("tls", "0.1"),
              "url_effective": response.get("final_url", url), "redirect_url": response.get("next_url", ""),
              "errormsg": response.get("error", "")}
    for name, value in values.items():
        writeout = writeout.replace("%{" + name + "}", str(value))
    sys.stdout.write(writeout)
record["end"] = time.monotonic()
publish(logs / (str(os.getpid()) + ".end.json"), record)
sys.exit(response.get("exit", 23 if write_failed else 0))
"""


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="check-tor-v2-tests-")
        self.addCleanup(directory.cleanup)
        self.temp = Path(directory.name)
        self.bin = self.temp / "bin"
        self.bin.mkdir()
        self.logs = self.temp / "requests"
        self.logs.mkdir()
        self.scanner_tmp = self.temp / "scanner-tmp"
        self.scanner_tmp.mkdir()
        fake = self.bin / "curl"
        fake.write_text("#!" + sys.executable + "\n" + FAKE)
        fake.chmod(0o755)
        self.input = self.temp / "synthetic-targets.txt"
        self.input.write_text("alpha.example.test\n")
        self.environment = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            TMPDIR=str(self.scanner_tmp),
            MEASUREMENT_TEST_LOG=str(self.logs),
        )
        self.processes = []
        self.addCleanup(self.kill_processes)

    def kill_processes(self):
        # Failed assertions must not strand synthetic descendants. Requests have
        # coordinator-owned process groups; the test scanner has its own session.
        pids = []
        for path in self.logs.glob("*.start.json"):
            pids.append(json.loads(path.read_text())["pid"])
        for path in self.logs.glob("*.child.json"):
            pids.append(json.loads(path.read_text())["pid"])
        for pid in pids:
            try:
                group = os.getpgid(pid)
                if group != os.getpgrp():
                    os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for process in self.processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.communicate(timeout=3)
            except (ValueError, subprocess.TimeoutExpired):
                process.wait(timeout=3)

    def clear_logs(self):
        for path in self.logs.iterdir():
            path.unlink()

    def calls(self, phase="start"):
        return sorted(
            (
                json.loads(path.read_text())
                for path in self.logs.glob("*." + phase + ".json")
            ),
            key=lambda row: row["start"],
        )

    def spawn(
        self,
        *arguments,
        targets=None,
        plan=None,
        env=None,
        input_path=None,
        scanner_path=None,
    ):
        if targets is not None:
            self.input.write_text("\n".join(targets) + "\n")
        environment = dict(
            self.environment, MEASUREMENT_TEST_PLAN=json.dumps(plan or {})
        )
        environment.update(env or {})
        process = subprocess.Popen(
            [
                shutil.which("zsh"),
                str(scanner_path or SCANNER),
                "--format",
                "jsonl-v2",
                *map(str, arguments),
                str(input_path or self.input),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def run_scan(self, *arguments, **kwargs):
        process = self.spawn(*arguments, **kwargs)
        stdout, stderr = process.communicate(timeout=20)
        records = self.parse(stdout)
        return process.returncode, records, stderr

    def parse(self, stdout):
        records = [json.loads(line) for line in stdout.splitlines()]
        for row in records:
            self.assertEqual(row["schema_version"], 2)
            self.assertIsInstance(row["type"], str)
        return records

    def select(self, records, kind, phase=None):
        return [
            row
            for row in records
            if row["type"] == kind and (phase is None or row.get("phase") == phase)
        ]

    def assert_clean(self):
        self.assertEqual(
            list(self.scanner_tmp.iterdir()), [], "owned request temporary files leaked"
        )

    def assert_accounting(self, records):
        end = self.select(records, "run_end")[-1]
        for phase in ("preflight", "target"):
            starts = self.select(records, "attempt_start", phase)
            completed = [
                row
                for row in self.select(records, "attempt_end", phase)
                if row["complete"]
            ]
            self.assertEqual(
                end["counts"][phase],
                {"issued": len(starts), "completed": len(completed)},
            )
        return end

    def wait_for_calls(self, minimum, process, timeout=5, children=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (
                len(self.calls()) >= minimum
                and len(list(self.logs.glob("*.child.json"))) >= children
            ):
                return
            if process.poll() is not None:
                break
            time.sleep(0.01)
        self.fail("scanner did not launch expected synthetic requests")

    def assert_no_owned_children(self):
        pids = [row["pid"] for row in self.calls()]
        pids += [
            json.loads(path.read_text())["pid"]
            for path in self.logs.glob("*.child.json")
        ]
        deadline = time.monotonic() + 3
        remaining = pids
        while time.monotonic() < deadline:
            remaining = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    remaining.append(pid)
                except ProcessLookupError:
                    pass
            if not remaining:
                return
            time.sleep(0.02)
        self.fail("owned fake curl descendants survived: " + str(remaining))

    def test_lifecycle_identity_nulls_escaping_and_counts(self):
        label = 'caller "quote" \\ slash\tline\nnext'
        status, rows, error = self.run_scan(
            "--run-id",
            label,
            "--group-id",
            "group☃",
            targets=["  alpha.example.test  ", "http://beta.example.test/path?q=%22"],
        )
        self.assertEqual(status, 0, error)
        self.assertEqual(rows[0]["type"], "run_start")
        self.assertEqual(rows[-1]["type"], "run_end")
        execution = rows[0]["execution_id"]
        self.assertTrue(execution)
        for row in rows:
            self.assertEqual(
                (row["execution_id"], row["run_id"], row["group_id"]),
                (execution, label, "group☃"),
            )
        starts = self.select(rows, "attempt_start")
        ends = self.select(rows, "attempt_end")
        self.assertEqual(
            {r["attempt_id"] for r in starts}, {r["attempt_id"] for r in ends}
        )
        self.assertEqual(
            [r["global_order"] for r in starts], list(range(1, len(starts) + 1))
        )
        target = self.select(rows, "attempt_end", "target")
        self.assertEqual(
            [r["url"] for r in target],
            ["https://alpha.example.test", "https://beta.example.test/path?q=%22"],
        )
        self.assertEqual(target[0]["original_input"], "alpha.example.test")
        self.assertEqual(len({r["target_id"] for r in target}), 2)
        for row in target:
            self.assertIsNone(row["trial_id"])
            self.assertIsNone(row["pair_id"])
            self.assertIsNone(row["tor_verified"])
            self.assertEqual(row["verdict"], "PASS")
            self.assertEqual(row["http_status"], 200)
            self.assertGreaterEqual(row["duration_seconds"], 0)
            datetime.datetime.fromisoformat(row["started_at"].replace("Z", "+00:00"))
            datetime.datetime.fromisoformat(row["ended_at"].replace("Z", "+00:00"))
        self.assertNotIn("192.0.2.123", json.dumps(rows))
        preflight = self.select(rows, "attempt_end", "preflight")[0]
        self.assertIs(preflight["tor_verified"], True)
        self.assertEqual(preflight["http_status"], 200)
        self.assertEqual(preflight["redirect_count"], 0)
        self.assertEqual(preflight["final_url"], PREFLIGHT)
        self.assertEqual(preflight["curl_exit"], 0)
        self.assertIsNone(preflight["curl_error"])
        self.assertEqual(self.assert_accounting(rows)["state"], "complete")
        self.assert_clean()

    def test_sourced_detailed_main_preserves_caller_and_traps(self):
        output = self.temp / "sourced.jsonl"
        exit_marker = self.temp / "caller-exit"
        script = r"""
            source "$1"
            trap 'print -r -- preserved > "$4"' EXIT
            trap 'true' INT
            trap 'true' TERM
            before=$(trap)
            main --format jsonl-v2 "$2" > "$3" || exit 21
            after=$(trap)
            [[ "$before" == "$after" ]] || exit 22
            [[ $# == 4 && -n "$1" ]] || exit 23
            print -r -- caller-continued
        """
        result = subprocess.run(
            [
                shutil.which("zsh"),
                "-fc",
                script,
                "zsh",
                str(SCANNER),
                str(self.input),
                str(output),
                str(exit_marker),
            ],
            env=self.environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "caller-continued")
        self.assertEqual(exit_marker.read_text().strip(), "preserved")
        rows = self.parse(output.read_text())
        self.assertEqual(self.assert_accounting(rows)["state"], "complete")
        self.assert_clean()

    def test_default_retry_stops_and_conditional_control(self):
        scenarios = [
            ([{"code": 200}], 1, 0),
            ([{"code": 403}, {"code": 200}], 2, 0),
            ([{"code": 403}], 3, 1),
            ([{"code": 503}], 1, 0),
            ([{"exit": 60, "code": "000"}], 1, 0),
        ]
        for responses, tor_count, direct_count in scenarios:
            with self.subTest(responses=responses):
                self.clear_logs()
                status, rows, error = self.run_scan(
                    plan={"https://alpha.example.test|tor": responses}
                )
                self.assertEqual(status, 0, error)
                calls = [row for row in self.calls() if row["url"] != PREFLIGHT]
                self.assertEqual(sum(r["route"] == "tor" for r in calls), tor_count)
                self.assertEqual(
                    sum(r["route"] == "direct" for r in calls), direct_count
                )
                self.assert_accounting(rows)
                self.assert_clean()

    def test_fixed_trials_preserve_all_native_verdicts(self):
        responses = [
            {"code": 200},
            {"exit": 60, "code": "000"},
            {"code": 503},
            {"exit": 28, "code": "000"},
            {"code": 200, "body": "Just a moment"},
        ]
        status, rows, error = self.run_scan(
            "--trials",
            5,
            "--control",
            "never",
            plan={"https://alpha.example.test": responses},
        )
        self.assertEqual(status, 0, error)
        ends = self.select(rows, "attempt_end", "target")
        self.assertEqual(
            [row["verdict"] for row in ends],
            ["PASS", "CERT", "WARN", "TIMEOUT", "CHALLENGE"],
        )
        self.assertEqual([row["trial_id"] for row in ends], [1, 2, 3, 4, 5])
        self.assertEqual(
            [row["http_status"] for row in ends], [200, None, 503, None, 200]
        )
        self.assertTrue(all(row["pair_id"] is None for row in ends))
        self.assertEqual(self.select(rows, "pair_end"), [])
        self.assert_accounting(rows)

    def test_target_and_trial_controls_have_honest_pairing(self):
        for scope, direct_count, pairs in [("target", 1, 0), ("trial", 3, 3)]:
            with self.subTest(scope=scope):
                self.clear_logs()
                status, rows, error = self.run_scan(
                    "--trials", 3, "--control", "always", "--control-scope", scope
                )
                self.assertEqual(status, 0, error)
                ends = self.select(rows, "attempt_end", "target")
                self.assertEqual(
                    sum(r["route"] == "direct" for r in ends), direct_count
                )
                summaries = self.select(rows, "pair_end")
                self.assertEqual(len(summaries), pairs)
                if scope == "target":
                    self.assertTrue(all(row["pair_id"] is None for row in ends))
                for pair in summaries:
                    members = [row for row in ends if row["pair_id"] == pair["pair_id"]]
                    self.assertEqual(
                        {row["route"] for row in members}, {"tor", "direct"}
                    )
                    self.assertEqual(
                        set(pair["attempt_ids"].values()),
                        {row["attempt_id"] for row in members},
                    )
                    self.assertEqual(pair["state"], "complete")
                    self.assertEqual(pair["missing_routes"], [])
                self.assert_accounting(rows)

    def test_conditional_trial_controls_only_blocky_trials(self):
        responses = [
            {"code": 200},
            {"code": 403},
            {"exit": 60, "code": "000"},
            {"code": 429},
        ]
        status, rows, error = self.run_scan(
            "--trials",
            4,
            "--control",
            "conditional",
            "--control-scope",
            "trial",
            plan={"https://alpha.example.test|tor": responses},
        )
        self.assertEqual(status, 0, error)
        direct = [
            r
            for r in self.select(rows, "attempt_end", "target")
            if r["route"] == "direct"
        ]
        self.assertEqual([r["trial_id"] for r in direct], [2, 4])
        self.assertEqual(len(self.select(rows, "pair_end")), 2)

    def test_explicit_order_and_counterbalance_are_schedule_independent(self):
        for order in ("tor-first", "direct-first"):
            status, rows, error = self.run_scan(
                "--trials",
                2,
                "--control",
                "always",
                "--control-scope",
                "trial",
                "--order",
                order,
            )
            self.assertEqual(status, 0, error)
            routes = [r["route"] for r in self.select(rows, "attempt_start", "target")]
            self.assertEqual(
                routes,
                (["tor", "direct"] if order == "tor-first" else ["direct", "tor"]) * 2,
            )
        expected = None
        for workers in (1, 2, 4):
            self.clear_logs()
            status, rows, error = self.run_scan(
                "--trials",
                3,
                "--control",
                "always",
                "--control-scope",
                "trial",
                "--order",
                "counterbalanced",
                "--seed",
                23,
                "--workers",
                workers,
                targets=[
                    "alpha.example.test",
                    "beta.example.test",
                    "gamma.example.test",
                ],
            )
            self.assertEqual(status, 0, error)
            groups = {}
            for row in self.select(rows, "attempt_start", "target"):
                groups.setdefault(
                    (row["target_occurrence"], row["trial_id"]), []
                ).append(row["route"])
            if expected is None:
                expected = groups
            self.assertEqual(groups, expected)
            for (occurrence, trial), routes in groups.items():
                self.assertEqual(
                    routes,
                    ["tor", "direct"]
                    if (23 + occurrence - 1 + trial - 1) % 2 == 0
                    else ["direct", "tor"],
                )
            self.assertTrue(any(routes[0] == "tor" for routes in groups.values()))
            self.assertTrue(any(routes[0] == "direct" for routes in groups.values()))

    def test_invalid_combinations_fail_before_input_or_requests(self):
        invalid = [
            ("--trials", "0"),
            ("--trials", "101"),
            ("--workers", "0"),
            ("--workers", "33"),
            ("--start-gap", "nan"),
            ("--start-gap", "-1"),
            ("--max-partner-gap", "inf"),
            ("--trials", "2", "--circuits", "2"),
            ("--seed", "1"),
            ("--order", "counterbalanced", "--control", "always"),
            ("--order", "direct-first"),
            ("--control", "never", "--control-scope", "trial"),
            ("--control-scope", "trial"),
            ("--no-clearnet", "--control", "always"),
            ("--control", "never", "--max-partner-gap", "10"),
        ]
        fifo = self.temp / "must-not-open"
        os.mkfifo(fifo)
        for args in invalid:
            with self.subTest(args=args):
                process = self.spawn(*args, input_path=fifo)
                stdout, stderr = process.communicate(timeout=2)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(self.calls(), [])
                self.assertNotIn("192.0.2.123", stdout + stderr)
        self.assert_clean()

    def test_userinfo_rejected_before_preflight_and_ipv6_supported(self):
        status, rows, error = self.run_scan(
            targets=["https://user:secret@alpha.example.test/"]
        )
        self.assertNotEqual(status, 0)
        self.assertEqual(self.calls(), [])
        self.assertNotIn("secret", json.dumps(rows) + error)
        status, rows, error = self.run_scan(
            "--control", "never", targets=["http://[2001:db8::1]:8443/path"]
        )
        self.assertEqual(status, 0, error)
        self.assertEqual(
            self.select(rows, "attempt_end", "target")[0]["url"],
            "https://[2001:db8::1]:8443/path",
        )

    def test_reproducible_routing_clears_ambient_proxy_but_keeps_trust(self):
        environment = {
            key: "http://ambient.example.test:9876"
            for key in (
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
            )
        }
        environment.update(
            NO_PROXY="*", no_proxy="*", SSL_CERT_FILE="/synthetic/trust.pem"
        )
        status, rows, error = self.run_scan(
            "--trials", 1, "--control", "always", env=environment
        )
        self.assertEqual(status, 0, error)
        for call in self.calls():
            self.assertTrue(
                all(value in (None, "") for value in call["proxy_env"].values())
            )
            self.assertEqual(call["trust_env"], "/synthetic/trust.pem")
        for row in self.select(rows, "attempt_start"):
            self.assertEqual(row["routing"]["mode"], "guaranteed")
        direct = [r for r in self.calls() if r["route"] == "direct"][0]
        self.assertIn("--noproxy", direct["args"])
        self.clear_logs()
        status, rows, error = self.run_scan(env=environment)
        self.assertEqual(status, 0, error)
        self.assertTrue(
            all(
                row["routing"]["mode"] == "inherited_unknown"
                for row in self.select(rows, "attempt_start")
            )
        )
        self.assertTrue(any(call["proxy_env"]["HTTPS_PROXY"] for call in self.calls()))

    def test_late_pair_uses_observed_start_gap(self):
        status, rows, error = self.run_scan(
            "--trials",
            1,
            "--control",
            "always",
            "--control-scope",
            "trial",
            "--max-partner-gap",
            "0.02",
            plan={"https://alpha.example.test|tor": [{"delay": 0.08}]},
        )
        self.assertEqual(status, 0, error)
        pair = self.select(rows, "pair_end")[0]
        self.assertEqual(pair["late"], True)
        self.assertGreaterEqual(pair["observed_start_gap_seconds"], 0.08)

    def test_workers_overlap_and_duplicate_hostnames_serialize(self):
        targets = [
            "alpha.example.test",
            "ALPHA.EXAMPLE.TEST.:8443/second",
            "beta.example.test",
            "gamma.example.test",
            "delta.example.test",
        ]
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                self.clear_logs()
                release = self.temp / ("overlap-release-" + str(workers))
                plan = {
                    "https://" + target: [{"release_file": str(release)}]
                    for target in targets
                }
                process = self.spawn(
                    "--workers",
                    workers,
                    "--control",
                    "never",
                    targets=targets,
                    plan=plan,
                )
                try:
                    self.wait_for_calls(workers + 1, process)  # plus preflight
                finally:
                    release.touch()
                stdout, error = process.communicate(timeout=20)
                rows = self.parse(stdout)
                self.assertEqual(process.returncode, 0, error)
                intervals = [r for r in self.calls("end") if r["url"] != PREFLIGHT]
                self.assertEqual(len(intervals), 5)
                maximum = max(
                    sum(
                        other["start"] <= row["start"] < other["end"]
                        for other in intervals
                    )
                    for row in intervals
                )
                self.assertLessEqual(maximum, workers)
                self.assertEqual(maximum, workers)
                duplicates = [
                    r
                    for r in intervals
                    if urlsplit(r["url"]).hostname.lower().rstrip(".")
                    == "alpha.example.test"
                ]
                self.assertLessEqual(duplicates[0]["end"], duplicates[1]["start"])
                self.assertEqual(
                    len(
                        {row["target_id"] for row in self.select(rows, "bundle_start")}
                    ),
                    5,
                )
                self.assert_accounting(rows)
                self.assert_clean()

    def test_global_start_gate_includes_preflight_and_all_routes(self):
        gap = 0.06
        status, rows, error = self.run_scan(
            "--workers",
            4,
            "--trials",
            2,
            "--control",
            "always",
            "--control-scope",
            "trial",
            "--start-gap",
            gap,
            targets=["alpha.example.test", "beta.example.test"],
        )
        self.assertEqual(status, 0, error)
        starts = self.select(rows, "attempt_start")
        actual = self.calls()
        self.assertEqual(len(starts), 9)
        self.assertEqual(len(actual), 9)

        def seconds(row):
            return datetime.datetime.fromisoformat(
                row["started_at"].replace("Z", "+00:00")
            ).timestamp()

        for left, right in zip(starts, starts[1:]):
            self.assertGreaterEqual(seconds(right) - seconds(left), gap - 0.003)
        # Process startup jitter is independent of the coordinator invocation
        # boundary; allow 40ms while still detecting an unpaced worker burst.
        for left, right in zip(actual, actual[1:]):
            self.assertGreaterEqual(right["start"] - left["start"], gap - 0.04)

    def test_output_completion_order_is_independent_of_input_order(self):
        status, rows, error = self.run_scan(
            "--workers",
            2,
            "--control",
            "never",
            targets=["slow.example.test", "fast.example.test"],
            plan={"https://slow.example.test": [{"delay": 0.25}]},
        )
        self.assertEqual(status, 0, error)
        ends = self.select(rows, "attempt_end", "target")
        self.assertEqual([r["target_occurrence"] for r in ends], [2, 1])
        self.assert_accounting(rows)

    def test_preflight_without_writeout_keeps_unavailable_metadata_null(self):
        status, rows, error = self.run_scan(
            plan={"preflight": [{"omit_writeout": True}]}
        )
        self.assertEqual(status, 0, error)
        preflight = self.select(rows, "attempt_end", "preflight")[0]
        self.assertIs(preflight["tor_verified"], True)
        self.assertIs(preflight["complete"], True)
        for key in ("http_status", "redirect_count", "final_url", "curl_error"):
            self.assertIsNone(preflight[key])
        self.assertEqual(preflight["curl_exit"], 0)
        self.assert_accounting(rows)
        self.assert_clean()

    def test_preflight_failure_is_accounted_without_target_requests(self):
        status, rows, error = self.run_scan(plan={"preflight": [{"fail": True}]})
        self.assertNotEqual(status, 0)
        self.assertEqual([r["url"] for r in self.calls()], [PREFLIGHT])
        end = self.assert_accounting(rows)
        self.assertEqual(end["state"], "error")
        self.assertEqual(end["counts"]["target"], {"issued": 0, "completed": 0})
        self.assertEqual(
            self.select(rows, "attempt_end", "preflight")[0]["tor_verified"], False
        )
        self.assert_clean()

    def test_sigint_stops_issuing_reaps_and_reports_missing_pairs(self):
        self.assert_signal_cancellation(signal.SIGINT)

    def test_sigterm_stops_issuing_reaps_and_reports_missing_pairs(self):
        self.assert_signal_cancellation(signal.SIGTERM)

    def assert_signal_cancellation(self, interruption):
        # Separate test instances isolate process ownership and temporary files
        # even when one signal case fails before sending its interruption.
        process = self.spawn(
            "--workers",
            2,
            "--trials",
            3,
            "--control",
            "always",
            "--control-scope",
            "trial",
            targets=[
                "alpha.example.test",
                "beta.example.test",
                "waiting.example.test",
            ],
            env={"MEASUREMENT_TEST_LOG_WRITE_DELAY": "0.01"},
            plan={
                "https://alpha.example.test": [{"delay": 30, "child": True}],
                "https://beta.example.test": [{"delay": 30, "child": True}],
            },
        )
        self.wait_for_calls(3, process, children=2)
        process.send_signal(interruption)
        stdout, stderr = process.communicate(timeout=6)
        self.assertNotEqual(process.returncode, 0, stderr)
        rows = self.parse(stdout)
        end = self.assert_accounting(rows)
        self.assertEqual(end["state"], "interrupted")
        self.assertEqual(len(self.calls()), 3)
        self.assertTrue(
            any(r["state"] == "not_started" for r in end["target_states"])
        )
        pairs = self.select(rows, "pair_end")
        self.assertTrue(pairs)
        self.assertTrue(all(r["state"] == "missing" for r in pairs))
        self.assertTrue(all(r["late"] is None for r in pairs))
        self.assert_no_owned_children()
        self.assert_clean()

    def test_runtime_source_and_request_directory_errors_never_claim_success(self):
        specification = importlib.util.spec_from_file_location(
            "measurement_fault_subject", ROOT / "check_tor_measure.py"
        )
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        for fault in ("source", "request-directory", "launch"):
            with self.subTest(fault=fault):
                records = []

                class CaptureWriter:
                    failed = False

                    def __init__(self, common):
                        self.common = common

                    def emit(self, kind, **fields):
                        records.append(dict(self.common, type=kind, **fields))

                    def restore(self):
                        pass

                with mock.patch.object(coordinator, "Writer", CaptureWriter):
                    args = coordinator.arguments([str(self.input)])
                    engine = coordinator.Engine(
                        args, coordinator.load_targets(self.input)
                    )
                operation = (
                    mock.patch.object(
                        Path,
                        "read_bytes",
                        side_effect=OSError("synthetic source failure"),
                    )
                    if fault == "source"
                    else mock.patch.object(
                        Path,
                        "mkdir",
                        side_effect=OSError("synthetic directory failure"),
                    )
                    if fault == "request-directory"
                    else contextlib.nullcontext()
                )
                with (
                    operation,
                    mock.patch.object(
                        coordinator.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, stdout=b"{}"),
                    ),
                    mock.patch.object(
                        coordinator.subprocess,
                        "Popen",
                        side_effect=OSError("synthetic launch failure")
                        if fault == "launch"
                        else None,
                    ) as popen,
                ):
                    self.assertEqual(engine.run(), 1)
                    self.assertEqual(
                        popen.call_count,
                        1 if fault == "launch" else 0,
                        "unexpected observation invocation count",
                    )
                self.assertEqual(records[-1]["type"], "run_end")
                self.assertEqual(records[-1]["state"], "error")
                self.assertIs(records[-1]["complete"], False)
                self.assertEqual(
                    records[-1]["counts"]["target"], {"issued": 0, "completed": 0}
                )
                self.assertFalse(Path(engine.temp.name).exists())
                self.assertEqual(
                    records[-1]["counts"]["preflight"], {"issued": 0, "completed": 0}
                )
                if fault == "launch":
                    starts = self.select(records, "attempt_start")
                    self.assertEqual(len(starts), 1)
                    self.assertIs(starts[0]["adapter_started"], False)
                    self.assertIs(
                        self.select(records, "attempt_end")[0]["complete"], False
                    )

    def test_departing_group_permission_transition_retries_only_owned_group(self):
        specification = importlib.util.spec_from_file_location(
            "measurement_group_fault_subject", ROOT / "check_tor_measure.py"
        )
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        engine = object.__new__(coordinator.Engine)
        leader = mock.Mock()
        leader.poll.return_value = None
        engine.active = {42: {"process": leader}}
        # Reproduce macOS's transient EPERM before waitpid observes departure.
        with mock.patch.object(
            coordinator.os, "killpg", side_effect=[PermissionError(), None]
        ) as send:
            engine.kill_group(42, signal.SIGTERM)
            self.assertEqual(send.call_args_list, [mock.call(42, signal.SIGTERM)] * 2)
        # A denial that persists against a live leader must never be ignored.
        with mock.patch.object(coordinator.os, "killpg", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                engine.kill_group(42, signal.SIGTERM)

    def test_output_oserror_stops_before_requests_and_cleans_up(self):
        specification = importlib.util.spec_from_file_location(
            "measurement_output_fault_subject", ROOT / "check_tor_measure.py"
        )
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        args = coordinator.arguments([str(self.input)])
        engine = coordinator.Engine(args, coordinator.load_targets(self.input))
        with (
            mock.patch.object(
                coordinator.os, "write", side_effect=OSError("synthetic output failure")
            ),
            mock.patch.object(
                coordinator.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout=b"{}"),
            ),
            mock.patch.object(coordinator.subprocess, "Popen") as popen,
        ):
            self.assertEqual(engine.run(), 1)
            self.assertEqual(
                popen.call_count, 0, "observation subprocess launched before fault"
            )
        self.assertIs(engine.writer.failed, True)
        self.assertFalse(Path(engine.temp.name).exists())

    def test_local_adapter_failure_is_an_error_without_a_native_verdict(self):
        copy = self.temp / "scanner-copy"
        copy.mkdir()
        for filename in (
            "check_tor.zsh",
            "check_tor_core.zsh",
            "check_tor_measure.py",
            "check_tor_probe.zsh",
            "check_tor_retry.py",
        ):
            shutil.copy2(ROOT / filename, copy / filename)
        (copy / "check_tor_probe.zsh").write_text(
            "#!/usr/bin/env zsh\nprint -r -- '{}'\n"
        )
        status, rows, error = self.run_scan(scanner_path=copy / "check_tor.zsh")
        self.assertNotEqual(status, 0)
        self.assertEqual(self.calls(), [])
        ends = self.select(rows, "attempt_end")
        self.assertEqual(len(ends), 1)
        self.assertEqual(ends[0]["status"], "error")
        self.assertIs(ends[0]["complete"], False)
        for key in ("verdict", "http_status", "curl_exit", "body_limited"):
            self.assertIsNone(ends[0][key])
        self.assertEqual(self.assert_accounting(rows)["state"], "error")
        self.assert_clean()

    def test_legacy_controls_and_requested_timeout_metadata(self):
        for control, direct_count in [("always", 1), ("never", 0)]:
            self.clear_logs()
            status, rows, error = self.run_scan(
                "--control",
                control,
                "--timeout-first",
                17,
                "--timeout-retry",
                13,
                "--timeout-clearnet",
                11,
                plan={"https://alpha.example.test|tor": [{"code": 403}, {"code": 200}]},
            )
            self.assertEqual(status, 0, error)
            ends = self.select(rows, "attempt_end", "target")
            self.assertEqual(
                [row["requested_timeout"] for row in ends],
                [17, 13] + ([11] if direct_count else []),
            )
            self.assertEqual(
                sum(row["route"] == "direct" for row in ends), direct_count
            )
            start = self.select(rows, "run_start")[0]
            self.assertEqual(start["settings"]["trial_policy"], "failure-retry")
            self.assertRegex(start["scanner"]["source_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(start["planned"]["target_count"], 1)
            self.assertGreaterEqual(
                start["planned"]["target_requests_upper_bound"], len(ends)
            )
            self.assert_accounting(rows)

    def test_empty_curl_metadata_fields_do_not_shift_error_text(self):
        diagnostic = "synthetic diagnostic\twith tab"
        status, rows, error = self.run_scan(
            "--control",
            "never",
            "--circuits",
            1,
            plan={
                "https://alpha.example.test": [
                    {
                        "exit": 28,
                        "code": "000",
                        "tls": "",
                        "final_url": "",
                        "error": diagnostic,
                    }
                ]
            },
        )
        self.assertEqual(status, 0, error)
        target = self.select(rows, "attempt_end", "target")[0]
        self.assertIs(target["complete"], True)
        self.assertEqual(target["verdict"], "TIMEOUT")
        self.assertEqual(target["curl_exit"], 28)
        self.assertIsNone(target["http_status"])
        self.assertIsNone(target["final_url"])
        self.assertEqual(target["redirect_count"], 0)
        self.assertEqual(target["curl_error"], diagnostic)
        self.assertIsNone(target["local_error"])
        self.assert_accounting(rows)
        self.assert_clean()

    def test_curl_write_error_is_local_unless_body_cap_was_reached(self):
        status, rows, error = self.run_scan(
            "--trials",
            2,
            "--control",
            "never",
            targets=["alpha.example.test", "must-not-run.example.test"],
            plan={
                "https://alpha.example.test": [
                    {"exit": 23, "error": "Failed writing received data"}
                ]
            },
        )
        self.assertNotEqual(status, 0, error)
        self.assertEqual(
            [call["url"] for call in self.calls()],
            [PREFLIGHT, "https://alpha.example.test"],
        )
        target = self.select(rows, "attempt_end", "target")[0]
        self.assertEqual(target["status"], "error")
        self.assertIs(target["complete"], False)
        self.assertIsNone(target["verdict"])
        self.assertEqual(target["http_status"], 200)
        self.assertEqual(target["curl_exit"], 23)
        self.assertEqual(target["curl_error"], "Failed writing received data")
        self.assertIs(target["body_limited"], False)
        self.assertTrue(target["local_error"])
        self.assertEqual(self.assert_accounting(rows)["state"], "error")
        self.assert_clean()
        self.clear_logs()
        status, rows, error = self.run_scan(
            "--control",
            "never",
            targets=["alpha.example.test"],
            plan={
                "https://alpha.example.test": [{"exit": 23, "body_bytes": 1024 * 1024}]
            },
        )
        self.assertEqual(status, 0, error)
        target = self.select(rows, "attempt_end", "target")[0]
        self.assertEqual(target["status"], "complete")
        self.assertIs(target["complete"], True)
        self.assertEqual(target["verdict"], "WARN")
        self.assertEqual(target["curl_exit"], 23)
        self.assertIs(target["body_limited"], True)
        self.assertEqual(self.assert_accounting(rows)["state"], "complete")
        self.assert_clean()

    def test_preflight_sink_failure_is_a_setup_error(self):
        executable = shutil.which("head")
        wrapper = self.bin / "head"
        wrapper.write_text(
            "#!"
            + sys.executable
            + "\nimport subprocess,sys\nsubprocess.run(["
            + repr(executable)
            + "] + sys.argv[1:], check=False)\nsys.exit(1)\n"
        )
        wrapper.chmod(0o755)
        status, rows, error = self.run_scan()
        self.assertNotEqual(status, 0, error)
        self.assertEqual([call["url"] for call in self.calls()], [PREFLIGHT])
        preflight = self.select(rows, "attempt_end", "preflight")[0]
        self.assertEqual(preflight["status"], "error")
        self.assertIs(preflight["complete"], False)
        self.assertIsNone(preflight["verdict"])
        self.assertEqual(preflight["http_status"], 200)
        self.assertEqual(preflight["curl_exit"], 0)
        self.assertTrue(preflight["local_error"])
        end = self.assert_accounting(rows)
        self.assertEqual(end["state"], "error")
        self.assertEqual(end["counts"]["target"], {"issued": 0, "completed": 0})
        self.assertEqual(len(self.calls("end")), 1)
        self.assert_no_owned_children()
        self.assert_clean()

    def test_local_processing_failures_preserve_transport_and_stop_run(self):
        for command in ("head", "awk", "wc"):
            with self.subTest(command=command):
                self.clear_logs()
                executable = shutil.which(command)
                wrapper = self.bin / command
                # Complete the real read first, then fail locally. In the head
                # case this lets curl finish successfully and isolates the sink
                # failure from a transport error or a broken response pipe.
                real_command = "[" + repr(executable) + "] + sys.argv[1:]"
                if command == "head":
                    behavior = (
                        "result=subprocess.run("
                        + real_command
                        + ", stdout=subprocess.PIPE, check=False)\n"
                        "sys.stdout.buffer.write(result.stdout)\n"
                        "sys.exit(result.returncode if b'IsTor' in result.stdout else 1)\n"
                    )
                elif command == "wc":
                    behavior = (
                        "body=sys.stdin.buffer.read()\n"
                        "if b'IsTor' in body:\n"
                        "    sys.exit(subprocess.run("
                        + real_command
                        + ", input=body, check=False).returncode)\n"
                        "print('invalid-byte-count')\n"
                    )
                else:
                    behavior = (
                        "subprocess.run("
                        + real_command
                        + ", check=False)\nsys.exit(1)\n"
                    )
                wrapper.write_text(
                    "#!" + sys.executable + "\nimport subprocess,sys\n" + behavior
                )
                wrapper.chmod(0o755)
                try:
                    status, rows, error = self.run_scan(
                        "--trials",
                        2,
                        "--control",
                        "always",
                        targets=["alpha.example.test", "must-not-run.example.test"],
                        plan={
                            "https://alpha.example.test": [
                                {"body": "synthetic response"}
                            ]
                        },
                    )
                finally:
                    wrapper.unlink()
                self.assertNotEqual(status, 0, error)
                self.assertEqual(
                    [call["url"] for call in self.calls()],
                    [PREFLIGHT, "https://alpha.example.test"],
                )
                target = self.select(rows, "attempt_end", "target")
                self.assertEqual(len(target), 1)
                self.assertEqual(target[0]["status"], "error")
                self.assertIs(target[0]["complete"], False)
                self.assertIsNone(target[0]["verdict"])
                self.assertEqual(target[0]["http_status"], 200)
                self.assertEqual(target[0]["curl_exit"], 0)
                self.assertEqual(target[0]["final_url"], "https://alpha.example.test")
                self.assertTrue(target[0]["local_error"])
                if command == "wc":
                    self.assertIsNone(target[0]["body_limited"])
                end = self.assert_accounting(rows)
                self.assertEqual(end["state"], "error")
                self.assertEqual(end["counts"]["target"], {"issued": 1, "completed": 0})
                self.assertEqual(
                    len(self.calls("end")),
                    2,
                    "fake curl must finish before the local processing failure",
                )
                self.assert_no_owned_children()
                self.assert_clean()

    def test_delayed_body_sink_finishes_before_classification(self):
        head = shutil.which("head")
        delayed = self.bin / "head"
        delayed.write_text(
            "#!"
            + sys.executable
            + "\nimport os,sys,time\ntime.sleep(0.1)\nos.execv("
            + repr(head)
            + ", ["
            + repr(head)
            + "] + sys.argv[1:])\n"
        )
        delayed.chmod(0o755)
        status, rows, error = self.run_scan(
            "--control",
            "never",
            "--circuits",
            1,
            plan={
                "https://alpha.example.test": [
                    {"code": 403, "body": "error code: 1020"}
                ]
            },
        )
        self.assertEqual(status, 0, error)
        result = self.select(rows, "attempt_end", "target")[0]
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("Cloudflare 1020", result["detail"])
        self.assert_clean()

    def test_body_limit_remains_inconclusive_and_does_not_retry(self):
        status, rows, error = self.run_scan(
            plan={
                "https://alpha.example.test": [
                    {"code": 403, "body_bytes": 2 * 1024 * 1024}
                ]
            }
        )
        self.assertEqual(status, 0, error)
        ends = self.select(rows, "attempt_end", "target")
        self.assertEqual(len(ends), 1)
        self.assertEqual(ends[0]["verdict"], "WARN")
        self.assertIs(ends[0]["body_limited"], True)
        self.assert_clean()

    def test_redirect_userinfo_is_never_stored(self):
        status, rows, error = self.run_scan(
            "--control",
            "never",
            plan={
                "https://alpha.example.test": [
                    {
                        "redirects": 1,
                        "final_url": "https://private-user:private-password@redirect.example.test/destination?q=1",
                    }
                ]
            },
        )
        self.assertEqual(status, 0, error)
        serialized = json.dumps(rows) + error
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("private-password", serialized)
        self.assertEqual(
            self.select(rows, "attempt_end", "target")[0]["final_url"],
            "https://redirect.example.test/destination?q=1",
        )
        self.assertEqual(
            self.select(rows, "attempt_end", "target")[0]["redirect_count"], 1
        )

    def test_cancelled_conditional_observation_keeps_missing_pair(self):
        specification = importlib.util.spec_from_file_location(
            "measurement_cancel_subject", ROOT / "check_tor_measure.py"
        )
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        # Exercise both the normal finish path and a result drained in cleanup.
        for during_drain in (False, True):
            with self.subTest(during_drain=during_drain):
                self.clear_logs()
                records = []

                class CaptureWriter:
                    failed = False

                    def __init__(self, common):
                        self.common = common

                    def emit(self, kind, **fields):
                        records.append(dict(self.common, type=kind, **fields))
                        if (
                            not during_drain
                            and kind == "attempt_end"
                            and fields.get("phase") == "target"
                        ):
                            os.kill(os.getpid(), signal.SIGTERM)

                    def restore(self):
                        pass

                original_finish = coordinator.Engine.finish

                def finish(engine, task, abort=False):
                    if during_drain and task["fields"]["phase"] == "target":
                        os.kill(os.getpid(), signal.SIGTERM)
                        abort = True
                    return original_finish(engine, task, abort=abort)

                handlers = {
                    sig: signal.getsignal(sig)
                    for sig in (signal.SIGINT, signal.SIGTERM)
                }
                try:
                    with (
                        mock.patch.dict(
                            os.environ,
                            dict(
                                self.environment,
                                MEASUREMENT_TEST_PLAN=json.dumps(
                                    {"https://alpha.example.test": [{"code": 403}]}
                                ),
                            ),
                        ),
                        mock.patch.object(coordinator, "Writer", CaptureWriter),
                        mock.patch.object(coordinator.Engine, "finish", finish),
                    ):
                        code = coordinator.main(
                            [
                                "--trials",
                                "1",
                                "--control",
                                "conditional",
                                "--control-scope",
                                "trial",
                                str(self.input),
                            ]
                        )
                finally:
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
                self.assertEqual(code, 143)
                attempts = self.select(records, "attempt_end", "target")
                self.assertEqual(len(attempts), 1)
                self.assertTrue(attempts[0]["complete"])
                pairs = self.select(records, "pair_end")
                self.assertEqual(len(pairs), 1)
                self.assertEqual(pairs[0]["missing_routes"], ["direct"])
                self.assertEqual(pairs[0]["state"], "missing")
                self.assertEqual(records[-1]["state"], "interrupted")
                self.assertEqual(len(self.calls()), 2)
                self.assert_clean()
                self.assert_no_owned_children()

    def test_cautious_hostname_stops_both_routes_and_normalized_duplicates(self):
        for order, route in (("tor-first", "tor"), ("direct-first", "direct")):
            with self.subTest(order=order):
                self.clear_logs()
                status, rows, error = self.run_scan(
                    "--execution-policy", "paired-cautious", "--trials", 3,
                    "--control", "always", "--control-scope", "trial", "--order", order,
                    targets=["alpha.example.test/a", "ALPHA.example.test.:8443/b", "beta.example.test"],
                    plan={"https://alpha.example.test/a|" + route: [{"code": 429}]},
                )
                self.assertEqual(status, 3, error)
                ends = self.select(rows, "attempt_end", "target")
                self.assertEqual(sum(r["target_id"] == "target-1" for r in ends), 1)
                self.assertFalse(any(r["target_id"] == "target-2" for r in ends))
                self.assertEqual(sum(r["target_id"] == "target-3" for r in ends), 6)
                trigger = next(r for r in ends if r["http_status"] == 429)
                self.assertTrue(trigger["complete"])
                self.assertEqual(trigger["verdict"], "RATELIMIT")
                omissions = self.select(rows, "target_omission")
                self.assertEqual(len(omissions), 2)
                self.assertTrue(all(r["triggering_attempt_id"] == trigger["attempt_id"] for r in omissions))
                self.assertEqual([sum(x["count"] for x in r["known_required"]) for r in omissions], [5, 6])
                pair = self.select(rows, "pair_end")[0]
                self.assertEqual(pair["state"], "missing")
                self.assertEqual(pair["aborted_routes"], [])
                self.assertIsNone(pair["observed_start_gap_seconds"])
                self.assertEqual(pair["missing_reason"]["triggering_attempt_id"], trigger["attempt_id"])
                end = rows[-1]
                self.assertEqual(end["state"], "policy_stopped")
                self.assertIs(end["complete"], False)
                self.assertIs(end["schedule_complete"], False)
                self.assertIs(end["policy_truncated"], True)
                self.assertEqual(end["omission_counts"], {"known_required": 11, "eligibility_undetermined": 0})
                self.assertEqual([r["state"] for r in end["target_states"]], ["partial", "not_started", "complete"])
                self.assert_accounting(rows)

    def test_cautious_second_member_429_preserves_pair_and_omits_later_trials(self):
        for order, route in (("tor-first", "direct"), ("direct-first", "tor")):
            with self.subTest(order=order):
                self.clear_logs()
                status, rows, error = self.run_scan(
                    "--execution-policy", "paired-cautious", "--trials", 2,
                    "--control", "always", "--control-scope", "trial", "--order", order,
                    plan={"https://alpha.example.test|" + route: [{"code": 429}]},
                )
                self.assertEqual(status, 3, error)
                self.assertEqual(len(self.select(rows, "attempt_end", "target")), 2)
                pair = self.select(rows, "pair_end")[0]
                self.assertEqual(pair["state"], "complete")
                self.assertEqual(pair["missing_routes"], [])
                self.assertNotIn("missing_reason", pair)
                self.assertEqual(rows[-1]["omission_counts"], {"known_required": 2, "eligibility_undetermined": 0})
                self.assertEqual(rows[-1]["target_states"][0]["state"], "partial")
                self.assert_accounting(rows)

    def test_cautious_conditional_and_retry_eligibility_accounting(self):
        for fixed in (True, False):
            with self.subTest(fixed=fixed):
                self.clear_logs()
                options = (["--trials", 3, "--control-scope", "trial"] if fixed else ["--circuits", 3])
                status, rows, error = self.run_scan(
                    "--execution-policy", "paired-cautious", *options,
                    plan={"https://alpha.example.test": [{"code": 429}]},
                )
                self.assertEqual(status, 3, error)
                counts = rows[-1]["omission_counts"]
                self.assertEqual(counts, {"known_required": 3 if fixed else 1, "eligibility_undetermined": 2})
                omission = self.select(rows, "target_omission")[0]
                self.assertEqual(omission["reason"], "hostname_stop")
                if fixed:
                    self.assertEqual(self.select(rows, "pair_end")[0]["missing_routes"], ["direct"])
                self.assertEqual(len(self.select(rows, "attempt_start", "target")), 1)
                self.assert_accounting(rows)

    def test_cautious_final_429_and_non429_preserve_full_coverage(self):
        for code in (429, 503, 403, 200):
            with self.subTest(code=code):
                self.clear_logs()
                status, rows, error = self.run_scan(
                    "--execution-policy", "paired-cautious", "--trials", 1,
                    "--control", "always", "--control-scope", "trial",
                    plan={"https://alpha.example.test|direct": [{"code": code}]},
                )
                self.assertEqual(status, 0, error)
                self.assertEqual(rows[-1]["state"], "complete")
                self.assertTrue(rows[-1]["schedule_complete"])
                self.assertFalse(rows[-1]["policy_truncated"])
                self.assertEqual(len(self.select(rows, "hostname_stop")), int(code == 429))
                self.assertEqual(self.select(rows, "target_omission"), [])
                self.assertEqual(self.select(rows, "pair_end")[0]["state"], "complete")
                self.assert_accounting(rows)
        self.clear_logs()
        status, rows, error = self.run_scan(
            "--trials", 2, "--control", "always", "--control-scope", "trial",
            plan={"https://alpha.example.test": [{"code": 429}]},
        )
        self.assertEqual(status, 0, error)
        self.assertEqual(len(self.select(rows, "attempt_end", "target")), 4)
        self.assertNotIn("policy_truncated", rows[-1])

    def test_cautious_virtual_clock_prioritizes_ready_partners(self):
        specification = importlib.util.spec_from_file_location("measurement_priority_subject", ROOT / "check_tor_measure.py")
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        # All order variants use two concurrent bundles. Drain one completion
        # at a time so the second must be consumed before any new launch.
        for control, order, trials in (("always", "tor-first", 1), ("always", "direct-first", 1),
                                       ("always", "counterbalanced", 1), ("conditional", "tor-first", 2)):
            with self.subTest(control=control, order=order):
                records, launches = [], []
                clock = [0.0]
                self.input.write_text("alpha.example.test\nbeta.example.test\ngamma.example.test\n")
                options = ["--execution-policy", "paired-cautious", "--trials", str(trials),
                           "--control", control, "--control-scope", "trial", "--order", order,
                           "--workers", "2", "--start-gap", "0.25"]
                if order == "counterbalanced":
                    options += ["--seed", "0"]

                class CaptureWriter:
                    failed = False
                    def __init__(self, common):
                        pass
                    def emit(self, kind, **fields):
                        records.append(dict(type=kind, **fields))
                    def restore(self):
                        pass

                with mock.patch.object(coordinator, "Writer", CaptureWriter):
                    engine = coordinator.Engine(coordinator.arguments(options + [str(self.input)]), coordinator.load_targets(self.input))

                def launch(bundle):
                    if engine.last_launch is not None and clock[0] - engine.last_launch < 0.25:
                        return False
                    route, trial, pair = bundle.pending
                    self.assertLess(len(engine.active), 2)
                    launches.append((bundle.target["target_id"], route, trial, clock[0]))
                    bundle.issued += 1
                    bundle.active = dict(bundle=bundle, request=bundle.pending, start=clock[0],
                                         due=(1.0 if control == "conditional" or len(launches) == 2 else 1.25)
                                         if len(launches) <= 2 else clock[0] + 0.5)
                    bundle.pending = None
                    engine.active[bundle.target["target_id"]] = bundle.active
                    engine.last_launch = clock[0]
                    return True

                def read_ready(wait=0.02):
                    clock[0] = round(clock[0] + wait, 9)
                    for key, task in list(engine.active.items()):
                        if task["due"] > clock[0]:
                            continue
                        bundle = task["bundle"]
                        route, trial, pair = task["request"]
                        observation = dict(route=route, trial_id=trial, complete=True, status="complete",
                                           verdict="FAIL" if key == "target-2" and control == "conditional" else "PASS",
                                           attempt_id="virtual-" + str(len(launches)), _start=task["start"])
                        bundle.history = getattr(bundle, "history", []) + [observation]
                        bundle.completed += 1
                        if pair:
                            bundle.pairs[pair]["attempts"][route] = observation
                        bundle.active = None
                        del engine.active[key]
                        bundle.advance(observation)
                        return True
                    return False

                try:
                    with mock.patch.object(engine, "launch", launch), mock.patch.object(engine, "read_ready", read_ready):
                        engine.run_cautious_targets()
                finally:
                    engine.selector.close()
                    engine.temp.cleanup()
                self.assertEqual([x[0] for x in launches[:2]], ["target-1", "target-2"])
                if control == "conditional":
                    # Alpha's next Tor trial is pending unpaired work; beta's
                    # conditional direct partner takes the first freed slot.
                    self.assertEqual(launches[2][:2], ("target-2", "direct"))
                else:
                    # Both ready partners win before gamma is admitted.
                    self.assertEqual([x[0] for x in launches[2:4]], ["target-2", "target-1"])
                    gamma_start = next(i for i, x in enumerate(launches) if x[0] == "target-3")
                    self.assertGreaterEqual(gamma_start, 4)
                self.assertTrue(all(b[3] - a[3] >= 0.25 - 1e-9 for a, b in zip(launches, launches[1:])))
                self.assertTrue(all(r["state"] == "complete" for r in records if r["type"] == "bundle_end"))

    def test_cautious_terminal_precedence_and_independent_coverage(self):
        specification = importlib.util.spec_from_file_location("measurement_terminal_subject", ROOT / "check_tor_measure.py")
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        for fault in ("error_after_stop", "cancel_after_stop", "cleanup", "late_cancel", "terminal_output"):
            with self.subTest(fault=fault):
                self.clear_logs()
                coordinator.CANCELLED = 0
                records = []
                stopped = fault.endswith("after_stop")
                self.input.write_text("alpha.example.test\nALPHA.example.test./duplicate\nbeta.example.test\n" if stopped else "alpha.example.test\n")

                class CaptureWriter:
                    failed = False
                    def __init__(self, common):
                        self.common = common
                    def emit(self, kind, **fields):
                        if fault == "error_after_stop" and kind == "bundle_start" and fields["target_id"] == "target-3":
                            raise coordinator.Failure("synthetic unrelated failure")
                        if fault == "terminal_output" and kind == "run_end":
                            self.failed = True
                            raise coordinator.OutputFailure("synthetic missing terminal")
                        records.append(dict(self.common, type=kind, **fields))
                        if fault == "cancel_after_stop" and kind == "target_omission":
                            coordinator.CANCELLED = signal.SIGTERM
                    def restore(self):
                        pass

                options = ["--execution-policy", "paired-cautious", "--trials", "1",
                           "--control", "always", "--control-scope", "trial", str(self.input)]
                with mock.patch.object(coordinator, "Writer", CaptureWriter):
                    engine = coordinator.Engine(coordinator.arguments(options), coordinator.load_targets(self.input))
                original_cleanup = engine.cleanup

                def cleanup():
                    original_cleanup()
                    if fault == "cleanup":
                        raise OSError("synthetic late cleanup failure")
                    if fault == "late_cancel":
                        coordinator.CANCELLED = signal.SIGTERM

                with mock.patch.dict(os.environ, dict(self.environment, MEASUREMENT_TEST_PLAN=json.dumps(
                    {"https://alpha.example.test": [{"code": 429}]} if stopped else {}
                ))), mock.patch.object(engine, "cleanup", cleanup):
                    engine.env.update(os.environ)
                    code = engine.run()
                if fault == "terminal_output":
                    self.assertEqual(code, 1)
                    self.assertEqual(self.select(records, "run_end"), [])
                    self.assertTrue(all(x["complete"] for x in self.select(records, "attempt_end")))
                    continue
                end = records[-1]
                self.assertEqual(end["state"], "interrupted" if "cancel" in fault else "error")
                self.assertEqual(code, 143 if "cancel" in fault else 1)
                self.assertFalse(end["complete"])
                self.assertEqual(end["policy_truncated"], stopped)
                self.assertEqual(end["schedule_complete"], not stopped)
                if stopped:
                    self.assertEqual(end["omission_counts"]["known_required"], 3)
                    self.assertEqual(end["schedule_accounting"]["known_required_unresolved"], 2)
                    self.assertEqual(end["target_states"][1]["state"], "not_started")
                else:
                    self.assertEqual(end["schedule_accounting"]["known_required_unresolved"], 0)
                self.assert_accounting(records)
                self.assert_clean()
        coordinator.CANCELLED = 0

    def test_cautious_direct_first_failure_keeps_first_tor_requirement(self):
        specification = importlib.util.spec_from_file_location("measurement_retry_subject", ROOT / "check_tor_measure.py")
        coordinator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(coordinator)
        args = coordinator.arguments([
            "--execution-policy", "paired-cautious", "--circuits", "3",
            "--control", "always", "--order", "direct-first", str(self.input),
        ])
        bundle = coordinator.Bundle(coordinator.load_targets(self.input)[0], args)
        bundle.advance()
        self.assertEqual(bundle.pending[0], "direct")
        # A launched direct request failed or was aborted before the first Tor
        # observation. Its failure cannot erase the unconditional first Tor.
        bundle.last_request, bundle.pending = bundle.pending, None
        engine = object.__new__(coordinator.Engine)
        engine.args = args
        known, unknown = engine.remaining_work(bundle)
        self.assertEqual(sum(x["count"] for x in known), 2)
        self.assertEqual(sum(x["count"] for x in unknown), 2)
        self.assertEqual(known[0]["route"], "tor")
        self.assertEqual(known[0]["trial_range"], [1, 1])
        self.assertEqual(unknown[0]["trial_range"], [2, 3])

    def test_cautious_validation_before_input_and_unnecessary_controls(self):
        status, rows, error = self.run_scan(
            "--execution-policy", "invalid", input_path=self.temp / "nonexistent.txt"
        )
        self.assertEqual(status, 2)
        self.assertIn("invalid choice", error)
        self.assertEqual(rows, [])
        self.assertEqual(self.calls(), [])
        status, rows, error = self.run_scan(
            "--execution-policy", "paired-cautious", "--trials", 3,
            "--control", "conditional", "--control-scope", "trial",
        )
        self.assertEqual(status, 0, error)
        self.assertEqual(rows[-1]["schedule_accounting"]["known_unnecessary"], 3)
        self.assertEqual(rows[-1]["schedule_accounting"]["known_required_unresolved"], 0)
        self.assertTrue(rows[-1]["schedule_complete"])
        self.assert_accounting(rows)

    def test_closed_stdout_stops_and_reaps(self):
        process = self.spawn(
            "--workers",
            2,
            "--control",
            "never",
            targets=["alpha.example.test", "beta.example.test"],
            plan={
                "https://alpha.example.test": [{"delay": 0.15}],
                "https://beta.example.test": [{"delay": 30, "child": True}],
            },
        )
        self.wait_for_calls(3, process)
        process.stdout.close()
        process.wait(timeout=6)
        process.stderr.close()
        self.assertNotEqual(process.returncode, 0)
        self.assert_no_owned_children()
        self.assert_clean()

    def test_blocked_stdout_can_be_interrupted(self):
        targets = [f"target-{number}.example.test" for number in range(16)]
        process = self.spawn(
            "--workers", 4, "--trials", 100, "--control", "never", targets=targets
        )
        self.wait_for_calls(5, process)
        # Leave the pipe unread long enough for detailed records to fill it.
        time.sleep(0.15)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=6)
        self.assertNotEqual(process.returncode, 0, stderr)
        rows = self.parse(stdout)
        if self.select(rows, "run_end"):
            self.assertEqual(
                self.select(rows, "run_end")[-1]["state"],
                "interrupted",
                self.select(rows, "run_end")[-1].get("error"),
            )
        self.assert_no_owned_children()
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
