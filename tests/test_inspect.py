"""Offline tests for saved native measurement evidence."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_tor_inspect as inspector
import test_measurement


COMMON = dict(schema_version=2, execution_id="offline-execution", run_id=None, group_id=None)
TARGET = dict(
    target_id="target-1",
    target_occurrence=1,
    bundle_id="bundle-1",
    original_input="example.test",
    url="https://example.test",
)
PAIR_ID = "bundle-1-pair-1"


def event(kind, **fields):
    return dict(COMMON, type=kind, **fields)


def attempt(order, phase, route, *, status="complete", verdict=None, issued=True):
    is_preflight = phase == "preflight"
    identity = dict.fromkeys(TARGET)
    identity["url"] = "https://check.torproject.org/api/ip"
    fields = dict(
        identity if is_preflight else TARGET,
        attempt_id=f"attempt-{order}",
        phase=phase,
        route=route,
        global_order=order,
        bundle_order=None if is_preflight else order - 1,
        trial_id=None if is_preflight else 1,
        pair_id=None if is_preflight else PAIR_ID,
        pairing_state="not_paired" if is_preflight else "planned",
        requested_timeout=15 if is_preflight else 20,
        started_at="2026-11-15T12:00:00.000Z",
        adapter_started=issued,
    )
    return (
        event("attempt_start", **fields),
        event(
            "attempt_end",
            **fields,
            status=status,
            complete=status == "complete",
            tor_verified=True if is_preflight else None,
            http_status=403 if verdict == "BLOCKED" else None,
            verdict=verdict,
        ),
    )


def completed_run():
    return [
        event(
            "run_start",
            settings=dict(
                timeout_preflight=15,
                trials=1,
                control="always",
                control_scope="trial",
                max_partner_gap=60,
                request_profile={"preflight_timeout": 15},
            ),
            planned=dict(target_count=1, target_requests_upper_bound=2, preflight_requests=1),
        ),
        *attempt(1, "preflight", "tor"),
        event("bundle_start", **TARGET, state="started"),
        *attempt(2, "target", "tor", verdict="BLOCKED"),
        *attempt(3, "target", "direct", verdict="TIMEOUT"),
        event(
            "pair_end",
            **TARGET,
            pair_id=PAIR_ID,
            trial_id=1,
            attempt_ids={"tor": "attempt-2", "direct": "attempt-3"},
            observed_start_gap_seconds=0.1,
            late=False,
            state="complete",
            missing_routes=[],
            aborted_routes=[],
        ),
        event("bundle_end", **TARGET, state="complete", attempts_issued=2, attempts_completed=2),
        event(
            "run_end",
            state="complete",
            complete=True,
            exit_code=0,
            counts=dict(preflight=dict(issued=1, completed=1), target=dict(issued=2, completed=2)),
            target_states=[dict(TARGET, state="complete")],
            verdict_counts=dict(tor={"BLOCKED": 1}, direct={"TIMEOUT": 1}),
            error=None,
        ),
    ]


def incomplete_pair_run(status, issued):
    rows = completed_run()
    rows[6:8] = attempt(3, "target", "direct", status=status, issued=issued)
    pair, bundle, terminal = rows[-3:]
    pair.update(state="missing", missing_routes=["direct"])
    if status == "aborted":
        pair["aborted_routes"] = ["direct"]
    if not issued:
        pair.update(attempt_ids={"tor": "attempt-2"}, late=None, observed_start_gap_seconds=None)
    total = int(issued) + 1
    bundle.update(state="partial", attempts_issued=total, attempts_completed=1)
    terminal.update(
        state="interrupted" if issued else "error",
        complete=False,
        exit_code=143 if issued else 1,
        target_states=[dict(TARGET, state="partial")],
        verdict_counts=dict(tor={"BLOCKED": 1}, direct={}),
        error=None if issued else "local adapter execution failed",
    )
    terminal["counts"]["target"].update(issued=total, completed=1)
    return rows


class InspectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="check-tor-inspect-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "saved.jsonl"

    def save(self, rows):
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def test_complete_negative_observations_and_older_v2(self):
        rows = completed_run()
        del rows[0]["settings"]["timeout_preflight"]
        rows[0]["settings"]["future_setting"] = {"ignored": True}
        rows[4]["new_evidence"] = [1, 2, 3]
        self.save(rows)
        report = inspector.inspect_file(self.path, 0)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["outcome"], "complete")
        self.assertEqual(report["pairs"], {"complete": 1, "missing": 0})
        self.assertEqual(report["verdict_counts"], {"tor": {"BLOCKED": 1}, "direct": {"TIMEOUT": 1}})
        self.assertEqual(report["attempts"]["target"]["direct"]["completed"], 1)
        self.assertEqual(inspector.inspect_file(self.path)["outcome"], "unverified")

    def test_native_policy_and_preflight_error(self):
        for stop, scanner_status in ((True, 3), (False, 1)):
            with self.subTest(stop=stop):
                scanner = test_measurement.MeasurementTests()
                scanner.setUp()
                try:
                    code, rows, stderr = scanner.run_scan(
                        "--execution-policy", "paired-cautious",
                        "--trials", "2", "--control-scope", "trial", "--control", "always",
                        targets=["alpha.example.test/a", "ALPHA.example.test.:8443/b"],
                        plan={"https://alpha.example.test/a": [{"code": 429}]}
                        if stop else {"preflight": [{"fail": True}]},
                    )
                    self.assertEqual(code, scanner_status, stderr)
                    self.save(rows)
                    report = inspector.inspect_file(self.path, code)
                    self.assertEqual(report["errors"], [])
                    self.assertEqual(report["outcome"], "policy_stopped" if stop else "error")
                    if stop:
                        self.assertEqual(report["omitted_targets"], 2)
                        self.assertEqual(report["pairs"]["missing"], 2)
                        self.assertEqual(report["omissions"]["known_required"], 7)
                    else:
                        self.assertEqual(report["attempts"]["preflight"]["tor"]["completed"], 1)
                        self.assertEqual(report["attempts"]["target"]["tor"]["logged"], 0)
                finally:
                    scanner.doCleanups()

    def test_interruption_and_adapter_launch_failure(self):
        for status, issued in (("aborted", True), ("error", False)):
            with self.subTest(status=status):
                self.save(incomplete_pair_run(status, issued))
                report = inspector.inspect_file(self.path, 143 if issued else 1)
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["outcome"], "interrupted" if issued else "error")
                self.assertEqual(report["pairs"]["missing"], 1)
                self.assertEqual(
                    report["attempts"]["target"]["direct"],
                    {"logged": 1, "issued": int(issued), "completed": 0},
                )

    def test_truncated_execution_preserves_observed_verdicts(self):
        self.save(completed_run()[:-1])
        with self.path.open("ab") as stream:
            stream.write(b'{"type":"run')
        report = inspector.inspect_file(self.path, 0)
        self.assertEqual(report["outcome"], "invalid")
        self.assertIn("no valid run_end record", report["errors"])
        self.assertEqual(report["verdict_counts"]["tor"], {"BLOCKED": 1})

    def test_contradictions_are_invalid(self):
        for change, error in (
            (lambda rows: rows[2].update(execution_id="another-execution"), "inconsistent execution_id"),
            (lambda rows: rows.insert(2, rows[1]), "duplicate attempt_id"),
            (lambda rows: rows[2].update(route="direct"), "disagrees with attempt_start"),
            (lambda rows: rows[8]["attempt_ids"].update(tor="attempt-3"), "incompatible"),
            (lambda rows: rows[8].update(state="missing"), "incorrect pair state"),
            (lambda rows: rows.pop(8), "lack a matching pair_end"),
            (lambda rows: rows[9].update(attempts_issued=3), "bundle attempt counts"),
            (lambda rows: rows[-1]["counts"]["target"].update(issued=3), "target issued count"),
            (lambda rows: rows[-1]["verdict_counts"]["tor"].clear(), "verdict counts"),
            (lambda rows: rows[-1].update(exit_code=3), "run_end state"),
            (lambda rows: rows.append(rows[-1]), "follows run_end"),
            (lambda rows: rows[0]["settings"].update(timeout_preflight=9), "inconsistent timeout_preflight"),
            (lambda rows: rows[0].update(schema_version=4), "unsupported schema_version"),
        ):
            with self.subTest(expected=error):
                rows = completed_run()
                change(rows)
                self.save(rows)
                report = inspector.inspect_file(self.path, 0)
                self.assertEqual(report["outcome"], "invalid")
                self.assertIn(error, " ".join(report["errors"]))

    def test_cli_exit_status_and_json(self):
        self.save(completed_run())
        base = [sys.executable, inspector.__file__, str(self.path)]
        unverified = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(unverified.returncode, 0, unverified.stderr)
        self.assertIn("Process exit status: unavailable", unverified.stdout)
        self.assertIn("Outcome: unverified", unverified.stdout)
        contradicted = subprocess.run(
            base + ["--exit-status", "3", "--format", "json"], capture_output=True, text=True
        )
        self.assertEqual(contradicted.returncode, 1, contradicted.stderr)
        report = json.loads(contradicted.stdout)
        self.assertEqual(report["outcome"], "invalid")
        self.assertIn("supplied process exit status disagrees with run_end", report["errors"])

    def test_parser_errors_and_limits_are_bounded(self):
        for content, error in (
            (b'\xff\n', "malformed UTF-8/JSON"),
            (b'{"not-json":}\n', "malformed UTF-8/JSON"),
            (b'{}', "missing its final newline"),
            (b'{"type":1,"type":2}\n', "duplicate JSON"),
            (b'{"x": NaN}\n', "non-JSON numeric"),

        ):
            with self.subTest(expected=error):
                self.path.write_bytes(content)
                report = inspector.inspect_file(self.path, 0)
                self.assertIn(error, report["errors"][0])
        # Python 3.15 can decode deeper nesting than older CPython versions.
        # Both paths must reject this top-level array as native evidence.
        self.path.write_bytes(b"[" * 2000 + b"]" * 2000 + b"\n")
        nested = inspector.inspect_file(self.path, 0)
        self.assertEqual(nested["outcome"], "invalid")
        self.assertTrue(any(
            message in nested["errors"][0]
            for message in ("excessive nesting", "record is not a JSON object")
        ))
        for limit, error in (
            ("MAX_LINE_BYTES", "line byte limit"),
            ("MAX_INPUT_BYTES", "total byte limit"),
            ("MAX_RECORDS", "record count limit"),
        ):
            with self.subTest(limit=limit), patch.object(inspector, limit, 1):
                self.save(completed_run())
                self.assertIn(error, inspector.inspect_file(self.path)["errors"][0])


if __name__ == "__main__":
    unittest.main()
