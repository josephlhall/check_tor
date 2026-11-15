#!/usr/bin/env python3
"""Inspect the lifecycle and accounting in one saved check_tor JSONL v2 run."""

import argparse
from collections import Counter
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit


MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_RECORDS = 100_000
PHASES = ("preflight", "target")
ROUTES = ("tor", "direct")
TARGET_STATES = ("complete", "partial", "not_started")
OMISSION_KINDS = ("known_required", "eligibility_undetermined")
PAIRING_START = ("planned", "conditional_pending", "not_paired")
TERMINAL_EXITS = {
    "complete": (0,),
    "policy_stopped": (3,),
    "error": (1,),
    "interrupted": (130, 143),
}


class EvidenceError(ValueError):
    pass


def require(test, message):
    if not test:
        raise EvidenceError(message)


def typed(record, name, value_type, *, nullable=False):
    value = record.get(name)
    require(
        name in record and (type(value) is value_type or (nullable and value is None)),
        f"invalid or missing {name}",
    )
    return value


def choice(record, name, values):
    value = typed(record, name, str)
    require(value in values, f"unsupported {name}")
    return value


def count(record, name, minimum=0):
    value = typed(record, name, int)
    require(value >= minimum, f"invalid {name}")
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON object key")
        value[key] = item
    return value


def json_int(value):
    # Bound integer conversion on older Python versions, too.
    require(len(value) <= 128, "JSON integer exceeds the supported size")
    return int(value)


def json_constant(_value):
    raise EvidenceError("non-JSON numeric constant")


@dataclass(frozen=True)
class Target:
    target_id: str
    bundle_id: str
    target_occurrence: int
    original_input: str
    url: str

    @classmethod
    def read(cls, record):
        return cls(
            typed(record, "target_id", str),
            typed(record, "bundle_id", str),
            count(record, "target_occurrence", 1),
            typed(record, "original_input", str),
            typed(record, "url", str),
        )

    @property
    def hostname(self):
        # Match the scanner's stop scope, which excludes port and tolerates
        # case and trailing-dot differences between input occurrences.
        try:
            hostname = urlsplit(self.url).hostname
        except ValueError:
            hostname = None
        require(bool(hostname), "invalid target URL hostname")
        return hostname.lower().rstrip(".")


@dataclass
class Bundle:
    target: Target
    started: bool = False
    state: str = ""
    issued: int = 0
    completed: Counter = field(default_factory=Counter)
    missing_pairs: int = 0
    omitted: dict = field(default_factory=dict)


@dataclass
class Attempt:
    phase: str
    route: str
    bundle: Optional[Bundle]
    fields: dict
    status: str = ""
    http_status: Optional[int] = None
    pairing_state: str = ""

    @property
    def complete(self):
        return self.status == "complete"

    @property
    def issued(self):
        return self.fields["adapter_started"]


class Inspection:
    def __init__(self):
        self.identity = None
        self.settings = {}
        self.planned = {}
        self.terminal = None
        self.bundles = {}
        self.bundle_ids = set()
        self.occurrences = set()
        self.attempts = {}
        self.expected_pair_members = set()
        self.joined_attempts = set()
        self.pair_ids = set()
        self.pair_trials = set()
        self.pairs = {"complete": 0, "missing": 0}
        self.stops = {}
        self.omission_totals = dict.fromkeys(OMISSION_KINDS, 0)
        self.activity = {
            phase: {
                route: {"logged": 0, "issued": 0, "completed": 0} for route in ROUTES
            }
            for phase in PHASES
        }
        self.verdicts = {route: Counter() for route in ROUTES}
        self.verified = False
        self.errors = []

    def record(self, record):
        require(type(record) is dict, "record is not a JSON object")
        require(count(record, "schema_version") == 2, "unsupported schema_version")
        kind = typed(record, "type", str)
        require(self.terminal is None, "record follows run_end")
        identity = (
            typed(record, "execution_id", str),
            typed(record, "run_id", str, nullable=True),
            typed(record, "group_id", str, nullable=True),
        )
        require(bool(identity[0]), "empty execution_id")
        if kind == "run_start":
            require(self.identity is None, "duplicate run_start")
            self.identity = identity
            self.settings = typed(record, "settings", dict)
            self.planned = typed(record, "planned", dict)
            count(self.planned, "target_count", 1)
            count(self.planned, "target_requests_upper_bound", 1)
            count(self.planned, "preflight_requests", 1)
            profile = typed(self.settings, "request_profile", dict)
            for setting, profile_key in (
                ("timeout_preflight", "preflight_timeout"),
                ("max_redirects", "redirect_limit"),
                ("max_body_bytes", "max_body_bytes"),
            ):
                self.compare_if_present(self.settings, setting, profile, profile_key)
            return
        require(self.identity is not None, "first record must be run_start")
        require(identity == self.identity, "inconsistent execution_id, run_id or group_id")
        readers = {
            "bundle_start": self.bundle_start,
            "attempt_start": self.attempt_start,
            "attempt_end": self.attempt_end,
            "pair_end": self.pair_end,
            "hostname_stop": self.hostname_stop,
            "target_omission": self.target_omission,
            "bundle_end": self.bundle_end,
            "run_end": self.run_end,
        }
        require(kind in readers, "unrecognized record type")
        readers[kind](record)

    @staticmethod
    def compare_if_present(left, left_key, right, right_key):
        if left_key in left and right_key in right:
            a, b = left[left_key], right[right_key]
            require(type(a) is type(b) and a == b, f"inconsistent {left_key} and {right_key}")

    def bundle(self, record, *, create=False):
        target = Target.read(record)
        require(bool(target.target_id and target.bundle_id), "empty target or bundle ID")
        bundle = self.bundles.get(target.target_id)
        if bundle is None:
            require(create, "target record has no matching bundle lifecycle")
            require(target.bundle_id not in self.bundle_ids, "duplicate bundle_id")
            require(target.target_occurrence not in self.occurrences, "duplicate target_occurrence")
            require(
                target.target_occurrence <= self.planned["target_count"],
                "target_occurrence exceeds planned target count",
            )
            bundle = Bundle(target)
            self.bundles[target.target_id] = bundle
            self.bundle_ids.add(target.bundle_id)
            self.occurrences.add(target.target_occurrence)
        require(target == bundle.target, "inconsistent target or bundle identity")
        return bundle

    def bundle_start(self, record):
        bundle = self.bundle(record, create=True)
        require(not (bundle.started or bundle.omitted or bundle.state), "unexpected bundle_start")
        choice(record, "state", ("started",))
        bundle.started = True

    def attempt_start(self, record):
        attempt_id = typed(record, "attempt_id", str)
        require(bool(attempt_id) and attempt_id not in self.attempts, "empty or duplicate attempt_id")
        require(
            count(record, "global_order", 1) == len(self.attempts) + 1,
            "attempt_start global_order is discontinuous",
        )
        phase = choice(record, "phase", PHASES)
        route = choice(record, "route", ROUTES)
        fields = self.attempt_fields(record)
        pairing = choice(record, "pairing_state", PAIRING_START)
        require((fields["pair_id"] is not None) == (pairing == "planned"), "inconsistent planned pair")
        bundle = None
        if phase == "preflight":
            require(not self.bundles and not self.verified, "preflight followed verified or target work")
            require(route == "tor" and pairing == "not_paired", "inconsistent preflight route or pairing")
            for key in ("bundle_id", "target_id", "target_occurrence", "original_input"):
                require(key in record and record[key] is None, f"unexpected preflight {key}")
            for key in ("trial_id", "pair_id", "bundle_order"):
                require(fields[key] is None, f"unexpected preflight {key}")
            self.compare_if_present(fields, "requested_timeout", self.settings, "timeout_preflight")
            self.compare_if_present(
                fields, "requested_timeout", self.settings["request_profile"], "preflight_timeout"
            )
        else:
            bundle = self.bundle(record)
            require(bundle.started and not (bundle.state or bundle.omitted), "attempt outside open bundle")
            require(fields["bundle_order"] == bundle.issued + 1, "inconsistent bundle_order")
            require(self.verified, "target attempt precedes verified preflight")
            self.check_permission(record, bundle, fields, route)
            if fields["adapter_started"]:
                bundle.issued += 1
                if fields["pair_id"] is not None:
                    self.expected_pair_members.add(attempt_id)
        self.attempts[attempt_id] = Attempt(phase, route, bundle, fields, pairing_state=pairing)
        activity = self.activity[phase][route]
        activity["logged"] += 1
        activity["issued"] += int(fields["adapter_started"])

    @staticmethod
    def attempt_fields(record):
        fields = {key: typed(record, key, int, nullable=True)
                  for key in ("trial_id", "bundle_order")}
        for key in fields:
            require(fields[key] is None or fields[key] > 0, f"invalid {key}")
        fields.update(
            pair_id=typed(record, "pair_id", str, nullable=True),
            requested_timeout=count(record, "requested_timeout", 1),
            started_at=typed(record, "started_at", str),
            url=typed(record, "url", str),
            adapter_started=typed(record, "adapter_started", bool),
            global_order=count(record, "global_order", 1),
        )
        return fields

    def attempt_end(self, record):
        attempt_id = typed(record, "attempt_id", str)
        attempt = self.attempts.get(attempt_id)
        require(attempt is not None and not attempt.status, "attempt_end has no unique start")
        require(
            attempt.phase == record.get("phase")
            and attempt.route == record.get("route")
            and attempt.fields == self.attempt_fields(record),
            "attempt_end disagrees with attempt_start",
        )
        status = choice(record, "status", ("complete", "error", "aborted"))
        complete = typed(record, "complete", bool)
        require(complete == (status == "complete"), "inconsistent attempt status and complete flag")
        require(attempt.issued or status == "error", "unissued attempt requires error status")
        require(not complete or record.get("local_error") is None, "complete attempt has a local error")
        if attempt.bundle is None:
            for key in ("bundle_id", "target_id", "target_occurrence", "original_input"):
                require(key in record and record[key] is None, f"unexpected preflight {key}")
        else:
            bundle = self.bundle(record)
            require(bundle is attempt.bundle and not bundle.state, "attempt_end outside its bundle")
            self.check_permission(record, bundle, attempt.fields, attempt.route)
        verified = typed(record, "tor_verified", bool, nullable=True)
        verdict = typed(record, "verdict", str, nullable=True)
        if attempt.phase == "preflight":
            require(not complete or verified is not None, "preflight verification result is missing")
            require(verified is not True or complete, "incomplete attempt claims Tor verification")
            self.verified |= verified is True
        else:
            require(verified is None, "target attempt claims Tor verification")
            require(complete == bool(verdict), "target verdict conflicts with attempt completion")
        pairing = typed(record, "pairing_state", str)
        if attempt.pairing_state == "conditional_pending" and attempt.issued:
            choices = ("control_scheduled", "not_paired") if complete else ("unavailable",)
        else:
            choices = (attempt.pairing_state,)
        require(pairing in choices, "inconsistent attempt pairing_state")
        attempt.status = status
        attempt.pairing_state = pairing
        attempt.http_status = typed(record, "http_status", int, nullable=True)
        if pairing == "control_scheduled":
            self.expected_pair_members.add(attempt_id)
        if complete:
            self.activity[attempt.phase][attempt.route]["completed"] += 1
            if attempt.bundle is not None:
                attempt.bundle.completed[attempt.route] += 1
                self.verdicts[attempt.route][verdict] += 1

    def check_permission(self, record, bundle, fields, route):
        if "rate_limit_trigger_attempt_id" not in record:
            return
        trigger = typed(record, "rate_limit_trigger_attempt_id", str)
        stop = self.stops.get(bundle.target.hostname, {})
        require(
            stop.get("triggering_attempt_id") == trigger
            and stop.get("triggering_target_id") == bundle.target.target_id
            and stop.get("triggering_pair_id") == fields["pair_id"]
            and stop.get("permitted_partner_route") == route,
            "attempt has inconsistent rate-limit partner permission",
        )

    def pair_end(self, record):
        bundle = self.bundle(record)
        require(not bundle.state, "pair_end appears after bundle_end")
        pair_id = typed(record, "pair_id", str)
        trial_id = count(record, "trial_id", 1)
        trial_key = (bundle.target.bundle_id, trial_id)
        require(
            bool(pair_id) and pair_id not in self.pair_ids and trial_key not in self.pair_trials,
            "empty or duplicate pair identity",
        )
        members = typed(record, "attempt_ids", dict)
        completed, aborted = set(), set()
        for route, attempt_id in members.items():
            require(route in ROUTES and type(attempt_id) is str, "invalid pair attempt reference")
            attempt = self.attempts.get(attempt_id)
            require(
                attempt is not None and attempt.issued and attempt.status
                and attempt_id not in self.joined_attempts
                and attempt.bundle is bundle and attempt.route == route
                and attempt.fields["trial_id"] == trial_id,
                "pair refers to incompatible or already paired attempt",
            )
            # A conditional control's Tor member was emitted before a pair
            # existed. Its attempt_end records the decision to form the pair.
            claimed_pair = attempt.fields["pair_id"]
            require(
                claimed_pair == pair_id
                or (claimed_pair is None and attempt.pairing_state == "control_scheduled"),
                "pair_id disagrees with its attempt",
            )
            if attempt.complete:
                completed.add(route)
            if attempt.status == "aborted":
                aborted.add(route)
        missing = [route for route in ROUTES if route not in completed]
        require(typed(record, "missing_routes", list) == missing, "incorrect pair missing_routes")
        require(
            typed(record, "aborted_routes", list) == [route for route in ROUTES if route in aborted],
            "incorrect pair aborted_routes",
        )
        expected_state = "missing" if missing else "complete"
        require(record.get("state") == expected_state, "incorrect pair state")
        gap = record.get("observed_start_gap_seconds")
        late = typed(record, "late", bool, nullable=True)
        if len(members) == 2:
            require(
                type(gap) in (float, int) and math.isfinite(gap) and gap >= 0 and late is not None,
                "invalid pair gap or late flag",
            )
            maximum = self.settings.get("max_partner_gap")
            if "max_partner_gap" in self.settings:
                require(
                    type(maximum) in (float, int) and math.isfinite(maximum) and maximum > 0
                    and late == (gap > maximum),
                    "pair late flag contradicts max_partner_gap",
                )
        else:
            require(
                "observed_start_gap_seconds" in record and gap is None and late is None,
                "pair without two starts has a gap or late flag",
            )
        if "missing_reason" in record:
            require(bool(missing), "complete pair has a missing_reason")
            self.check_omission_trigger(typed(record, "missing_reason", dict), bundle)
        self.pair_ids.add(pair_id)
        self.pair_trials.add(trial_key)
        self.joined_attempts.update(members.values())
        self.pairs[expected_state] += 1
        bundle.missing_pairs += int(bool(missing))

    def hostname_stop(self, record):
        require(self.settings.get("execution_policy") != "legacy", "hostname stop during legacy policy")
        hostname = typed(record, "hostname", str)
        require(hostname not in self.stops, "duplicate hostname_stop")
        trigger = typed(record, "triggering_attempt_id", str)
        attempt = self.attempts.get(trigger)
        route = choice(record, "route", ROUTES)
        require(
            attempt is not None and attempt.bundle is not None and attempt.complete
            and not attempt.bundle.state
            and attempt.bundle.target.hostname == hostname and attempt.route == route
            and attempt.bundle.target.target_id == record.get("triggering_target_id")
            and attempt.http_status == 429 and count(record, "http_status") == 429,
            "hostname_stop lacks a matching complete HTTP 429",
        )
        stop = {key: record[key] for key in (
            "hostname", "triggering_attempt_id", "triggering_target_id", "route", "http_status"
        )}
        if "triggering_pair_id" in record:
            self.compare_if_present(record, "triggering_pair_id", attempt.fields, "pair_id")
            stop["triggering_pair_id"] = record["triggering_pair_id"]
        if "permitted_partner_route" in record:
            permitted = typed(record, "permitted_partner_route", str, nullable=True)
            require(
                permitted is None or (
                    permitted in ROUTES and permitted != route and attempt.fields["pair_id"]
                ),
                "invalid permitted partner route",
            )
            stop["permitted_partner_route"] = permitted
        self.stops[hostname] = stop

    def check_omission_trigger(self, record, bundle):
        choice(record, "reason", ("hostname_stop",))
        stop = self.stops.get(bundle.target.hostname)
        require(stop is not None, "omission or missing pair has no hostname_stop")
        for key in ("hostname", "triggering_attempt_id", "triggering_target_id", "route", "http_status"):
            require(key in record and record[key] == stop[key], "omission trigger contradicts hostname_stop")
        for key in ("triggering_pair_id", "permitted_partner_route"):
            self.compare_if_present(record, key, stop, key)

    def omission(self, record, bundle):
        self.check_omission_trigger(record, bundle)
        ranges = {}
        for kind in OMISSION_KINDS:
            ranges[kind] = []
            for entry in typed(record, kind, list):
                require(type(entry) is dict, "omission entry is not an object")
                route = choice(entry, "route", ROUTES)
                total = count(entry, "count", 1)
                description = typed(entry, "description", str)
                if "trial_range" in entry:
                    span = typed(entry, "trial_range", list)
                    require(
                        len(span) == 2 and all(type(n) is int for n in span)
                        and 1 <= span[0] <= span[1] and total == span[1] - span[0] + 1
                        and "scope" not in entry,
                        "incorrect omission trial range or count",
                    )
                else:
                    require(route == "direct" and entry.get("scope") == "target" and total == 1,
                            "incorrect target-scoped omission")
                    span = []
                ranges[kind].append((route, span, total, description))
        require(any(ranges.values()), "empty target_omission")
        return ranges

    def target_omission(self, record):
        bundle = self.bundle(record, create=True)
        require(not (bundle.omitted or bundle.state), "duplicate or late target_omission")
        bundle.omitted = self.omission(record, bundle)
        for kind, ranges in bundle.omitted.items():
            self.omission_totals[kind] += sum(total for _, _, total, _ in ranges)

    def bundle_end(self, record):
        bundle = self.bundle(record)
        require(not bundle.state, "duplicate bundle_end")
        require(bundle.started or bundle.omitted, "bundle_end has no start or omission")
        issued = count(record, "attempts_issued")
        completed = count(record, "attempts_completed")
        require(
            issued == bundle.issued and completed == sum(bundle.completed.values()),
            "bundle attempt counts disagree with observations",
        )
        state = choice(record, "state", TARGET_STATES)
        require((state == "not_started") == (issued == 0), "bundle state contradicts issued count")
        if state == "complete":
            require(
                completed == issued and bundle.completed["tor"] > 0
                and not (bundle.missing_pairs or bundle.omitted),
                "complete bundle has missing observations or policy omissions",
            )
            trials = self.settings.get("trials")
            if type(trials) is int:
                require(bundle.completed["tor"] == trials, "complete bundle disagrees with fixed trials")
            control = self.settings.get("control")
            scope = self.settings.get("control_scope")
            direct = bundle.completed["direct"]
            if control == "never":
                require(direct == 0, "bundle has direct observations with controls disabled")
            if control == "always" and scope in ("target", "trial"):
                expected = 1 if scope == "target" else bundle.completed["tor"]
                require(direct == expected, "complete bundle disagrees with always-control settings")
        if "omission" in record:
            require(
                self.omission(typed(record, "omission", dict), bundle) == bundle.omitted,
                "bundle_end omission disagrees with target_omission",
            )
        bundle.state = state

    def run_end(self, record):
        state = choice(record, "state", TERMINAL_EXITS)
        code = count(record, "exit_code")
        complete = typed(record, "complete", bool)
        error = typed(record, "error", str, nullable=True)
        require(
            code in TERMINAL_EXITS[state] and complete == (state == "complete")
            and (error is not None) == (state == "error"),
            "run_end state, complete flag, exit code or error disagree",
        )
        counts = typed(record, "counts", dict)
        for phase in PHASES:
            actual = typed(counts, phase, dict)
            for kind in ("issued", "completed"):
                expected = sum(route[kind] for route in self.activity[phase].values())
                require(count(actual, kind) == expected, f"run_end {phase} {kind} count disagrees")
        require(
            counts["preflight"]["issued"] <= self.planned["preflight_requests"]
            and counts["target"]["issued"] <= self.planned["target_requests_upper_bound"],
            "issued attempts exceed planned upper bounds",
        )
        require(all(attempt.status for attempt in self.attempts.values()), "attempt starts have no end")
        require(
            self.expected_pair_members == self.joined_attempts,
            "paired attempts lack a matching pair_end",
        )
        self.check_verdict_counts(typed(record, "verdict_counts", dict))
        all_complete = self.check_terminal_targets(typed(record, "target_states", list))
        truncated = any(self.omission_totals.values())
        schedule_complete = self.verified and all_complete and not truncated
        normal_exit = state in ("complete", "policy_stopped")
        if normal_exit:
            require(all(attempt.complete for attempt in self.attempts.values()),
                    "normal exit has an incomplete attempt")
        if complete:
            require(schedule_complete, "complete run has an incomplete schedule")
        if state == "policy_stopped":
            require(
                truncated and self.verified and self.settings.get("execution_policy") != "legacy"
                and all(bundle.state == "complete" or bundle.omitted for bundle in self.bundles.values()),
                "policy-stopped run has unjustified missing work or no omissions",
            )
        self.check_terminal_policy(record, schedule_complete, truncated, normal_exit)
        self.terminal = {"state": state, "complete": complete, "exit_code": code}

    def check_verdict_counts(self, reported):
        for route in ROUTES:
            actual = typed(reported, route, dict)
            expected = self.verdicts[route]
            for name in actual.keys() | expected.keys():
                value = actual.get(name, 0)
                require(
                    type(value) is int and value == expected[name],
                    "run_end verdict counts disagree with complete observations",
                )

    def check_terminal_targets(self, targets):
        require(len(targets) == self.planned["target_count"], "run_end target count disagrees")
        all_complete = True
        for occurrence, entry in enumerate(targets, 1):
            require(type(entry) is dict, "run_end target state is not an object")
            bundle = self.bundle(entry, create=True)
            require(bundle.target.target_occurrence == occurrence, "run_end target order disagrees")
            state = choice(entry, "state", TARGET_STATES)
            require(
                state == (bundle.state or "not_started")
                and (bundle.state or not (bundle.started or bundle.omitted)),
                "run_end target state disagrees with bundle lifecycle",
            )
            all_complete &= state == "complete"
        return all_complete

    def check_terminal_policy(self, record, schedule_complete, truncated, normal_exit):
        for name, value in (
            ("schedule_complete", schedule_complete), ("policy_truncated", truncated)
        ):
            if name in record:
                require(typed(record, name, bool) == value, f"incorrect run_end {name}")
        if "hostname_stops" in record:
            require(count(record, "hostname_stops") == len(self.stops), "incorrect hostname_stops count")
        if "omission_counts" in record:
            totals = typed(record, "omission_counts", dict)
            for kind, actual in self.omission_totals.items():
                require(count(totals, kind) == actual, "run_end omission_counts disagree")
        if "schedule_accounting" in record:
            accounting = typed(record, "schedule_accounting", dict)
            for kind, actual in self.omission_totals.items():
                require(count(accounting, kind + "_omitted") == actual, "run_end omitted accounting disagrees")
                unresolved = kind + "_unresolved"
                if unresolved in accounting:
                    value = count(accounting, unresolved)
                    require(not normal_exit or value == 0, "normal exit has unresolved work")

    def summary(self, process_status):
        if self.terminal is None:
            self.errors.append("no valid run_end record")
        elif process_status is not None and process_status != self.terminal["exit_code"]:
            self.errors.append("supplied process exit status disagrees with run_end")
        if self.errors:
            outcome = "invalid"
        elif process_status is None:
            outcome = "unverified"
        else:
            outcome = self.terminal["state"]
        return {
            "execution_id": self.identity[0] if self.identity else None,
            "outcome": outcome,
            "process_exit_status": process_status,
            "terminal": self.terminal,
            "attempts": self.activity,
            "verdict_counts": {route: dict(counts) for route, counts in self.verdicts.items()},
            "pairs": self.pairs,
            "hostname_stops": len(self.stops),
            "omitted_targets": sum(bool(bundle.omitted) for bundle in self.bundles.values()),
            "omissions": self.omission_totals,
            "errors": self.errors,
        }


def inspect_file(path, process_status=None):
    inspection = Inspection()
    line_number = total = 0
    try:
        require(path.is_file(), "input is not a saved regular file")
        with path.open("rb") as stream:
            while True:
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                line_number += 1
                total += len(line)
                require(len(line) <= MAX_LINE_BYTES, "record exceeds line byte limit")
                require(line_number <= MAX_RECORDS, "input exceeds record count limit")
                require(total <= MAX_INPUT_BYTES, "input exceeds total byte limit")
                require(line.endswith(b"\n"), "record is missing its final newline")
                record = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=unique_object,
                    parse_int=json_int,
                    parse_constant=json_constant,
                )
                inspection.record(record)
    except EvidenceError as exc:
        prefix = f"line {line_number}: " if line_number else ""
        inspection.errors.append(prefix + str(exc))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        inspection.errors.append(f"line {line_number}: malformed UTF-8/JSON or excessive nesting")
    except MemoryError:
        inspection.errors.append(f"line {line_number}: reader memory limit exceeded")
    except OSError:
        inspection.errors.append("could not read the saved input file")
    return inspection.summary(process_status)


VALIDATION_LIMIT = (
    "Checks cover native record linkage, lifecycle, counts, and selected settings. "
    "The inspector does not replay the scheduler or verify transport evidence, "
    "provenance, or study eligibility."
)


def print_report(report):
    status = report["process_exit_status"]
    print(f"Outcome: {report['outcome']}")
    print(f"Process exit status: {status if status is not None else 'unavailable'}")
    terminal = report["terminal"]
    if terminal:
        print(f"Terminal state: {terminal['state']} (recorded exit {terminal['exit_code']})")
    else:
        print("Terminal state: unavailable")
    for phase, routes in report["attempts"].items():
        for route, counts in routes.items():
            print(
                f"{phase} {route}: {counts['logged']} logged, {counts['issued']} issued, "
                f"{counts['completed']} completed"
            )
    for route, counts in report["verdict_counts"].items():
        print(f"Target {route} verdicts: {json.dumps(counts, sort_keys=True)}")
    pairs = report["pairs"]
    print(f"Pairs: {pairs['complete']} complete, {pairs['missing']} missing")
    omissions = report["omissions"]
    print(
        f"Policy: {report['hostname_stops']} hostname stops, {report['omitted_targets']} "
        f"omitted targets, {omissions['known_required']} known required, "
        f"{omissions['eligibility_undetermined']} eligibility undetermined"
    )
    for error in report["errors"]:
        print(f"Evidence error: {error}")
    print(VALIDATION_LIMIT)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("file", type=Path, help="saved scanner stdout")
    parser.add_argument("--exit-status", type=int, help="exit status captured from the scanner")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    report = inspect_file(args.file, args.exit_status)
    if args.format == "json":
        print(json.dumps(dict(report, validation_limits=VALIDATION_LIMIT), sort_keys=True))
    else:
        print_report(report)
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
