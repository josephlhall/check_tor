#!/usr/bin/env python3
"""Opt-in observation coordinator; transport and verdicts remain in Zsh.

A launch is the coordinator's Popen boundary, not the first packet or redirect.
Only the coordinator grants launches: sleeping workers never hold future slots.
"""

import argparse
import collections
import datetime
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

SCHEMA = 2
# Keep this set aligned with blocky() in check_tor_core.zsh: it governs
# retry/control scheduling, while the shell owns native verdict classification.
BLOCKY = {"FAIL", "CHALLENGE", "RATELIMIT", "DROP", "TIMEOUT", "SOCKS"}
VERDICTS = BLOCKY | {"PASS", "CERT", "WARN"}
MAX_RESULT_BYTES = 131072
# These are retained metadata bounds, independent of curl's follow budget.
# Read private headers only here, before their request directory is removed.
MAX_REDIRECT_HEADER_BYTES = 262144
MAX_REDIRECT_HOPS = 100
MAX_REDIRECT_URL_BYTES = 8192
MAX_REDIRECT_EVIDENCE_BYTES = 65536
CANCELLED = 0


class Failure(Exception):
    pass


class OutputFailure(Failure):
    pass


def utc():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def bounded_int(maximum, minimum=1):
    def parse(value):
        if not re.fullmatch(r"[0-9]{1,10}", value):
            raise argparse.ArgumentTypeError("expected bounded decimal integer")
        result = int(value)
        if not minimum <= result <= maximum:
            raise argparse.ArgumentTypeError("integer outside supported bounds")
        return result

    return parse


def gap(value):
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected finite seconds")
    if not math.isfinite(result) or not 0 <= result <= 3600:
        raise argparse.ArgumentTypeError(
            "seconds must be finite and between 0 and 3600"
        )
    return result


def arguments(argv):
    p = argparse.ArgumentParser(
        description="Record versioned Tor/direct observations with configurable trials and pacing.",
        allow_abbrev=False,
    )
    p.add_argument("--format", choices=["jsonl-v2"], default="jsonl-v2")
    p.add_argument("--proxy", default="localhost:9050")
    p.add_argument("--circuits", type=bounded_int(100), default=3)
    p.add_argument("--max-redirects", type=bounded_int(100, 0), default=10)
    p.add_argument("--timeout-first", type=bounded_int(3600), default=60)
    p.add_argument("--timeout-retry", type=bounded_int(3600), default=30)
    p.add_argument("--timeout-clearnet", type=bounded_int(3600), default=20)
    p.add_argument("--no-clearnet", action="store_true")
    p.add_argument("--run-id")
    p.add_argument("--group-id")
    p.add_argument("--trials", type=bounded_int(100))
    p.add_argument(
        "--control", choices=["conditional", "always", "never"], default="conditional"
    )
    p.add_argument("--control-scope", choices=["target", "trial"], default="target")
    p.add_argument(
        "--order",
        choices=["tor-first", "direct-first", "counterbalanced"],
        default="tor-first",
    )
    p.add_argument("--seed", type=bounded_int(2147483647, 0))
    p.add_argument("--max-partner-gap", type=gap, default=60.0)
    p.add_argument("--reproducible", action="store_true")
    p.add_argument("--workers", type=bounded_int(32), default=1)
    p.add_argument("--start-gap", type=gap, default=0.0)
    p.add_argument("target_file")
    a = p.parse_args(argv)
    for label in (a.run_id, a.group_id):
        if label is not None and len(label) > 1024:
            p.error("run/group labels must not exceed 1024 characters")
    option_arguments = argv[: argv.index("--")] if "--" in argv else argv
    explicit = {v.split("=", 1)[0] for v in option_arguments if v.startswith("--")}
    if a.trials is not None and "--circuits" in explicit:
        p.error("--trials conflicts with --circuits")
    if a.no_clearnet:
        if "--control" in explicit and a.control != "never":
            p.error("--no-clearnet conflicts with --control")
        a.control = "never"
    if a.control_scope == "trial" and (a.trials is None or a.control == "never"):
        p.error("trial controls require fixed trials and enabled controls")
    if a.order != "tor-first" and a.control != "always":
        p.error("direct-first/counterbalanced order requires always controls")
    if a.order == "counterbalanced" and a.seed is None:
        p.error("counterbalanced order requires --seed")
    if a.order != "counterbalanced" and a.seed is not None:
        p.error("--seed requires counterbalanced order")
    if a.max_partner_gap <= 0:
        p.error("--max-partner-gap must be positive")
    if "--max-partner-gap" in explicit and a.control_scope != "trial":
        p.error("--max-partner-gap requires trial controls")
    policy_flags = {
        "--trials",
        "--control",
        "--control-scope",
        "--order",
        "--seed",
        "--max-partner-gap",
        "--workers",
        "--start-gap",
    }
    a.reproducible = a.reproducible or bool(explicit & policy_flags)
    # Endpoint grammar matches the scanner: no schemes, userinfo, or paths.
    if re.search(r"[\s/@]", a.proxy):
        p.error("--proxy requires HOST:PORT without credentials")
    m = re.fullmatch(r"(\[[^\]]*:[^\]]+\]|[^:]+):([0-9]{1,9})", a.proxy)
    if not m or not 1 <= int(m[2]) <= 65535:
        p.error("--proxy requires HOST:PORT")
    a.proxy = m[1] + ":" + str(int(m[2]))
    return a


def load_targets(path):
    source = Path(path)
    if not source.is_file():
        raise Failure("target file is not a regular file")
    targets = []
    with source.open(encoding="utf-8", errors="strict") as stream:
        for raw in stream:
            original = raw.replace("\r", "").strip()
            if len(original) > 8192:
                raise Failure("target input exceeds 8192 characters")
            if not original or original.startswith("#"):
                continue
            url = (
                original
                if original.startswith("https://")
                else "https://" + original.removeprefix("http://")
            )
            # Python 3.9 compatibility: removeprefix is intentionally sufficient.
            try:
                parsed = urllib.parse.urlsplit(url)
                host = parsed.hostname
                _ = parsed.port  # Access validates the numeric port.
            except ValueError:
                raise Failure("invalid target URL")
            if parsed.username is not None or parsed.password is not None:
                raise Failure("target URLs containing userinfo are unsupported")
            if not host or parsed.scheme != "https" or any(ord(c) < 32 for c in url):
                raise Failure("invalid target URL")
            # Identity belongs to the input occurrence, including duplicates.
            # The normalized hostname is only a scheduling lock, not an ID.
            occurrence = len(targets) + 1
            targets.append(
                {
                    "target_id": "target-" + str(occurrence),
                    "target_occurrence": occurrence,
                    "bundle_id": "bundle-" + str(occurrence),
                    "original_input": original,
                    "url": url,
                    "hostname": host.lower().rstrip("."),
                }
            )
    if not targets:
        raise Failure("target file contains no targets")
    return targets


class Writer:
    """Bounded writes keep signals/failed consumers from wedging cleanup."""

    def __init__(self, common):
        self.common = common
        self.fd = sys.stdout.fileno()
        self.blocking = os.get_blocking(self.fd)
        os.set_blocking(self.fd, False)
        self.failed = False

    def emit(self, kind, **fields):
        if self.failed:
            raise OutputFailure("output unavailable")
        line = (
            json.dumps(
                dict(self.common, type=kind, **fields),
                ensure_ascii=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        view = memoryview(line)
        # Finish an in-progress JSON line for at most two seconds, even on a
        # signal, then abandon an unusable destination and clean owned sessions.
        deadline = time.monotonic() + 2.0
        try:
            while view:
                try:
                    n = os.write(self.fd, view)
                    if n <= 0:
                        raise OSError("short output write")
                    view = view[n:]
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OSError("output stalled")
                    time.sleep(0.01)
        except OSError as exc:
            self.failed = True
            raise OutputFailure("cannot retain further records: output failed") from exc

    def restore(self):
        try:
            os.set_blocking(self.fd, self.blocking)
        except OSError:
            pass


def scrub(value):
    """Diagnostics can contain redirect URLs; userinfo must never be emitted."""
    if not isinstance(value, str):
        return value
    return re.sub(
        r"(https?://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[redacted]@", value, flags=re.I
    )


def redirect_url(value, base=None):
    """Resolve before removing userinfo; never return a partial URL as evidence.

    Query and fragment values remain intact for interpretation, so the result
    is sanitized transport evidence, not anonymized or safe-to-publish data.
    """
    if len(value.encode("utf-8")) > MAX_REDIRECT_URL_BYTES:
        return None, "truncated"
    if not value or re.search(r"[\x00-\x20\x7f]", value) or "\\" in value:
        return None, "invalid"
    try:
        # curl accepts some references differently from RFC-oriented urljoin.
        # Refuse those for reconstructed followed hops; native redirect_url
        # independently supplies the destination at the observation boundary.
        # Reject before retaining each hop: a later absolute redirect could
        # hide a wrong intermediate reconstruction from the terminal URL check.
        reference = urllib.parse.urlsplit(value)
        if base and (
            value.startswith(("///", "#"))
            or value.endswith(("?", "#"))
            or re.search(r"\?(?:#|$)", value)
            or "//" in reference.path
            or "//" in urllib.parse.urlsplit(base).path
            or (
                reference.scheme
                and (
                    not reference.netloc
                    or not value.startswith(("http://", "https://"))
                )
            )
        ):
            return None, "unsupported"
        resolved = urllib.parse.urljoin(base, value) if base else value
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme.lower() not in ("http", "https"):
            return None, "unsupported"
        if not parsed.hostname:
            return None, "invalid"
        if any(segment in (".", "..") for segment in parsed.path.split("/")):
            return None, "unsupported"
        # Accessing .port validates malformed and out-of-range ports too.
        port = parsed.port
        host = parsed.hostname
        if ":" in host:
            host = "[" + host + "]"
        if port is not None:
            host += ":" + str(port)
        safe = urllib.parse.urlunsplit(parsed._replace(netloc=host))
    except ValueError:
        return None, "invalid"
    if len(safe.encode("utf-8")) > MAX_REDIRECT_URL_BYTES:
        return None, "truncated"
    return safe, "available"


def redirect_evidence(directory, initial_url, result):
    """Join complete HTTP response blocks to curl's authoritative follow count.

    Headers alone are not a request log: informational responses and proxy
    CONNECT responses are not redirect hops. Conflicting or incomplete facts
    must not manufacture a visited destination. Raw headers never leave here.
    """
    evidence = dict(
        state="unavailable",
        followed=[],
        next_destination=None,
        next_destination_state="unavailable",
    )
    # Capture the native next destination independently: missing or truncated
    # header evidence must not erase a safely captured curl observation. The
    # evidence-quality state does not change the probe's native verdict.
    at_limit = result["curl_exit"] == 47
    if not at_limit:
        evidence["next_destination_state"] = "not_applicable"
    elif result.get("next_redirect_truncated"):
        evidence.update(state="truncated", next_destination_state="truncated")
    elif result.get("next_redirect_url"):
        target, state = redirect_url(result["next_redirect_url"])
        evidence.update(next_destination=target, next_destination_state=state)
    try:
        with (directory / "headers").open("rb") as source:
            raw = source.read(MAX_REDIRECT_HEADER_BYTES + 1)
    except OSError:
        return evidence
    truncated = len(raw) > MAX_REDIRECT_HEADER_BYTES
    raw = raw[:MAX_REDIRECT_HEADER_BYTES]
    blocks = []
    parts = re.split(rb"\r?\n\r?\n", raw)
    for block in parts[:-1]:
        lines = block.splitlines()
        if not lines:
            continue
        status = re.fullmatch(
            rb"HTTP/(?:1\.[01]|2|3) +([0-9]{3})(?: +([^\r\n]*))?", lines[0]
        )
        if not status:
            evidence["state"] = "invalid"
            return evidence
        code = int(status[1])
        if (
            100 <= code < 200
            or (status[2] or b"").lower() == b"connection established"
        ):
            continue
        locations = [
            line.split(b":", 1)[1].strip(b" \t")
            for line in lines[1:]
            if line.lower().startswith(b"location:")
        ]
        # Folded Location values are ambiguous; never export their raw content.
        folded = any(line.startswith((b" ", b"\t")) for line in lines[1:])
        blocks.append((code, locations, folded))
    count = result["redirect_count"]
    if type(count) is not int or not 0 <= count <= MAX_REDIRECT_HOPS:
        return evidence
    if not blocks:
        evidence["state"] = "truncated" if truncated else "unavailable"
        return evidence
    if not truncated and (len(blocks) != count + 1 or parts[-1]):
        return evidence
    evidence["state"] = "truncated" if truncated else "complete"
    current = initial_url

    def destination(block):
        _, locations, folded = block
        if not locations:
            return None, "absent"
        if len(locations) != 1 or folded:
            return None, "invalid"
        try:
            location = locations[0].decode("utf-8")
        except UnicodeError:
            return None, "invalid"
        return redirect_url(location, current)

    for index, block in enumerate(blocks[:count]):
        # Only curl-followable redirect responses can explain a followed hop.
        if not 300 <= block[0] < 400:
            evidence["state"] = "unsupported"
            break
        response_url, response_state = redirect_url(current)
        target, state = destination(block)
        if state != "available" or response_state != "available":
            evidence["state"] = (
                "unavailable" if state == "absent"
                else state if state != "available" else response_state
            )
            break
        evidence["followed"].append(
            dict(
                hop=index + 1,
                http_status=block[0],
                response_url=response_url,
                destination=target,
            )
        )
        # Resolution must retain the original base semantics, including userinfo.
        current = urllib.parse.urljoin(current, block[1][0].decode("utf-8"))
    if (
        len(evidence["followed"]) == count
        and len(blocks) == count + 1
        and not truncated
    ):
        # Effective URL is curl's final visited destination, not a reconstruction.
        # Fragment and an omitted root slash do not change the HTTP request URL.
        reconstructed, _ = redirect_url(current)
        actual, _ = redirect_url(result.get("final_url") or "")

        def request_url(value):
            if value is None:
                return None
            parsed = urllib.parse.urlsplit(value)
            return parsed._replace(path=parsed.path or "/", fragment="").geturl()

        if blocks[-1][0] != result["http_status"]:
            evidence.update(state="invalid", followed=[])
        elif actual is None:
            evidence.update(state="unavailable", followed=[])
        elif request_url(actual) != request_url(reconstructed):
            evidence.update(state="unsupported", followed=[])
        elif at_limit:
            if not 300 <= blocks[-1][0] < 400:
                evidence["state"] = "invalid"
            elif (
                not result.get("next_redirect_url")
                and not result.get("next_redirect_truncated")
            ):
                _, state = destination(blocks[-1])
                # A plausible Location is not a substitute for curl's resolved
                # next URL. Only its absence/invalidity can be asserted here.
                if state == "available":
                    state = "unavailable"
                evidence["next_destination_state"] = state
    if at_limit and evidence["next_destination_state"] not in (
        "available", "absent", "unavailable"
    ):
        evidence["state"] = evidence["next_destination_state"]
    if truncated and evidence["next_destination_state"] == "unavailable":
        evidence["next_destination_state"] = "truncated"
    # Bound serialized bytes, including JSON escaping. Drop whole hop records;
    # a shortened destination would look like a different, valid URL.
    while (
        len(json.dumps(evidence, ensure_ascii=True).encode())
        > MAX_REDIRECT_EVIDENCE_BYTES
    ):
        evidence["followed"].pop()
        evidence["state"] = "truncated"
    return evidence


def public_target(target):
    return {k: v for k, v in target.items() if k != "hostname"}


class Bundle:
    def __init__(self, target, args):
        self.target, self.args = target, args
        self.generator = self.schedule()
        self.pending = None
        self.active = None
        self.done = False
        self.issued = self.completed = 0
        self.pairs = {}

    def order(self, trial):
        if self.args.order == "counterbalanced":
            # Stable arithmetic independent of PRNGs, isolation tags, workers.
            return (
                "direct-first"
                if (self.args.seed + self.target["target_occurrence"] - 1 + trial - 1)
                % 2
                else "tor-first"
            )
        return self.args.order

    def schedule(self):
        # Each yield queues one request; advance() sends its completed
        # observation back before policy can choose the next request. This
        # serializes a bundle even when other target bundles run concurrently.
        a = self.args
        count = a.trials if a.trials is not None else a.circuits
        target_direct_first = (
            a.control_scope == "target"
            and a.control == "always"
            and self.order(1) == "direct-first"
        )
        if target_direct_first:
            yield ("direct", None, None)
        last = None
        for trial in range(1, count + 1):
            trial_id = trial if a.trials is not None else None
            pair_id = (
                self.target["bundle_id"] + "-pair-" + str(trial)
                if a.control_scope == "trial" and a.control == "always"
                else None
            )
            if pair_id:
                self.pairs[pair_id] = {"trial_id": trial, "attempts": {}}
            if pair_id and self.order(trial) == "direct-first":
                yield ("direct", trial_id, pair_id)
            last = yield ("tor", trial_id, pair_id)
            if a.control_scope == "trial":
                if a.control == "always":
                    if self.order(trial) != "direct-first":
                        yield ("direct", trial_id, pair_id)
                elif last and last.get("verdict") in BLOCKY:
                    # Conditional pairs exist only after the Tor result. Retain
                    # that observation without revising its emitted pair metadata.
                    pair_id = self.target["bundle_id"] + "-pair-" + str(trial)
                    self.pairs[pair_id] = {"trial_id": trial, "attempts": {"tor": last}}
                    yield ("direct", trial_id, pair_id)
            if a.trials is None and last and last.get("verdict") not in BLOCKY:
                break
        if (
            a.control_scope == "target"
            and not target_direct_first
            and (
                a.control == "always"
                or (
                    a.control == "conditional"
                    and last
                    and last.get("verdict") in BLOCKY
                )
            )
        ):
            yield ("direct", None, None)

    def advance(self, result=None):
        try:
            self.pending = self.generator.send(result)
        except StopIteration:
            self.pending = None
            self.done = True


class Engine:
    def __init__(self, args, targets):
        self.args, self.targets = args, targets
        self.execution_id = str(uuid.uuid4())
        self.root = Path(__file__).resolve().parent
        self.temp = tempfile.TemporaryDirectory(prefix="check-tor-measure-")
        os.chmod(self.temp.name, 0o700)
        self.selector = selectors.DefaultSelector()
        self.active = {}
        self.bundles = []
        self.states = {t["target_id"]: "not_started" for t in targets}
        self.counts = {
            phase: {"issued": 0, "completed": 0} for phase in ("preflight", "target")
        }
        self.verdicts = {route: collections.Counter() for route in ("tor", "direct")}
        self.sequence = 0
        self.last_launch = None
        self.error = None
        self.stopping = False
        self.run_started = time.monotonic()
        self.env = dict(os.environ)
        if args.reproducible:
            self.env = {
                k: v
                for k, v in self.env.items()
                if not (k.lower().endswith("_proxy") or k.lower() == "proxy")
            }
        self.env["CHECK_TOR_PROXY"] = args.proxy
        self.env["CHECK_TOR_MAX_REDIRECTS"] = str(args.max_redirects)
        # Alter stdout only after other initialization succeeds; run() always
        # restores its original flags, including when main was called by Zsh.
        self.writer = Writer(
            {
                "schema_version": SCHEMA,
                "execution_id": self.execution_id,
                "run_id": args.run_id,
                "group_id": args.group_id,
            }
        )

    def start_record(self):
        names = (
            "proxy",
            "circuits",
            "max_redirects",
            "trials",
            "control",
            "control_scope",
            "order",
            "seed",
            "max_partner_gap",
            "reproducible",
            "workers",
            "start_gap",
            "timeout_first",
            "timeout_retry",
            "timeout_clearnet",
        )
        settings = {n: getattr(self.args, n) for n in names}
        settings["trial_policy"] = (
            "fixed" if self.args.trials is not None else "failure-retry"
        )
        settings["redirect_evidence_bounds"] = dict(
            header_bytes=MAX_REDIRECT_HEADER_BYTES,
            hops=MAX_REDIRECT_HOPS,
            url_bytes=MAX_REDIRECT_URL_BYTES,
            json_bytes=MAX_REDIRECT_EVIDENCE_BYTES,
        )
        settings["counterbalance_algorithm"] = (
            "(seed + target_occurrence - 1 + trial - 1) % 2; 0=tor-first"
        )
        # Hash exact instrument sources, including comments; even a comment-only
        # revision gets a distinct recorded identity for later provenance checks.
        digest = hashlib.sha256()
        for filename in (
            "check_tor.zsh",
            "check_tor_core.zsh",
            "check_tor_probe.zsh",
            "check_tor_measure.py",
        ):
            digest.update(
                filename.encode() + b"\0" + (self.root / filename).read_bytes() + b"\0"
            )
        tor_bound = self.args.trials or self.args.circuits
        control_bound = (
            0
            if self.args.control == "never"
            else (tor_bound if self.args.control_scope == "trial" else 1)
        )
        try:
            profile_result = subprocess.run(
                ["zsh", str(self.root / "check_tor_probe.zsh"), "--settings"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.env,
                timeout=5,
                check=True,
            )
            if len(profile_result.stdout) > MAX_RESULT_BYTES:
                raise Failure("request profile exceeded metadata bound")
            self.profile = json.loads(profile_result.stdout)
            if not isinstance(self.profile, dict):
                raise Failure("invalid shared request profile")
            settings["request_profile"] = self.profile
        except (subprocess.SubprocessError, ValueError):
            raise Failure("cannot obtain shared request profile")
        self.writer.emit(
            "run_start",
            started_at=utc(),
            settings=settings,
            scanner={
                "name": "check_tor",
                "version": None,
                "source_sha256": digest.hexdigest(),
            },
            clocks={
                "utc": "wall-clock UTC",
                "elapsed": "time.monotonic",
                "probe_start": "coordinator Popen invocation; excludes redirect hops",
            },
            planned={
                "target_count": len(self.targets),
                "target_requests_upper_bound": len(self.targets)
                * (tor_bound + control_bound),
                "preflight_requests": 1,
            },
        )

    def launch(self, bundle=None):
        if CANCELLED:
            return
        now = time.monotonic()
        if (
            self.last_launch is not None
            and now - self.last_launch < self.args.start_gap
        ):
            return
        preflight = bundle is None
        if preflight:
            route, trial, pair = "tor", None, None
            identity = {
                "attempt_id": "attempt-" + str(self.sequence + 1),
                "bundle_id": None,
                "target_id": None,
                "target_occurrence": None,
                "original_input": None,
                "url": "https://check.torproject.org/api/ip",
                "trial_id": None,
                "pair_id": None,
            }
            timeout, order = self.profile.get("preflight_timeout"), None
        else:
            route, trial, pair = bundle.pending
            identity = public_target(bundle.target)
            identity.update(
                attempt_id="attempt-" + str(self.sequence + 1),
                trial_id=trial,
                pair_id=pair,
            )
            timeout = (
                self.args.timeout_clearnet
                if route == "direct"
                else (
                    self.args.timeout_first
                    if not any(
                        x.get("route") == "tor" for x in getattr(bundle, "history", [])
                    )
                    else self.args.timeout_retry
                )
            )
            order = bundle.issued + 1
        self.sequence += 1
        phase = "preflight" if preflight else "target"
        fields = dict(
            identity,
            phase=phase,
            route=route,
            global_order=self.sequence,
            bundle_order=order,
            requested_timeout=timeout,
            pairing_state="planned"
            if pair
            else (
                "conditional_pending"
                if bundle and self.args.control_scope == "trial" and route == "tor"
                else "not_paired"
            ),
            routing={
                "mode": "guaranteed" if self.args.reproducible else "inherited_unknown",
                "proxy": self.args.proxy if route == "tor" else None,
                "dns": "remote"
                if self.args.reproducible and route == "tor"
                else ("local" if self.args.reproducible else "inherited_unknown"),
            },
        )
        request_dir = Path(self.temp.name) / str(self.sequence)
        request_dir.mkdir(mode=0o700)
        # The timestamp precedes Popen; emitting after registration ensures an
        # output fault cannot strand a successfully launched owned session.
        fields["started_at"] = utc()
        started = time.monotonic()
        self.last_launch = started
        if bundle:
            self.states[bundle.target["target_id"]] = "partial"
        if CANCELLED:
            shutil.rmtree(request_dir, ignore_errors=True)
            return
        try:
            process = subprocess.Popen(
                [
                    "zsh",
                    str(self.root / "check_tor_probe.zsh"),
                    str(request_dir),
                    route,
                    fields["url"],
                    str(timeout),
                    "1" if self.args.reproducible else "0",
                    phase,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.env,
                start_new_session=True,
            )
        except OSError:
            self.writer.emit("attempt_start", **fields, adapter_started=False)
            self.writer.emit(
                "attempt_end",
                **fields,
                ended_at=utc(),
                duration_seconds=time.monotonic() - started,
                status="error",
                complete=False,
                adapter_started=False,
                verdict=None,
                http_status=None,
                curl_exit=None,
                curl_error=None,
                detail="local adapter execution failed",
                final_url=None,
                redirect_count=None,
                body_limited=None,
                tor_verified=None,
                local_error=None,
            )
            raise Failure("local adapter execution failed")
        self.counts[phase]["issued"] += 1
        if bundle:
            bundle.issued += 1
        task = {
            "process": process,
            "fields": fields,
            "started": started,
            "buffer": bytearray(),
            "bundle": bundle,
            "directory": request_dir,
            "eof": False,
        }
        self.active[process.pid] = task
        os.set_blocking(process.stdout.fileno(), False)
        self.selector.register(process.stdout, selectors.EVENT_READ, task)
        if bundle and pair:
            bundle.pairs[pair]["attempts"][route] = dict(
                fields, _start=started, complete=False, status="running"
            )
        if bundle:
            bundle.active = task
            bundle.pending = None
        self.writer.emit("attempt_start", **fields, adapter_started=True)

    def kill_group(self, pid, sig):
        deadline = time.monotonic() + 0.2
        while True:
            try:
                os.killpg(pid, sig)
                return
            except ProcessLookupError:
                return
            except PermissionError:
                # macOS can report EPERM while a group is departing, a few
                # moments before waitpid can reap its leader. Retry that short
                # transition rather than declaring cancellation a local fault.
                # A persistent denial against a live owned leader stays fatal.
                task = self.active.get(pid)
                if task is None or task["process"].poll() is not None:
                    return
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)

    def read_ready(self, wait=0.02):
        for key, _ in self.selector.select(wait):
            task = key.data
            try:
                data = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            if not data:
                task["eof"] = True
                self.selector.unregister(key.fileobj)
            else:
                task["buffer"].extend(data)
                if len(task["buffer"]) > MAX_RESULT_BYTES:
                    raise Failure("adapter metadata exceeded its bound")
        for task in list(self.active.values()):
            if task["process"].poll() is not None:
                # A descendant may inherit stdout after the adapter leader exits.
                self.kill_group(task["process"].pid, signal.SIGKILL)
                if task["eof"]:
                    self.finish(task, abort=self.stopping or bool(CANCELLED))

    def result(self, task, abort=False):
        # A valid final JSON object proves completion even if cancellation hits
        # between its printf and the adapter exit. Partial JSON proves nothing.
        acceptable = (
            (0, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL) if abort else (0,)
        )
        if task["process"].returncode not in acceptable:
            return None
        try:
            result = json.loads(task["buffer"].decode("utf-8"))
        except (ValueError, UnicodeError):
            return None
        required = {
            "verdict",
            "detail",
            "http_status",
            "curl_exit",
            "curl_error",
            "final_url",
            "next_redirect_url",
            "next_redirect_truncated",
            "redirect_count",
            "body_limited",
            "tor_verified",
            "local_error",
        }
        if not isinstance(result, dict) or set(result) != required:
            return None
        if type(result["next_redirect_truncated"]) is not bool:
            return None
        local_error = result["local_error"]
        if local_error is not None and not isinstance(local_error, str):
            return None
        if task["fields"]["phase"] == "target":
            if local_error is None and (
                not isinstance(result["verdict"], str)
                or result["verdict"] not in VERDICTS
            ):
                return None
            if local_error is not None and result["verdict"] is not None:
                return None
        # JSON booleans decode to Python bool, a subclass of int. Exact types
        # keep true/false from masquerading as transport counts or exit codes.
        if type(result["curl_exit"]) is not int and not (
            local_error is not None and result["curl_exit"] is None
        ):
            return None
        if type(result["body_limited"]) is not bool and not (
            local_error is not None and result["body_limited"] is None
        ):
            return None
        for key in ("http_status", "redirect_count"):
            if result[key] is not None and type(result[key]) is not int:
                return None
        for key in ("detail", "curl_error", "final_url", "next_redirect_url"):
            if result[key] is not None and not isinstance(result[key], str):
                return None
            if key not in ("final_url", "next_redirect_url"):
                result[key] = scrub(result[key])
        # Parse the original URL before diagnostic redaction: its [redacted]
        # placeholder is not valid URL userinfo and would discard the destination.
        # Never echo a URL with redirect userinfo, including a password without
        # a username. Parsing rather than regex alone covers percent encoding.
        if result["final_url"]:
            try:
                parsed = urllib.parse.urlsplit(result["final_url"])
                if parsed.username is not None or parsed.password is not None:
                    host = parsed.hostname or ""
                    if ":" in host:
                        host = "[" + host + "]"
                    if parsed.port:
                        host += ":" + str(parsed.port)
                    result["final_url"] = urllib.parse.urlunsplit(
                        parsed._replace(netloc=host)
                    )
            except ValueError:
                result["final_url"] = None
        return result

    def finish(self, task, abort=False):
        process, fields, bundle = task["process"], task["fields"], task["bundle"]
        result = (
            self.result(task, abort=abort)
            if process.poll() is not None and task["eof"]
            else None
        )
        status = (
            ("error" if result["local_error"] else "complete")
            if result is not None
            else ("aborted" if abort else "error")
        )
        if result is not None and fields["phase"] == "target":
            result["stop_reason"] = (
                "body_limit"
                if result["body_limited"]
                else "redirect_limit" if result["curl_exit"] == 47 else None
            )
            result["redirect_evidence"] = redirect_evidence(
                task["directory"], fields["url"], result
            )
        if result is not None:
            # This private native URL can contain userinfo. Export only its
            # allowlisted sanitized representation in redirect_evidence.
            result.pop("next_redirect_url", None)
            result.pop("next_redirect_truncated", None)
        if result is None:
            result = dict(
                verdict=None,
                detail=None,
                http_status=None,
                curl_exit=None,
                curl_error=None,
                final_url=None,
                redirect_count=None,
                body_limited=None,
                tor_verified=None,
                local_error=None,
            )
        duration = time.monotonic() - task["started"]
        end = dict(
            fields,
            ended_at=utc(),
            duration_seconds=duration,
            status=status,
            complete=status == "complete",
            adapter_started=True,
            **result,
        )
        if fields["pairing_state"] == "conditional_pending":
            end["pairing_state"] = (
                ("control_scheduled" if result["verdict"] in BLOCKY else "not_paired")
                if status == "complete"
                else "unavailable"
            )
        # Kill descendants even when the adapter leader has already exited.
        self.kill_group(process.pid, signal.SIGKILL)
        if not task["eof"]:
            try:
                self.selector.unregister(process.stdout)
            except KeyError:
                pass
        process.stdout.close()
        process.wait(timeout=1)
        self.active.pop(process.pid, None)
        shutil.rmtree(task["directory"], ignore_errors=True)
        if bundle:
            bundle.active = None
        if bundle and fields["pair_id"]:
            bundle.pairs[fields["pair_id"]]["attempts"][fields["route"]] = dict(
                end, _start=task["started"]
            )
        self.writer.emit("attempt_end", **end)
        if status == "complete":
            self.counts[fields["phase"]]["completed"] += 1
            if bundle:
                bundle.completed += 1
                if not hasattr(bundle, "history"):
                    bundle.history = []
                # Internal monotonic starts support pairing without claiming
                # synchronized wall clocks across machines.
                observation = dict(end, _start=task["started"])
                bundle.history.append(observation)
                if fields["pair_id"]:
                    bundle.pairs[fields["pair_id"]]["attempts"][fields["route"]] = (
                        observation
                    )
                self.verdicts[fields["route"]][result["verdict"]] += 1
                # Advancing records conditional pairs even during cancellation.
                # It only queues work; launch() independently rejects cancellation.
                bundle.advance(observation)
            else:
                self.preflight_ok = result["tor_verified"] is True
        elif not abort:
            raise Failure("local adapter/setup failed")

    def end_bundle(self, bundle):
        for pair_id, pair in bundle.pairs.items():
            observations = pair["attempts"]
            complete = len(observations) == 2 and all(
                v["complete"] for v in observations.values()
            )
            starts = [v["_start"] for v in observations.values()]
            observed_gap = abs(starts[0] - starts[1]) if len(starts) == 2 else None
            self.writer.emit(
                "pair_end",
                **public_target(bundle.target),
                pair_id=pair_id,
                trial_id=pair["trial_id"],
                attempt_ids={r: v["attempt_id"] for r, v in observations.items()},
                observed_start_gap_seconds=observed_gap,
                late=(observed_gap > self.args.max_partner_gap)
                if observed_gap is not None
                else None,
                state="complete" if complete else "missing",
                missing_routes=[
                    r
                    for r in ("tor", "direct")
                    if r not in observations or not observations[r]["complete"]
                ],
                aborted_routes=[
                    r
                    for r, observation in observations.items()
                    if observation["status"] == "aborted"
                ],
            )
        state = (
            "complete"
            if bundle.done
            else ("partial" if bundle.issued else "not_started")
        )
        self.states[bundle.target["target_id"]] = state
        self.writer.emit(
            "bundle_end",
            **public_target(bundle.target),
            state=state,
            attempts_issued=bundle.issued,
            attempts_completed=bundle.completed,
        )

    def cleanup(self):
        self.stopping = True
        # TERM, short grace, then KILL every owned session, including leaders
        # already reaped. Never inspect or signal unrelated process trees.
        for task in list(self.active.values()):
            self.kill_group(task["process"].pid, signal.SIGTERM)
        deadline = time.monotonic() + 0.2
        while self.active and time.monotonic() < deadline:
            try:
                self.read_ready(0.01)
            except Failure:
                break
        for task in list(self.active.values()):
            self.kill_group(task["process"].pid, signal.SIGKILL)
        for task in list(self.active.values()):
            task["process"].wait(timeout=1)
        # Drain bytes already produced before marking unfinished observations.
        try:
            self.read_ready(0)
        except Failure:
            pass
        for task in list(self.active.values()):
            try:
                self.finish(task, abort=True)
            except Failure:
                pass
        self.selector.close()
        self.temp.cleanup()

    def run(self):
        state, code = "complete", 0
        self.preflight_ok = False
        try:
            self.start_record()
            self.launch()
            while self.active and not CANCELLED:
                self.read_ready()
            if CANCELLED:
                state, code = "interrupted", 128 + CANCELLED
            elif not self.preflight_ok:
                raise Failure("Tor preflight failed")
            waiting = collections.deque(self.targets)
            while not CANCELLED and (waiting or self.bundles or self.active):
                # Hold the hostname lock for the entire bundle, including gaps
                # between its Tor/control requests. Paths and ports on the same
                # normalized hostname must not create overlapping bundles.
                busy_hosts = {b.target["hostname"] for b in self.bundles}
                # Scan past blocked duplicates without changing occurrence IDs.
                for _ in range(len(waiting)):
                    if len(self.bundles) >= self.args.workers:
                        break
                    target = waiting.popleft()
                    if target["hostname"] in busy_hosts:
                        waiting.append(target)
                        continue
                    bundle = Bundle(target, self.args)
                    bundle.advance()
                    self.bundles.append(bundle)
                    busy_hosts.add(target["hostname"])
                    self.states[target["target_id"]] = "partial"
                    self.writer.emit(
                        "bundle_start", **public_target(target), state="started"
                    )
                for bundle in list(self.bundles):
                    if bundle.done:
                        self.end_bundle(bundle)
                        self.bundles.remove(bundle)
                    elif bundle.pending and bundle.active is None:
                        self.launch(bundle)
                self.read_ready()
            if CANCELLED:
                state, code = "interrupted", 128 + CANCELLED
        except (Failure, OSError, ValueError) as exc:
            state, code = "error", 1
            self.error = (
                str(exc)
                if isinstance(exc, Failure)
                else "local measurement setup/output failure"
            )
        finally:
            try:
                self.cleanup()
            except (Failure, OSError, subprocess.TimeoutExpired):
                state, code = "error", 1
                self.error = "local cleanup failure"
            if CANCELLED and state != "error":
                state, code = "interrupted", 128 + CANCELLED
            if not self.writer.failed:
                try:
                    for bundle in self.bundles:
                        self.end_bundle(bundle)
                    self.writer.emit(
                        "run_end",
                        ended_at=utc(),
                        duration_seconds=time.monotonic() - self.run_started,
                        state=state,
                        complete=state == "complete",
                        exit_code=code,
                        counts=self.counts,
                        target_states=[
                            dict(public_target(t), state=self.states[t["target_id"]])
                            for t in self.targets
                        ],
                        verdict_counts={k: dict(v) for k, v in self.verdicts.items()},
                        error=self.error,
                    )
                except OutputFailure:
                    code = 1
            self.writer.restore()
        if self.error:
            print("Error: " + self.error, file=sys.stderr)
        return code


def main(argv=None):
    global CANCELLED
    CANCELLED = 0
    if sys.version_info < (3, 9):
        print("Error: jsonl-v2 requires Python 3.9 or later", file=sys.stderr)
        return 1
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = arguments(argv)
        targets = load_targets(args.target_file)
        for command in ("zsh", "curl", "awk", "grep", "head", "cut", "tr", "wc"):
            if shutil.which(command) is None:
                raise Failure("missing required command: " + command)

        def stop(signum, _frame):
            global CANCELLED
            CANCELLED = signum

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        return Engine(args, targets).run()
    except (Failure, OSError, UnicodeError) as exc:
        print(
            "Error: "
            + (
                str(exc)
                if isinstance(exc, Failure)
                else "cannot read target input or initialize measurement"
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
