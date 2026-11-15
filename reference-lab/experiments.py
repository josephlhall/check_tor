#!/usr/bin/env python3
"""Run fixed offline experiments using the check_tor probe and classifier."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from lab_fixture import (
    HERE, LOOPBACK, ROOT, Interrupted, LabError, Processes,
    direct_probe, nginx_fixture, private_env, tls_certificate,
)


CASES = {
    "normal": "The opening page and its visitor-information destination return HTTP 200.",
    "accepted": "A terminal HTTP 202 serves a short page explaining that a request is pending.",
    "tls-handshake-stall": "The listener accepts TCP and withholds the TLS handshake.",
    "tls-response-stall": "The listener completes TLS and reads request bytes, then withholds HTTP.",
    "preflight-failure": "Synthetic curl reports HTTP 200 with IsTor false for the verification URL.",
}
ROUTES = {"normal": ("/normal", "/normal/complete"), "accepted": ("/accepted",)}
SCANNER_SOURCES = (
    "check_tor.zsh", "check_tor_core.zsh", "check_tor_probe.zsh",
    "check_tor_measure.py", "check_tor_retry.py", "check_tor_onion.py",
)
PREFLIGHT_URL = "https://check.torproject.org/api/ip"


def outside_git(path):
    for ancestor in (path, *path.parents):
        if os.path.lexists(ancestor / ".git") or (
            (ancestor / "HEAD").is_file() and (ancestor / "objects").is_dir()
            and (ancestor / "refs").is_dir()
        ):
            raise LabError("choose a directory outside Git checkouts and repositories")


def output_destination(path):
    if path is None:
        return None
    try:
        path = path.expanduser()
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LabError(f"cannot resolve --output-dir parent: {exc}") from exc
    if path.name in ("", ".."):
        raise LabError("--output-dir must name a new directory")
    outside_git(parent)
    destination = parent / path.name
    if os.path.lexists(destination):
        raise LabError(f"--output-dir already exists: {destination}")
    return destination


def write_artifacts(destination, manifest, observations):
    # Resolve and check again just before the exclusive mkdir. Files are also
    # created exclusively, including against pre-existing dangling symlinks.
    destination = output_destination(destination)
    files = {
        "observations.jsonl": observations,
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    }
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(destination.parent, flags)
    try:
        if destination.parent.resolve(strict=True) != destination.parent:
            raise LabError("--output-dir parent changed during the run")
        os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
        directory_fd = os.open(destination.name, flags, dir_fd=parent_fd)
        try:
            for name, content in files.items():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(content)
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)


def dependencies(case):
    names = ["zsh"]
    if case != "preflight-failure":
        names += ["curl", "openssl"]
    if case in ROUTES:
        names.append("nginx")
    tools = {name: shutil.which(name) for name in names}
    missing = [name for name, location in tools.items() if not location]
    if missing:
        raise LabError(f"install {' and '.join(missing)} and put it on PATH for {case}")
    return {name: os.path.abspath(location) for name, location in tools.items()}


def runtime_inventory(tools, processes, env):
    versions = {
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": platform.python_version(),
    }
    options = {"zsh": "--version", "curl": "--version", "openssl": "version", "nginx": "-v"}
    for name, location in tools.items():
        result = processes.run([location, options[name]], env=env, timeout=5)
        version = (result.stdout.strip() or result.stderr.strip()).splitlines()
        if not version:
            raise LabError(f"{name} did not report a version")
        versions[name] = version[0]
    return versions


@contextmanager
def stall_fixture(certificate, after_tls):
    stages = {
        "tcp_accepted": False,
        "tls_handshake_record_started": False,
        "tls_completed": False,
        "request_bytes_received": False,
    }
    stop = threading.Event()
    with socket.socket() as listener:
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        listener.settimeout(0.1)
        port = listener.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(certificate.with_suffix(".key")))

        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    stages["tcp_accepted"] = True
                    # Bound each operation so an interrupted client cannot
                    # delay cleanup. Leave the first record byte for TLS.
                    connection.settimeout(0.8)
                    try:
                        stages["tls_handshake_record_started"] = (
                            connection.recv(1, socket.MSG_PEEK) == bytes((22,))
                        )
                        if after_tls:
                            with context.wrap_socket(connection, server_side=True) as secure:
                                stages["tls_completed"] = True
                                stages["request_bytes_received"] = bool(secure.recv(8192))
                                stop.wait()
                        else:
                            stop.wait()
                    except OSError as exc:
                        stages["fixture_error"] = type(exc).__name__
                return

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield port, stages
        finally:
            stop.set()
            worker.join(2.5)
            if worker.is_alive():
                raise LabError("loopback stall fixture did not stop")


def run_probe_case(case, timeout, prefix, tools, processes, env, experiment_id):
    certificate = tls_certificate(prefix, tools["openssl"], processes)
    env.update(CURL_CA_BUNDLE=str(certificate), SSL_CERT_FILE=str(certificate))
    if case in ROUTES:
        with nginx_fixture(prefix, certificate, tools["nginx"], processes) as fixture:
            direct = [
                observe_probe(prefix, processes, tools["zsh"], fixture.port, route, timeout, env)
                for route in ROUTES[case]
            ]
    else:
        with stall_fixture(certificate, case == "tls-response-stall") as (port, stages):
            direct = [observe_probe(prefix, processes, tools["zsh"], port, "/", timeout, env)]
        direct[0]["loopback_listener"] = stages
    return [
        dict(row, schema="check_tor.lab_probe.v1", experiment_id=experiment_id)
        for row in direct
    ]


def observe_probe(prefix, processes, zsh, port, route, timeout, env):
    with tempfile.TemporaryDirectory(prefix="probe-", dir=prefix) as directory:
        request = Path(directory)
        started = time.monotonic()
        probe = direct_probe(request, processes, zsh, port, route, timeout, env)
        return {
            "url": f"https://{LOOPBACK}:{port}{route}",
            "route": "direct",
            "requested_timeout_seconds": timeout,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "response_body_bytes": (request / "body").stat().st_size,
            "probe": probe,
        }


def mock_curl(prefix, bin_dir):
    invocation_log = prefix / "mock-curl.log"
    fake = bin_dir / "curl"
    # Use no programs beyond the script interpreter and its shell builtins.
    # Any unrecognized transfer is counted and rejected without networking.
    fake.write_text(
        "#!/bin/sh\n"
        "url= destination= format=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case $1 in\n"
        "    -o) destination=$2; shift ;;\n"
        "    -w) format=$2; shift ;;\n"
        "    http://*|https://*) [ -z \"$url\" ] || exit 2; url=$1 ;;\n"
        "  esac\n"
        "  shift\n"
        "done\n"
        f"printf '%s\\n' \"$url\" >> {shlex.quote(str(invocation_log))} || exit 2\n"
        f"[ \"$url\" = {shlex.quote(PREFLIGHT_URL)} ] || exit 2\n"
        "[ -n \"$destination\" ] && [ -n \"$format\" ] || exit 2\n"
        "printf '%s' '{\"IsTor\":false}' > \"$destination\" || exit 2\n"
        "printf 'CHECK_TOR_META\\t200\\t0\\t%s\\t' \"$url\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o700)
    return fake, invocation_log


def run_mock_preflight(prefix, tools, processes):
    bin_dir = prefix / "bin"
    bin_dir.mkdir(mode=0o700)
    commands = {"zsh": tools["zsh"], "python3": sys.executable}
    for name in ("awk", "grep", "head", "cut", "tr", "wc", "rm"):
        # Copy only scanner prerequisites into the synthetic PATH.
        executable = shutil.which(name, path=os.defpath)
        if not executable:
            raise LabError(f"install the standard {name} utility for the synthetic preflight")
        commands[name] = executable
    for name, executable in commands.items():
        (bin_dir / name).symlink_to(executable)
    fake, invocation_log = mock_curl(prefix, bin_dir)
    env = private_env(prefix, str(bin_dir))
    # System zshenv runs before the private zshenv; restore the allowlist in
    # every nested shell. Abort if startup prevents the intended resolution.
    (prefix / ".zshenv").write_text(f"export PATH={shlex.quote(str(bin_dir))}\n", encoding="utf-8")
    resolved = processes.run([tools["zsh"], "-c", "command -v curl"], env=env, check=False)
    if resolved.returncode or resolved.stdout.strip() != str(fake):
        raise LabError("cannot verify isolated mock curl through zsh startup")
    target = prefix / "synthetic-target.txt"
    target.write_text("https://target.example.invalid/\n", encoding="ascii")
    # If interpreter startup changes despite the verified allowlist, even a
    # real curl would be routed to this bound, non-listening loopback port.
    with socket.socket() as closed_proxy:
        closed_proxy.bind((LOOPBACK, 0))
        proxy = f"{LOOPBACK}:{closed_proxy.getsockname()[1]}"
        result = processes.run(
            [tools["zsh"], str(ROOT / "check_tor.zsh"), "--format", "jsonl-v2",
             "--reproducible", "--control", "never", "--proxy", proxy, str(target)],
            cwd=prefix, env=env, timeout=10, check=False, grace=2,
        )
    if not invocation_log.exists():
        raise LabError(f"scanner did not invoke isolated mock curl: {result.stderr.strip()}")
    calls = invocation_log.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    starts = [row for row in rows if row.get("type") == "attempt_start"]
    attempts = [row for row in rows if row.get("type") == "attempt_end"]
    if (
        calls != [PREFLIGHT_URL] or result.returncode != 1
        or [row.get("phase") for row in starts] != ["preflight"] or len(attempts) != 1
        or attempts[0].get("phase") != "preflight"
        or attempts[0].get("tor_verified") is not False
        or attempts[0].get("http_status") != 200 or not rows
        or rows[-1].get("type") != "run_end" or rows[-1].get("state") != "error"
        or rows[-1].get("error") != "Tor preflight failed"
        or rows[-1].get("counts", {}).get("target") != {"issued": 0, "completed": 0}
    ):
        raise LabError("mock preflight did not produce exactly one failed verification and zero target requests")
    return result, rows


def source_inventory(case):
    lab_sources = ["experiments.py", "lab_fixture.py"]
    if case in ROUTES:
        lab_sources.extend(("nginx.conf", "routes.conf"))
    sources = [ROOT / name for name in SCANNER_SOURCES] + [HERE / name for name in lab_sources]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources}


def run_experiment(args, processes):
    destination = output_destination(args.output_dir)
    tools = dependencies(args.case)
    sources = source_inventory(args.case) if destination is not None else None
    parent = Path(os.environ.get("TMPDIR") or "/tmp").resolve(strict=True)
    try:
        outside_git(parent)
    except LabError:
        parent = Path("/tmp").resolve(strict=True)
        outside_git(parent)
    with tempfile.TemporaryDirectory(prefix="check-tor-experiment-", dir=parent) as directory:
        prefix = Path(directory)
        env = private_env(prefix, os.environ.get("PATH") or os.defpath)
        runtime = runtime_inventory(tools, processes, env)
        experiment_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc).isoformat()
        if args.case == "preflight-failure":
            result, rows = run_mock_preflight(prefix, tools, processes)
            observations = result.stdout
            provenance = {
                "observation_format": "jsonl-v2", "transport": "synthetic_curl",
                "scanner_exit_status": result.returncode,
                "scanner_stderr": result.stderr,
            }
            summary = [
                "Observed verification: HTTP 200, Tor verified false (synthetic).",
                f"Scanner exit {result.returncode}. Target requests issued: 0. Target accessibility is unobserved.",
            ]
        else:
            timeout = args.timeout or 2
            rows = run_probe_case(args.case, timeout, prefix, tools, processes, env, experiment_id)
            observations = "".join(json.dumps(row) + "\n" for row in rows)
            provenance = {
                "observation_format": "check_tor.lab_probe.v1", "transport": "loopback",
                "probe_timeout_seconds": timeout,
            }
            summary = []
            for row in rows:
                probe = row["probe"]
                status = probe["http_status"]
                http = f"HTTP {status}" if status is not None else "no HTTP status"
                summary.append(
                    f"Observed {row['url']}: {http}, curl exit {probe['curl_exit']}, "
                    f"{probe['verdict']}, {row['response_body_bytes']} body bytes "
                    f"in {row['elapsed_seconds']:.3f}s."
                )
                summary.append(f"Scanner detail: {probe['detail']}")
                if "loopback_listener" in row:
                    stages = row["loopback_listener"]
                    summary.append(
                        f"Listener evidence: TCP accepted={stages['tcp_accepted']}, "
                        f"TLS handshake record started={stages['tls_handshake_record_started']}, "
                        f"TLS completed={stages['tls_completed']}, "
                        f"request bytes received={stages['request_bytes_received']}."
                    )
            summary.append("These curl probes record retrieval. Browser actions and task completion were not measured.")

    processes.check()
    if destination is not None:
        if source_inventory(args.case) != sources:
            raise LabError("instrument or fixture source changed during the run")
        manifest = {
            "schema": "check_tor.experiment.v1",
            "experiment_id": experiment_id,
            "started_at_utc": started,
            "condition": {"case": args.case, "configured_behavior": CASES[args.case]},
            "provenance": provenance,
            "runtime": runtime,
            "source_sha256": sources,
        }
        if args.case == "preflight-failure":
            manifest["provenance"]["execution_id"] = rows[0]["execution_id"]
        write_artifacts(destination, manifest, observations)
        summary.append(f"Saved private artifacts to {destination}")
    processes.check()
    print(f"Configured condition ({args.case}): {CASES[args.case]}")
    print("\n".join(summary))


def timeout_seconds(value):
    digits = value.lstrip("0")
    if not digits or len(digits) > 2 or not digits.isascii() or not digits.isdecimal() or int(digits) > 60:
        raise argparse.ArgumentTypeError("timeout must be a whole number from 1 to 60 seconds")
    return int(digits)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list the fixed case IDs", allow_abbrev=False)
    run = subparsers.add_parser("run", help="run one offline experiment", allow_abbrev=False)
    run.add_argument("case", choices=CASES)
    run.add_argument("--timeout", type=timeout_seconds, metavar="SECONDS",
                     help="local probe deadline, 1 to 60 seconds (default: 2)")
    run.add_argument("--output-dir", type=Path, metavar="PATH",
                     help="save private artifacts in a new directory outside Git")
    args = parser.parse_args(argv)
    if args.command == "list":
        for case, description in CASES.items():
            print(f"{case:<21} {description}")
        return 0
    if args.case == "preflight-failure" and args.timeout is not None:
        run.error("--timeout applies only to the local target probe cases")

    processes = Processes()
    previous = {signum: signal.signal(signum, processes.cancel)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        run_experiment(args, processes)
        return 0
    except Interrupted as exc:
        print(f"Experiment interrupted by {exc}.", file=sys.stderr)
        return 128 + processes.interrupted
    except (LabError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Experiment failed: {exc}", file=sys.stderr)
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
