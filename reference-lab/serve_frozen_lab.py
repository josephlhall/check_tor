"""Run a dedicated nginx origin until its reviewed exit snapshot expires."""

import argparse
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import time

from freeze_exit_snapshot import INCLUDE, UTC_FORMAT, utc


DEADLINE_PREFIX = b"# frozen deadline UTC: "
STOP_MARGIN_SECONDS = 5


def service_cutoff(snapshot, expected_digest):
    data = snapshot.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("frozen include does not match the reviewed SHA-256")
    values = [line[len(DEADLINE_PREFIX):] for line in data.splitlines()
              if line.startswith(DEADLINE_PREFIX)]
    if len(values) != 1:
        raise ValueError("frozen include must record one deadline")
    deadline = utc(values[0].decode("ascii"), UTC_FORMAT).timestamp()
    return deadline - STOP_MARGIN_SECONDS


def stop(_signum, _frame):
    raise SystemExit(0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="absolute path to nginx.conf")
    parser.add_argument("--runtime", required=True, type=Path, help="private nginx runtime directory")
    parser.add_argument("--include-sha256", required=True, help="reviewed generated include SHA-256 in hex")
    args = parser.parse_args()
    config = args.config.resolve()
    try:
        cutoff = service_cutoff(config.with_name(INCLUDE), args.include_sha256)
        seconds = cutoff - time.time()
        if seconds <= 0:
            raise ValueError("frozen snapshot is at or past the service cutoff")
        # A backward wall-clock correction must never extend this launch.
        monotonic_cutoff = time.monotonic() + seconds
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        with subprocess.Popen(
            ["nginx", "-p", str(args.runtime.resolve()) + "/", "-c", str(config),
             "-e", "stderr", "-g", "daemon off;"], start_new_session=True,
        ) as nginx:
            try:
                while min(cutoff - time.time(), monotonic_cutoff - time.monotonic()) > 0:
                    try:
                        return nginx.wait(timeout=0.25)
                    except subprocess.TimeoutExpired:
                        pass
                print("Frozen exit snapshot reached the service cutoff", flush=True)
            finally:
                # Kill the dedicated process group so no worker can keep serving
                # after the supervisor exits. The service manager owns the cgroup.
                try:
                    os.killpg(nginx.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except (OSError, ValueError) as error:
        parser.exit(1, f"Frozen lab unavailable: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
