"""Compile one reviewed CollecTor exit list into a private nginx include."""

import argparse
import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile


SOURCE = "https://collector.torproject.org/recent/exit-lists/"
INCLUDE = "condition-http-tor-diff.conf"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ADDRESSES = 8192
MAX_LIST_AGE = timedelta(hours=3)
MAX_ADDRESS_AGE = timedelta(hours=24)
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
LIST_TIME = "%Y-%m-%d-%H-%M-%S"
OBSERVATION_TIME = "%Y-%m-%d %H:%M:%S"

TIMESTAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
ADDRESS = rf"ExitAddress ([.0-9]+) ({TIMESTAMP})\n"
RECORD = re.compile(
    rf"ExitNode [0-9A-Fa-f]{{40}}\nPublished ({TIMESTAMP})\n"
    rf"LastStatus ({TIMESTAMP})\n(?:{ADDRESS})+"
)


def utc(value, pattern):
    try:
        parsed = datetime.strptime(value, pattern).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("invalid timestamp") from None
    if parsed.strftime(pattern) != value:
        raise ValueError("invalid timestamp")
    return parsed


def parse_observations(data, list_time):
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the size limit")
    if not data.startswith(b"@type tordnsel 1.0\n"):
        raise ValueError("source must be an annotated tordnsel 1.0 exit list")
    try:
        records = data.decode("ascii").split("\n", 1)[1]
    except UnicodeDecodeError:
        raise ValueError("source must contain ASCII records") from None
    if records.startswith("Downloaded "):
        downloaded, _, records = records.partition("\n")
        if utc(downloaded.removeprefix("Downloaded "), OBSERVATION_TIME) != list_time:
            raise ValueError("source filename and Downloaded timestamp disagree")

    observations = {}
    cursor = 0
    while cursor < len(records):
        record = RECORD.match(records, cursor)
        if not record:
            raise ValueError("malformed or unsupported exit list record")
        for timestamp in record.group(1, 2):
            utc(timestamp, OBSERVATION_TIME)
        for value, timestamp in re.findall(ADDRESS, record.group()):
            try:
                address = ipaddress.IPv4Address(value)
            except ValueError:
                raise ValueError("invalid exit IPv4 address") from None
            if not address.is_global or address.is_multicast or address.is_reserved:
                raise ValueError("exit list requires public IPv4 addresses")
            observed = utc(timestamp, OBSERVATION_TIME)
            if observed > list_time:
                raise ValueError("exit observation follows the source timestamp")
            observations[address] = max(observed, observations.get(address, observed))
            if len(observations) > MAX_ADDRESSES:
                raise ValueError("source exceeds the address limit")
        cursor = record.end()
    return observations


def freeze(source, expected_sha256, batch_end, now):
    try:
        reviewed_digest = base64.b64decode(expected_sha256, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("source SHA-256 must be the Base64 CollecTor index value") from None
    if len(reviewed_digest) != 32 or base64.b64encode(reviewed_digest).decode("ascii") != expected_sha256:
        raise ValueError("source SHA-256 must be the Base64 CollecTor index value")

    list_time = utc(source.name, LIST_TIME)
    if not list_time <= now < batch_end:
        raise ValueError("require a non-future source and a future batch end")
    if batch_end >= list_time + MAX_LIST_AGE:
        raise ValueError("source will be stale by the planned batch end")
    # Nonblocking open lets us reject named pipes without waiting for a writer.
    with open(source, "rb", opener=lambda path, flags: os.open(path, flags | os.O_NONBLOCK)) as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("source must be a local regular file")
        data = handle.read(MAX_SOURCE_BYTES + 1)
    if hashlib.sha256(data).digest() != reviewed_digest:
        raise ValueError("source SHA-256 does not match")

    observed = parse_observations(data, list_time)
    selected = sorted(address for address, stamp in observed.items()
                      if batch_end < stamp + MAX_ADDRESS_AGE)
    if not selected or batch_end >= max(observed.values()) + MAX_LIST_AGE:
        raise ValueError("no sufficiently recent IPv4 observation for the planned batch end")
    stamps = [observed[address] for address in selected]
    # nginx reads this include at start or reload and keeps the snapshot in
    # use until stopped or reconfigured. The operator enforces its cutoff.
    rows = [
        "# REF-TOR-DIFF v1, tordnsel 1.0, frozen IPv4 coverage",
        f"# source: {SOURCE}{source.name}",
        f"# source SHA-256 (Base64): {expected_sha256}",
        f"# source timestamp UTC: {list_time.strftime(UTC_FORMAT)}",
        f"# frozen deadline UTC: {batch_end.strftime(UTC_FORMAT)}",
        f"# oldest selected observation UTC: {min(stamps).strftime(UTC_FORMAT)}",
        f"# newest selected observation UTC: {max(stamps).strftime(UTC_FORMAT)}",
        f"# selected IPv4 addresses: {len(selected)} of {len(observed)}",
        "geo $remote_addr $reference_exit_membership {",
        "    default unavailable;",
        "    0.0.0.0/0 unlisted;",
    ]
    rows.extend(f"    {address}/32 listed;" for address in selected)
    return "\n".join(rows + ["}", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="cached exit list with its original UTC filename")
    parser.add_argument("--sha256", required=True, help="reviewed CollecTor index sha256 (Base64)")
    parser.add_argument("--batch-end", required=True, help="frozen deadline as YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--prefix", required=True, type=Path, help="new private nginx config directory")
    args = parser.parse_args()
    try:
        config = freeze(args.source, args.sha256, utc(args.batch_end, UTC_FORMAT),
                        datetime.now(timezone.utc))
        with tempfile.NamedTemporaryFile(dir=args.prefix) as output:
            output.write(config.encode("ascii"))
            output.flush()
            # Publish only complete bytes and never replace an existing include.
            os.link(output.name, args.prefix / INCLUDE)
    except ValueError as error:
        parser.exit(1, f"Exit snapshot unavailable: {error}\n")
    except OSError as error:
        parser.exit(1, f"Exit snapshot unavailable: {error.strerror}\n")


if __name__ == "__main__":
    main()
