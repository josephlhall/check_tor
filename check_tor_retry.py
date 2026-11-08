"""Bounded terminal response association and private-header Retry-After evidence.

This module only describes a response; it never sleeps, schedules, or changes
native verdicts. No raw header, URL, or exception text is retained in evidence.
"""

import datetime
import email.utils
import json
import math
import re
import urllib.parse

BOUNDS = dict(
    header_bytes=262144,
    response_blocks=256,
    header_lines=4096,
    value_bytes=256,
    url_bytes=8192,
    redirects=100,
    wait_seconds=2147483647,
    evidence_bytes=2048,
)
UTC = datetime.timezone.utc
DAYS = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
MONTHS = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
TIME = r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
HTTP_DATES = (
    re.compile(DAYS + r", [0-9]{2} " + MONTHS + r" [0-9]{4} " + TIME + r" GMT"),
    re.compile(r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), "
               r"[0-9]{2}-" + MONTHS + r"-[0-9]{2} " + TIME + r" GMT"),
    re.compile(DAYS + r" " + MONTHS + r" (?: [1-9]|[0-9]{2}) " + TIME + r" [0-9]{4}"),
)


def _utc(value):
    value = value.astimezone(UTC)
    precision = ("seconds" if not value.microsecond else
                 "milliseconds" if value.microsecond % 1000 == 0 else "microseconds")
    return value.isoformat(timespec=precision).replace("+00:00", "Z")


def _completion(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _request_url(value, base=None):
    """Conservatively compare URL facts; never emit or guess a destination."""
    if not isinstance(value, str) or not value:
        return None
    try:
        if len(value.encode("utf-8")) > BOUNDS["url_bytes"]:
            return None
        if re.search(r"[\x00-\x20\x7f\\]", value):
            return None
        reference = urllib.parse.urlsplit(value)
        if base is not None and (
            value.startswith(("///", "#", "?"))
            or value.endswith("#")
            or re.search(r"\?(?:#|$)", value)
            or "//" in reference.path
            or "//" in urllib.parse.urlsplit(base).path
            or (reference.scheme and (
                not reference.netloc or not value.startswith(("http://", "https://"))
            ))
        ):
            return None
        parsed = urllib.parse.urlsplit(urllib.parse.urljoin(base, value) if base else value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        if any(piece in (".", "..") for piece in parsed.path.split("/")):
            return None
        port = parsed.port
        host = parsed.hostname
        if ":" in host:
            host = "[" + host + "]"
        if port is not None:
            host += ":" + str(port)
        return urllib.parse.urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def _date(value, reference):
    form = next((index for index, pattern in enumerate(HTTP_DATES) if pattern.fullmatch(value)), None)
    if form is None:
        return None, "malformed_syntax"
    if form != 1:
        explicit_year = int(value.split()[3] if form == 0 else value.split()[-1])
        if not 1 <= explicit_year <= 9999:
            return None, "date_overflow"
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if form == 2:
            parsed = parsed.replace(tzinfo=UTC)  # asctime's HTTP form is GMT.
        if form == 1:
            # HTTP's obsolete two-digit year rule is relative to receipt, not
            # strptime/email's fixed 1969/2068 pivot. Completion approximates it.
            year = int(value.split("-", 2)[2][:2])
            year += ((reference.year + 50) // 100) * 100
            parsed = parsed.replace(year=year)
            # Compare month/day/time as well as year at the fifty-year edge.
            boundary = (reference.year + 50, reference.month, reference.day,
                        reference.hour, reference.minute, reference.second,
                        reference.microsecond)
            candidate = (year, parsed.month, parsed.day, parsed.hour,
                         parsed.minute, parsed.second, parsed.microsecond)
            if candidate > boundary:
                parsed = parsed.replace(year=year - 100)
        else:
            # email's permissive parser applies its two-digit pivot even to
            # four-digit strings such as 0000; enforce the actual HTTP year.
            year = int(value.split()[3] if form == 0 else value.split()[-1])
            parsed = parsed.replace(year=year)
        return parsed.astimezone(UTC), None
    except (ValueError, TypeError, OverflowError):
        # Calendar/time errors are separate from grammar or numeric overflow.
        # No exception may reveal header text.
        return None, "invalid_date"


def _value(value, ended_at):
    if len(value) > BOUNDS["value_bytes"]:
        return dict(state="truncated", reason="value_bytes_limit")
    try:
        text = value.decode("ascii")
    except UnicodeError:
        return dict(state="invalid", reason="malformed_syntax")
    reference = _completion(ended_at)
    if re.fullmatch(r"[0-9]+", text):
        # Compare bounded decimal strings before int(), including long leading
        # zeroes. Neither Python's digit limit nor an enormous integer is used.
        digits = text.lstrip("0") or "0"
        maximum = str(BOUNDS["wait_seconds"])
        if len(digits) > len(maximum) or (len(digits) == len(maximum) and digits > maximum):
            return dict(state="invalid", reason="numeric_overflow")
        if reference is None:
            return dict(state="unavailable", reason="completion_clock_unavailable")
        return dict(
            state="usable", reason="valid_delay", form="delay_seconds", units="seconds",
            wait_seconds=int(digits), reference_time_utc=_utc(reference),
            reference_basis="observation_completion_conservative",
            clock_uncertainty="receipt_precedes_completion",
        )
    if reference is None:
        return dict(state="unavailable", reason="completion_clock_unavailable")
    parsed, reason = _date(text, reference)
    if reason:
        return dict(state="invalid", reason=reason)
    delta = (parsed - reference).total_seconds()
    wait = max(0, math.ceil(delta))
    if wait > BOUNDS["wait_seconds"]:
        return dict(state="invalid", reason="date_wait_overflow")
    return dict(
        state="usable", reason="past_date" if delta < 0 else "valid_date",
        form="http_date", units="seconds", wait_seconds=wait,
        not_before_utc=_utc(parsed), past_date=delta < 0,
        reference_time_utc=_utc(reference),
        reference_basis="local_observation_completion_clock",
        clock_uncertainty="local_server_clock_offset_unknown",
    )


def terminal_response_fields(directory, initial_url, result, wanted):
    """Associate allowlisted fields with curl's final visited response.

    Require a complete, unambiguous header sequence that agrees with curl's
    status, redirect count and effective URL. Keep private values in memory
    only long enough to resolve Location and extract the requested fields.
    """
    count = result.get("redirect_count")
    if type(count) is not int or not 0 <= count <= BOUNDS["redirects"]:
        return None, dict(state="unavailable", reason="native_redirect_count")
    actual = _request_url(result.get("final_url"))
    current = _request_url(initial_url)
    if actual is None or current is None:
        return None, dict(state="unavailable", reason="native_url_unavailable")
    try:
        with (directory / "headers").open("rb") as source:
            raw = source.read(BOUNDS["header_bytes"] + 1)
    except OSError:
        return None, dict(state="unavailable", reason="headers_unavailable")
    if len(raw) > BOUNDS["header_bytes"]:
        return None, dict(state="truncated", reason="header_bytes_limit")
    if not raw:
        return None, dict(state="unavailable", reason="headers_unavailable")
    parts = re.split(rb"\r?\n\r?\n", raw)
    if parts[-1]:
        return None, dict(state="unavailable", reason="incomplete_final_block")
    if len(parts) - 1 > BOUNDS["response_blocks"]:
        return None, dict(state="truncated", reason="response_blocks_limit")
    blocks = []
    lines_seen = 0
    for index, part in enumerate(parts[:-1]):
        lines = part.split(b"\n")
        lines = [line.removesuffix(b"\r") for line in lines]
        lines_seen += len(lines)
        if lines_seen > BOUNDS["header_lines"]:
            return None, dict(state="truncated", reason="header_lines_limit")
        status = re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) +([0-9]{3})(?: +([^\r\n]*))?", lines[0])
        if not status:
            return None, dict(state="invalid", reason="malformed_response_block")
        code = int(status[1])
        connect = (
            code == 200 and lines[0].startswith(b"HTTP/1.")
            and (status[2] or b"").lower() == b"connection established"
        )
        if 100 <= code < 200 or connect:
            # In particular, a reason phrase is not proof that a preceding
            # 200 was the origin and a trailing 200 was the proxy.
            if index == len(parts) - 2:
                return None, dict(state="unavailable", reason="terminal_block_unavailable")
            continue
        # No permissive splitlines(): controls must never become separators.
        if any(re.search(rb"[\x00-\x08\x0b-\x1f\x7f]", line) for line in lines[1:]):
            return None, dict(state="invalid", reason="malformed_header_block")
        fields = []
        for line in lines[1:]:
            if line.startswith((b" ", b"\t")) or b":" not in line:
                return None, dict(state="invalid", reason="ambiguous_header_block")
            name, value = line.split(b":", 1)
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                return None, dict(state="invalid", reason="malformed_header_block")
            name = name.lower()
            if name == b"location" or name in wanted:
                fields.append((name, value.strip(b" \t")))
        blocks.append((code, fields))
    if len(blocks) != count + 1:
        return None, dict(state="unavailable", reason="response_count_mismatch")
    if blocks[-1][0] != result["http_status"]:
        return None, dict(state="invalid", reason="final_status_mismatch")
    for code, fields in blocks[:-1]:
        locations = [value for name, value in fields if name == b"location"]
        if not 300 <= code < 400 or len(locations) != 1:
            return None, dict(state="invalid", reason="redirect_chain_ambiguous")
        try:
            current = _request_url(locations[0].decode("utf-8"), current)
        except UnicodeError:
            current = None
        if current is None:
            return None, dict(state="unavailable", reason="redirect_chain_unavailable")
    if current != actual:
        return None, dict(state="invalid", reason="final_url_mismatch")
    return blocks[-1][1], None


def retry_after_evidence(directory, initial_url, result, ended_at):
    """Describe only a complete final visited 429/503 response header block.

    Curl's native final status/count/URL must agree with the entire captured
    response sequence. Informational and CONNECT blocks are never candidates.
    Delay-seconds use completion as a conservative receipt-relative anchor;
    dates use the local completion clock, whose server offset remains unknown.
    A past date is zero by that clock and promises nothing about later success.
    """
    if result.get("http_status") not in (429, 503):
        return dict(state="not_applicable", reason="http_status")
    fields, problem = terminal_response_fields(directory, initial_url, result, {b"retry-after"})
    if problem:
        return problem
    values = [value for name, value in fields if name == b"retry-after"]
    if not values:
        return dict(state="absent", reason="field_absent")
    if len(values) != 1:
        return dict(state="invalid", reason="duplicate_fields")
    evidence = _value(values[0], ended_at)
    # All values above are fixed enums, bounded numbers or normalized UTC dates.
    # Keep an explicit serialized cap as an invariant if the schema grows later.
    if len(json.dumps(evidence).encode("utf-8")) > BOUNDS["evidence_bytes"]:
        return dict(state="truncated", reason="serialized_evidence_limit")
    return evidence
