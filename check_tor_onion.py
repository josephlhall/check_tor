"""Passive onion advertisements from the existing terminal response capture."""

import ipaddress
import json
import re
import urllib.parse

from check_tor_retry import BOUNDS as RESPONSE_BOUNDS, terminal_response_fields

BOUNDS = {
    name: RESPONSE_BOUNDS[name]
    for name in ("header_bytes", "response_blocks", "header_lines", "url_bytes", "redirects")
}
BOUNDS.update(
    fields_per_type=8, value_bytes=4096, alt_entries=8, protocol_bytes=64,
    evidence_bytes=4096,
)
DNS_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                      r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
V3_ONION = re.compile(r"(?:^|\.)[a-z2-7]{56}\.onion$")
TOKEN = r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]"
PERCENT_ESCAPE = re.compile(r"%([0-9A-F]{2})")
QUOTED_PARAMETER = r'"(?:[^"\\]|\\[\t -~\x80-\xff])*"'
ALT_MEMBER = re.compile(
    rf'[ \t]*({TOKEN}+)="([^"\\]*)"'
    rf'(?:[ \t]*;[ \t]*{TOKEN}+=(?:{TOKEN}+|{QUOTED_PARAMETER}))*'
    r'[ \t]*(,|$)'
)
ALT_AUTHORITY = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]*):([0-9]{1,5})")
LOCATION_AUTHORITY = re.compile(r"([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?")
PCHAR = r"A-Za-z0-9._~!$&'()*+,;=:@%\-"
USERINFO = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:%-]*")


def _status(state, reason):
    return dict(state=state, reason=reason)


def _dns_name(value):
    # Accept at most one root dot. Check the host separately from any
    # discarded userinfo, resource path, parameters, or port.
    host = value.lower().removesuffix(".")
    return host if len(host) <= 253 and DNS_NAME.fullmatch(host) else None


def _onion_location(values):
    if len(values) != 1:
        return _status("invalid", "duplicate_fields")
    try:
        value = values[0].decode("ascii")
        parsed = urllib.parse.urlsplit(value)
    except (ValueError, UnicodeError):
        return _status("invalid", "invalid_onion_url")
    userinfo, separator, authority = parsed.netloc.rpartition("@")
    match = LOCATION_AUTHORITY.fullmatch(authority)
    if (
        not re.match(r"https?://", value, re.IGNORECASE)
        or re.search(r"[\x00-\x20\x7f\\]|%(?![0-9A-Fa-f]{2})", value)
        or not USERINFO.fullmatch(userinfo)
        or not re.fullmatch(rf"[{PCHAR}/]*", parsed.path)
        or not all(re.fullmatch(rf"[{PCHAR}/?]*", part)
                   for part in (parsed.query, parsed.fragment))
        or not match
    ):
        return _status("invalid", "invalid_onion_url")
    host = _dns_name(match[1])
    port = int(match[2]) if match[2] is not None else None
    if not host or not V3_ONION.search(host) or (port is not None and not 1 <= port <= 65535):
        return _status("invalid", "invalid_onion_url")
    origin = parsed.scheme.lower() + "://" + host
    if port is not None:
        origin += ":" + str(port)
    # Inspect the original delimiters so even empty query and fragment
    # components count as omitted. Export only their names.
    before_fragment, fragment, _ = value.partition("#")
    omitted = [
        name for name, present in (
            ("userinfo", separator), ("path", parsed.path),
            ("query", "?" in before_fragment), ("fragment", fragment),
        ) if present
    ]
    return dict(state="available", origin=origin, omitted_components=omitted)


def _alt_svc(values):
    # Preserve opaque bytes in quoted extension parameters, which are
    # discarded. The protocol and authority grammars still require ASCII.
    text = b",".join(values).decode("latin-1")
    if text == "clear":
        return _status("absent", "clear")
    entries = []
    position, count = 0, 0
    while True:
        match = ALT_MEMBER.match(text, position)
        if match is None:
            return _status("invalid", "invalid_alt_svc")
        count += 1
        protocol, authority, comma = match.groups()
        if count > BOUNDS["alt_entries"]:
            return _status("truncated", "alt_entries_limit")
        if len(protocol) > BOUNDS["protocol_bytes"]:
            return _status("truncated", "protocol_bytes_limit")
        # Keep the RFC 7838 token spelling. An escape must use uppercase
        # hex and must not encode a token character other than percent.
        if "%" in PERCENT_ESCAPE.sub("", protocol) or any(
            code != "25" and re.fullmatch(TOKEN, chr(int(code, 16)))
            for code in PERCENT_ESCAPE.findall(protocol)
        ):
            return _status("invalid", "invalid_alt_svc")
        endpoint = ALT_AUTHORITY.fullmatch(authority)
        if not endpoint or not 1 <= int(endpoint[2]) <= 65535:
            return _status("invalid", "invalid_alt_svc")
        host = endpoint[1]
        if host.startswith("["):
            try:
                ipaddress.IPv6Address(host[1:-1])
            except ValueError:
                return _status("invalid", "invalid_alt_svc")
        elif host:
            host = _dns_name(host)
            if not host:
                return _status("invalid", "invalid_alt_svc")
            if host.endswith(".onion"):
                if not V3_ONION.search(host):
                    return _status("invalid", "invalid_onion_authority")
                entry = dict(protocol=protocol, authority=host + ":" + str(int(endpoint[2])))
                if entry not in entries:
                    entries.append(entry)
        if not comma:
            break
        position = match.end()
    return dict(state="available", entries=entries) if entries else _status("absent", "no_onion_authority")


def _field_evidence(fields, name, parse):
    values = [value for field, value in fields if field == name]
    if not values:
        return _status("absent", "field_absent")
    if len(values) > BOUNDS["fields_per_type"]:
        return _status("truncated", "fields_per_type_limit")
    if any(len(value) > BOUNDS["value_bytes"] for value in values):
        return _status("truncated", "value_bytes_limit")
    return parse(values)


def onion_advertisement_evidence(directory, initial_url, result):
    """Collect two independent evidence states without changing the observation."""
    status = result.get("http_status") if result else None
    if type(status) is not int or not 200 <= status <= 599:
        problem = _status("unavailable", "native_status_unavailable")
    else:
        fields, problem = terminal_response_fields(
            directory, initial_url, result, {b"onion-location", b"alt-svc"}
        )
    if problem:
        return dict(source=None, onion_location=problem, alt_svc=problem)

    url = urllib.parse.urlsplit(result["final_url"])
    source = dict(https=url.scheme.lower() == "https",
                  onion_hostname=url.hostname.lower().rstrip(".").endswith(".onion"))
    evidence = dict(
        source=source,
        onion_location=_field_evidence(fields, b"onion-location", _onion_location),
        alt_svc=_field_evidence(fields, b"alt-svc", _alt_svc),
    )
    if len(json.dumps(evidence, ensure_ascii=True).encode()) > BOUNDS["evidence_bytes"]:
        problem = _status("truncated", "evidence_bytes_limit")
        return dict(source=source, onion_location=problem, alt_svc=problem)
    return evidence
