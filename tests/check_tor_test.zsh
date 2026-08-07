#!/usr/bin/env zsh

# Offline regression tests for check_tor_core.zsh. All response data is
# synthetic, and this suite never starts Tor or makes network requests.

source "${0:A:h:h}/check_tor_core.zsh"

tests=0
failures=0
TEST_TMP=$(mktemp -d)
BODY="$TEST_TMP/body"
LASTH="$TEST_TMP/headers"
trap 'rm -rf "$TEST_TMP"' EXIT INT TERM

pass() {
    (( tests++ ))
    return 0
}

fail() {
    (( tests++ ))
    (( failures++ ))
    print -u2 -- "FAIL: $1"
    return 1
}

assert_eq() {
    local name=$1 expected=$2 actual=$3
    if [[ "$actual" == "$expected" ]]; then
        pass
    else
        fail "$name: expected '$expected', got '$actual'"
    fi
}

assert_contains() {
    local name=$1 expected=$2 actual=$3
    if [[ "$actual" == *"$expected"* ]]; then
        pass
    else
        fail "$name: expected '$actual' to contain '$expected'"
    fi
}

reset_probe() {
    probe_exit=0
    probe_code=200
    probe_redirs=0
    probe_tls=0
    probe_timeout=30
    probe_body_limited=0
    probe_final="https://example.test/"
    probe_err=""
    : > "$BODY"
    : > "$LASTH"
}

assert_classify() {
    local name=$1 exit_code=$2 http_code=$3 expected=$4
    reset_probe
    probe_exit=$exit_code
    probe_code=$http_code
    classify
    assert_eq "$name" "$expected" "$verdict"
}

assert_blocker() {
    local name=$1 expected=$2 body=$3 headers=$4
    reset_probe
    print -r -- "$body" > "$BODY"
    print -r -- "$headers" > "$LASTH"
    blocker_id
    assert_eq "$name" "$expected" "$blocker"
}

# curl exit-code classification
assert_classify "SOCKS proxy resolution" 5 000 SOCKS
assert_classify "SOCKS handshake" 97 000 SOCKS
assert_classify "certificate verification 60" 60 000 CERT
assert_classify "certificate verification 51" 51 000 CERT
assert_classify "TLS handshake" 35 000 CERT
assert_classify "receive failure" 56 000 DROP
assert_classify "empty reply" 52 000 DROP
assert_classify "truncated transfer" 18 000 DROP
assert_classify "timeout" 28 000 TIMEOUT
assert_classify "connect failure" 7 000 TIMEOUT
assert_classify "redirect loop" 47 000 WARN
assert_classify "unexpected curl failure" 42 000 WARN

reset_probe
probe_exit=23 probe_code=403 probe_body_limited=1
classify
assert_contains "body cutoff detail" "1 MiB inspection limit" "$detail"
blocky "$verdict"
assert_eq "body cutoff is not blocky" 1 "$?"

reset_probe
probe_exit=28 probe_timeout=12 probe_tls=0
classify
assert_contains "pre-TLS timeout detail" "no response in 12s" "$detail"

reset_probe
probe_exit=28 probe_timeout=12 probe_tls=0.25
classify
assert_contains "post-TLS timeout detail" "TLS completed, then stalled for 12s" "$detail"

reset_probe
probe_exit=97 probe_err="connection refused"
classify
assert_contains "SOCKS error detail" "connection refused" "$detail"

# HTTP classification
assert_classify "HTTP 200" 0 200 PASS
assert_classify "HTTP 401" 0 401 FAIL
assert_classify "HTTP 403" 0 403 FAIL
assert_classify "HTTP 202" 0 202 CHALLENGE
assert_classify "HTTP 429" 0 429 RATELIMIT
assert_classify "HTTP 503 without WAF" 0 503 WARN
assert_classify "unfollowed redirect" 0 302 WARN
assert_classify "unexpected HTTP status" 0 418 WARN

reset_probe
probe_redirs=2
classify
assert_contains "redirect count detail" "after 2 redirect(s)" "$detail"

reset_probe
probe_final="https://example.test/cdn-cgi/challenge-platform/"
classify
assert_eq "challenge URL disguised as 200" CHALLENGE "$verdict"

reset_probe
probe_code=403
print -r -- "cf-mitigated: challenge" > "$LASTH"
classify
assert_eq "managed challenge response" CHALLENGE "$verdict"

reset_probe
probe_code=503
print -r -- "Server: AkamaiGHost" > "$LASTH"
classify
assert_eq "WAF-backed 503" CHALLENGE "$verdict"

# WAF and blocker fingerprints
assert_blocker "Cloudflare managed challenge" \
    "Cloudflare challenge (cf-mitigated)" "" "cf-mitigated: challenge"
assert_blocker "Cloudflare 1020" \
    "Cloudflare 1020: blocked by a firewall rule" "error code: 1020" ""
assert_blocker "Cloudflare 1015" \
    "Cloudflare 1015: rate limited" "error code: 1015" ""
assert_blocker "Cloudflare IP ban" \
    "Cloudflare 1006: IP banned" "error code: 1006" ""
assert_blocker "Cloudflare unknown error" \
    "Cloudflare error 1099" "error code: 1099" ""
assert_blocker "Cloudflare challenge page" \
    "Cloudflare challenge page" "Just a moment" ""
assert_blocker "Cloudflare error header" \
    "Cloudflare error (firewall)" "" "cf-error-type: firewall"
assert_blocker "Cloudflare edge" \
    "served by Cloudflare" "" "cf-ray: abc123"
assert_blocker "Akamai edge" \
    "Akamai edge" "" "Server: AkamaiGHost"
assert_blocker "Sucuri WAF" \
    "Sucuri WAF" "" "x-sucuri-id: 123"
assert_blocker "Imperva header" \
    "Imperva/Incapsula WAF" "" "x-iinfo: 1-2-3"
assert_blocker "Imperva cookie" \
    "Imperva/Incapsula WAF" "" "Set-Cookie: incap_ses=abc"

# Severity and retry policy
for verdict_key expected_severity in \
    PASS 0 CHALLENGE 1 RATELIMIT 1 FAIL 2 DROP 2 TIMEOUT 2 SOCKS 2 CERT -1 WARN -1; do
    severity "$verdict_key"
    assert_eq "severity $verdict_key" "$expected_severity" "$sev"
done

for verdict_key in FAIL CHALLENGE RATELIMIT DROP TIMEOUT SOCKS; do
    blocky "$verdict_key"
    assert_eq "blocky $verdict_key" 0 "$?"
done

blocky PASS
assert_eq "PASS is not blocky" 1 "$?"

# Tor-versus-clearnet comparison
compare_treatment FAIL "HTTP 403" PASS
assert_eq "Tor-specific flag" 1 "$tor_specific"
assert_contains "Tor-specific detail" "clearnet OK → Tor-specific" "$tor_detail"

compare_treatment FAIL "HTTP 403" CHALLENGE
assert_eq "escalated-for-Tor flag" 1 "$tor_specific"
assert_contains "escalated-for-Tor detail" "escalated for Tor" "$tor_detail"

compare_treatment FAIL "HTTP 403" FAIL
assert_eq "equal treatment flag" 0 "$tor_specific"
assert_contains "equal treatment detail" "likely not Tor-specific" "$tor_detail"

compare_treatment CHALLENGE "HTTP 403" FAIL
assert_eq "clearnet worse flag" 0 "$tor_specific"

compare_treatment FAIL "HTTP 403" CERT
assert_eq "inconclusive control flag" 1 "$tor_specific"
assert_contains "inconclusive control detail" "clearnet inconclusive (CERT)" "$tor_detail"

if (( failures > 0 )); then
    print -u2 -- "$failures of $tests checks failed"
    exit 1
fi

print -- "All $tests offline checks passed."
