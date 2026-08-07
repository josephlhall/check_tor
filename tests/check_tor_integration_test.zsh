#!/usr/bin/env zsh

# Offline integration tests for the executable scanner. The fake curl below
# is the only curl visible to the scanner, so these checks cannot reach the
# network even if a test scenario is incomplete.

setopt ERR_EXIT NO_UNSET PIPE_FAIL

REPO_ROOT=${0:A:h:h}
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT INT TERM

tests=0
failures=0

pass() {
    (( tests++ )) || true
}

fail() {
    (( tests++ )) || true
    (( failures++ )) || true
    print -u2 -- "FAIL: $1"
}

assert_contains() {
    local name=$1 expected=$2 actual=$3
    if [[ "$actual" == *"$expected"* ]]; then
        pass
    else
        fail "$name: expected output to contain '$expected'"
    fi
}

assert_eq() {
    local name=$1 expected=$2 actual=$3
    if [[ "$actual" == "$expected" ]]; then
        pass
    else
        fail "$name: expected '$expected', got '$actual'"
    fi
}

FAKE_BIN="$TEST_TMP/bin"
mkdir "$FAKE_BIN"

cat > "$FAKE_BIN/curl" <<'FAKE_CURL'
#!/usr/bin/env zsh

setopt ERR_EXIT NO_UNSET

body_file=""
header_file=""
proxy_user=""
url=""

for (( i = 1; i <= $#; i++ )); do
    case ${argv[$i]} in
        -o)                (( i++ )); body_file=${argv[$i]} ;;
        -D)                (( i++ )); header_file=${argv[$i]} ;;
        --proxy-user)      (( i++ )); proxy_user=${argv[$i]} ;;
        http://*|https://*) url=${argv[$i]} ;;
    esac
done

print -r -- "$*" >> "$CHECK_TOR_FAKE_LOG"

if [[ "$url" == "https://check.torproject.org/api/ip" ]]; then
    print -r -- '{"IsTor":true,"IP":"192.0.2.10"}'
    exit 0
fi

probe_number=0
[[ -f "$CHECK_TOR_FAKE_STATE" ]] && read -r probe_number < "$CHECK_TOR_FAKE_STATE"
(( probe_number++ )) || true
print -r -- "$probe_number" > "$CHECK_TOR_FAKE_STATE"

code=200
case $CHECK_TOR_FAKE_SCENARIO in
    all_pass)
        code=200
        ;;
    retry_then_pass)
        (( probe_number == 1 )) && code=403
        ;;
    persistent_tor_block)
        [[ -n "$proxy_user" ]] && code=403
        ;;
    *)
        print -u2 -- "Unknown fake curl scenario: $CHECK_TOR_FAKE_SCENARIO"
        exit 2
        ;;
esac

print -r -- "HTTP/2 $code" > "$header_file"
if (( code == 403 )); then
    print -r -- "error code: 1020" > "$body_file"
else
    : > "$body_file"
fi

printf '%s\t0\t0.1\t%s\t\n' "$code" "$url"
FAKE_CURL
chmod +x "$FAKE_BIN/curl"

# Keep the scanner's temporary response files separate from harness state so
# an empty directory proves its EXIT trap removed every file it created.
run_scanner() {
    local scenario=$1 input=$2 case_dir=$3
    mkdir -p "$case_dir/scanner-tmp"
    : > "$case_dir/curl.log"
    CHECK_TOR_FAKE_SCENARIO=$scenario \
    CHECK_TOR_FAKE_STATE="$case_dir/curl.state" \
    CHECK_TOR_FAKE_LOG="$case_dir/curl.log" \
    TMPDIR="$case_dir/scanner-tmp" \
    PATH="$FAKE_BIN:/usr/bin:/bin" \
        "$REPO_ROOT/check_tor.zsh" "$input" 2>&1
}

plain_output() {
    sed $'s/\033\\[[0-9;]*m//g'
}

# Missing and invalid inputs fail before curl (real or fake) can run.
set +e
missing_output=$(PATH="$FAKE_BIN:/usr/bin:/bin" "$REPO_ROOT/check_tor.zsh" 2>&1)
missing_status=$?
invalid_output=$(PATH="$FAKE_BIN:/usr/bin:/bin" "$REPO_ROOT/check_tor.zsh" "$TEST_TMP/absent.txt" 2>&1)
invalid_status=$?
set -e
assert_eq "missing argument status" 1 "$missing_status"
assert_contains "missing argument usage" "Usage:" "$missing_output"
assert_eq "missing file status" 1 "$invalid_status"
assert_contains "missing file diagnostic" "not found" "$invalid_output"

# Parsing and normalization: blank/comment lines disappear, http is upgraded,
# and a bare hostname receives an https scheme.
parse_case="$TEST_TMP/parse"
mkdir "$parse_case"
print -r -- $'\n  # synthetic targets only\nhttp://alpha.example.test\n  beta.example.test  \n' > "$parse_case/targets.txt"
parse_output=$(run_scanner all_pass "$parse_case/targets.txt" "$parse_case" | plain_output)
assert_contains "http upgraded" "https://alpha.example.test" "$parse_output"
assert_contains "scheme added" "https://beta.example.test" "$parse_output"
assert_contains "parse summary total" "Scanned 2 domain(s):" "$parse_output"
assert_contains "parse summary passes" "2 PASS" "$parse_output"
assert_eq "parse probe count" 2 "$(< "$parse_case/curl.state")"
assert_eq "parse temporary cleanup" 0 "$(find "$parse_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

# A block on one circuit followed by success must not become a site-wide block
# and must not trigger a clearnet control request.
retry_case="$TEST_TMP/retry"
mkdir "$retry_case"
print -r -- "retry.example.test" > "$retry_case/targets.txt"
retry_output=$(run_scanner retry_then_pass "$retry_case/targets.txt" "$retry_case" | plain_output)
assert_contains "retry final verdict" "[PASS]" "$retry_output"
assert_contains "retry explanation" "blocked on 1 of 3 circuits" "$retry_output"
assert_eq "retry probe count" 2 "$(< "$retry_case/curl.state")"
assert_eq "retry used isolated credentials" 2 "$(grep -c -- '--proxy-user' "$retry_case/curl.log")"

# A persistent Tor block is retried three times, compared with clearnet, and
# represented in both the per-target output and final summary.
block_case="$TEST_TMP/block"
mkdir "$block_case"
print -r -- "blocked.example.test" > "$block_case/targets.txt"
block_output=$(run_scanner persistent_tor_block "$block_case/targets.txt" "$block_case" | plain_output)
assert_contains "persistent verdict" "[FAIL]" "$block_output"
assert_contains "persistent circuit detail" "on 3 different circuits" "$block_output"
assert_contains "clearnet comparison" "clearnet OK → Tor-specific" "$block_output"
assert_contains "blocked summary count" "1 FAIL" "$block_output"
assert_contains "blocked target list" "blocked.example.test (FAIL)" "$block_output"
assert_eq "persistent probe count" 4 "$(< "$block_case/curl.state")"
assert_eq "three Tor probes" 3 "$(grep -c -- '--proxy-user' "$block_case/curl.log")"

if (( failures > 0 )); then
    print -u2 -- "$failures of $tests checks failed"
    exit 1
fi

print -- "All $tests offline integration checks passed."
