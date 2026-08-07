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

assert_not_contains() {
    local name=$1 unexpected=$2 actual=$3
    if [[ "$actual" != *"$unexpected"* ]]; then
        pass
    else
        fail "$name: expected output not to contain '$unexpected'"
    fi
}

FAKE_BIN="$TEST_TMP/bin"
mkdir "$FAKE_BIN"
zsh_executable=${commands[zsh]}

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
    if [[ "$CHECK_TOR_FAKE_SCENARIO" == preflight_fail ]]; then
        print -r -- '{"IsTor":false}'
    else
        print -r -- '{"IsTor":true,"IP":"192.0.2.10"}'
    fi
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
    inconclusive_control)
        [[ -n "$proxy_user" ]] && code=403 || code=503
        ;;
    oversized_body)
        code=403
        ;;
    *)
        print -u2 -- "Unknown fake curl scenario: $CHECK_TOR_FAKE_SCENARIO"
        exit 2
        ;;
esac

print -r -- "HTTP/2 $code" > "$header_file"
if [[ "$CHECK_TOR_FAKE_SCENARIO" == oversized_body ]]; then
    # Write well beyond the scanner's cap. Its byte-counting output sink must
    # stop this synthetic chunked/unknown-size response at the finite limit.
    printf '%*s' 2097152 '' > "$body_file"
    printf '%s\t0\t0.1\t%s\t\n' "$code" "$url"
elif (( code == 403 )); then
    print -r -- "error code: 1020" > "$body_file"
else
    : > "$body_file"
fi

printf '%s\t0\t0.1\t%s\t\n' "$code" "$url"
FAKE_CURL
chmod +x "$FAKE_BIN/curl"

# Sourcing from an unrelated working directory must load definitions without
# treating caller arguments as scanner arguments or installing side effects.
source_case="$TEST_TMP/source"
mkdir "$source_case" "$source_case/scanner-tmp"
: > "$source_case/curl.log"
print -r -- $'\n# source fixture\nalpha.example.test\r\n beta.example.test \n' > "$source_case/targets.txt"
set +e
CHECK_TOR_FAKE_SCENARIO=all_pass \
CHECK_TOR_FAKE_STATE="$source_case/curl.state" \
CHECK_TOR_FAKE_LOG="$source_case/curl.log" \
CHECK_TOR_SOURCE_TRAP="$source_case/caller-trap" \
CHECK_TOR_SOURCE_INPUT="$source_case/targets.txt" \
CHECK_TOR_SOURCE_RESULT="$source_case/function-result" \
TMPDIR="$source_case/scanner-tmp" \
PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$zsh_executable" -c '
        script_path=$1 source_workdir=$2
        cd "$source_workdir"
        set -- caller-argument second-argument
        trap '\''print -r -- "$#:$1:$2" > "$CHECK_TOR_SOURCE_TRAP"'\'' EXIT
        source "$script_path"
        [[ $# == 2 && $1 == caller-argument && $2 == second-argument ]] || exit 10
        (( $+functions[configure_output] && $+functions[usage] &&
           $+functions[parse_args] && $+functions[load_targets] &&
           $+functions[check_dependencies] && $+functions[warn_tracked_input] &&
           $+functions[json_quote] && $+functions[print_json_target] &&
           $+functions[print_json_summary] && $+functions[probe] && $+functions[tor_preflight] &&
           $+functions[scan_target] && $+functions[print_summary] &&
           $+functions[run_scan] && $+functions[main] )) || exit 11
        parse_args --format jsonl "$CHECK_TOR_SOURCE_INPUT" || exit 12
        parsed_input=$REPLY
        parsed_format=${reply[2]}
        json_quote $'"'"'quote" slash\\ tab\t line\n'"'"'
        quoted_value=$REPLY
        load_targets "$parsed_input" || exit 13
        check_dependencies || exit 14
        print -r -- "$parsed_input:$parsed_format:$quoted_value:${(j:,:)reply}" > "$CHECK_TOR_SOURCE_RESULT"
    ' zsh "$REPO_ROOT/check_tor.zsh" "$source_case" \
    > "$source_case/stdout" 2> "$source_case/stderr"
source_status=$?
set -e
assert_eq "source status" 0 "$source_status"
assert_eq "source stdout" "" "$(< "$source_case/stdout")"
assert_eq "source stderr" "" "$(< "$source_case/stderr")"
assert_eq "source preserves caller arguments and trap" \
    "2:caller-argument:second-argument" "$(< "$source_case/caller-trap")"
assert_eq "source callable boundaries" \
    "$source_case/targets.txt:jsonl:\"quote\\\" slash\\\\ tab\\u0009 line\\u000a\":alpha.example.test,beta.example.test" \
    "$(< "$source_case/function-result")"
assert_eq "source curl calls" "" "$(< "$source_case/curl.log")"
assert_eq "source temporary files" 0 "$(find "$source_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

# Calling main after sourcing owns its temporary files and restores the
# caller's EXIT trap when it returns.
sourced_main_case="$TEST_TMP/sourced-main"
mkdir "$sourced_main_case" "$sourced_main_case/scanner-tmp"
print -r -- "sourced-main.example.test" > "$sourced_main_case/targets.txt"
: > "$sourced_main_case/curl.log"
set +e
CHECK_TOR_FAKE_SCENARIO=all_pass \
CHECK_TOR_FAKE_STATE="$sourced_main_case/curl.state" \
CHECK_TOR_FAKE_LOG="$sourced_main_case/curl.log" \
CHECK_TOR_SOURCE_TRAP="$sourced_main_case/caller-trap" \
TMPDIR="$sourced_main_case/scanner-tmp" \
PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$zsh_executable" -c '
        source "$1"
        trap '\''print -r -- preserved > "$CHECK_TOR_SOURCE_TRAP"'\'' EXIT
        main "$2"
    ' zsh "$REPO_ROOT/check_tor.zsh" "$sourced_main_case/targets.txt" \
    > "$sourced_main_case/stdout" 2> "$sourced_main_case/stderr"
sourced_main_status=$?
set -e
assert_eq "sourced main status" 0 "$sourced_main_status"
assert_eq "sourced main stderr" "" "$(< "$sourced_main_case/stderr")"
assert_eq "sourced main preserves caller trap" "preserved" "$(< "$sourced_main_case/caller-trap")"
assert_eq "sourced main temporary cleanup" 0 "$(find "$sourced_main_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

# Capture streams separately because their separation is part of the command's
# public contract. Keep scanner temporary files apart from harness state so an
# empty directory proves its EXIT trap removed every file it created.
run_scanner() {
    local scenario=$1 input=$2 case_dir=$3 output_format=${4:-default}
    local -a scanner_args=("$input")
    [[ "$output_format" != default ]] && scanner_args=(--format "$output_format" "$input")
    mkdir -p "$case_dir/scanner-tmp"
    : > "$case_dir/curl.log"
    set +e
    CHECK_TOR_FAKE_SCENARIO=$scenario \
    CHECK_TOR_FAKE_STATE="$case_dir/curl.state" \
    CHECK_TOR_FAKE_LOG="$case_dir/curl.log" \
    TMPDIR="$case_dir/scanner-tmp" \
    PATH="$FAKE_BIN:/usr/bin:/bin" \
        "$REPO_ROOT/check_tor.zsh" "${scanner_args[@]}" \
        > "$case_dir/stdout" 2> "$case_dir/stderr"
    scanner_status=$?
    set -e
    scanner_stdout=$(< "$case_dir/stdout")
    scanner_stderr=$(< "$case_dir/stderr")
}

# Help and invalid invocation fail or return before curl (real or fake) can run.
cli_case="$TEST_TMP/cli"
mkdir "$cli_case"
: > "$cli_case/curl.log"
set +e
CHECK_TOR_FAKE_LOG="$cli_case/curl.log" PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$REPO_ROOT/check_tor.zsh" --help > "$cli_case/help.out" 2> "$cli_case/help.err"
help_status=$?
CHECK_TOR_FAKE_LOG="$cli_case/curl.log" PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$REPO_ROOT/check_tor.zsh" > "$cli_case/missing.out" 2> "$cli_case/missing.err"
missing_status=$?
CHECK_TOR_FAKE_LOG="$cli_case/curl.log" PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$REPO_ROOT/check_tor.zsh" one.txt two.txt > "$cli_case/extra.out" 2> "$cli_case/extra.err"
extra_status=$?
CHECK_TOR_FAKE_LOG="$cli_case/curl.log" PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$REPO_ROOT/check_tor.zsh" "$TEST_TMP/absent.txt" > "$cli_case/invalid.out" 2> "$cli_case/invalid.err"
invalid_status=$?
CHECK_TOR_FAKE_LOG="$cli_case/curl.log" PATH="$FAKE_BIN:/usr/bin:/bin" \
    "$REPO_ROOT/check_tor.zsh" --format xml "$TEST_TMP/absent.txt" > "$cli_case/format.out" 2> "$cli_case/format.err"
format_status=$?
set -e
assert_eq "help status" 0 "$help_status"
assert_contains "help usage" "Usage:" "$(< "$cli_case/help.out")"
assert_contains "help documents NO_COLOR" "NO_COLOR" "$(< "$cli_case/help.out")"
assert_contains "help documents JSONL format" "--format text|jsonl" "$(< "$cli_case/help.out")"
assert_eq "help stderr" "" "$(< "$cli_case/help.err")"
assert_eq "missing argument status" 1 "$missing_status"
assert_eq "missing argument stdout" "" "$(< "$cli_case/missing.out")"
assert_contains "missing argument usage" "Usage:" "$(< "$cli_case/missing.err")"
assert_eq "extra argument status" 1 "$extra_status"
assert_contains "extra argument diagnostic" "exactly one target file" "$(< "$cli_case/extra.err")"
assert_eq "missing file status" 1 "$invalid_status"
assert_eq "missing file stdout" "" "$(< "$cli_case/invalid.out")"
assert_contains "missing file diagnostic" "not found" "$(< "$cli_case/invalid.err")"
assert_eq "invalid format status" 1 "$format_status"
assert_eq "invalid format stdout" "" "$(< "$cli_case/format.out")"
assert_contains "invalid format diagnostic" "unsupported format 'xml'" "$(< "$cli_case/format.err")"
assert_eq "invalid invocation curl calls" "" "$(< "$cli_case/curl.log")"

# Empty and comment-only files are rejected before dependency or Tor checks.
empty_case="$TEST_TMP/empty"
mkdir "$empty_case"
print -r -- $'\n  # no targets\n  \n' > "$empty_case/targets.txt"
run_scanner all_pass "$empty_case/targets.txt" "$empty_case"
assert_eq "empty input status" 1 "$scanner_status"
assert_eq "empty input stdout" "" "$scanner_stdout"
assert_contains "empty input diagnostic" "contains no targets" "$scanner_stderr"
assert_eq "empty input curl calls" "" "$(< "$empty_case/curl.log")"

# A missing runtime command is diagnosed before temporary files or Tor access.
dependency_case="$TEST_TMP/dependency"
mkdir "$dependency_case" "$dependency_case/bin"
ln -s "$FAKE_BIN/curl" "$dependency_case/bin/curl"
print -r -- "dependency.example.test" > "$dependency_case/targets.txt"
: > "$dependency_case/curl.log"
set +e
CHECK_TOR_FAKE_LOG="$dependency_case/curl.log" PATH="$dependency_case/bin" \
    "$zsh_executable" "$REPO_ROOT/check_tor.zsh" "$dependency_case/targets.txt" \
    > "$dependency_case/stdout" 2> "$dependency_case/stderr"
dependency_status=$?
set -e
assert_eq "missing dependency status" 1 "$dependency_status"
assert_eq "missing dependency stdout" "" "$(< "$dependency_case/stdout")"
assert_contains "missing dependency diagnostic" "missing required command(s)" "$(< "$dependency_case/stderr")"
assert_contains "missing awk diagnostic" "awk" "$(< "$dependency_case/stderr")"
assert_eq "missing dependency curl calls" "" "$(< "$dependency_case/curl.log")"

# Parsing and normalization: blank/comment lines disappear, http is upgraded,
# and a bare hostname receives an https scheme.
parse_case="$TEST_TMP/parse"
mkdir "$parse_case"
print -r -- $'\n  # synthetic targets only\nhttp://alpha.example.test\n  beta.example.test  \n' > "$parse_case/targets.txt"
run_scanner all_pass "$parse_case/targets.txt" "$parse_case"
assert_eq "successful scan status" 0 "$scanner_status"
assert_eq "successful scan stderr" "" "$scanner_stderr"
assert_contains "http upgraded" "https://alpha.example.test" "$scanner_stdout"
assert_contains "scheme added" "https://beta.example.test" "$scanner_stdout"
assert_contains "parse summary total" "Scanned 2 domain(s):" "$scanner_stdout"
assert_contains "parse summary passes" "2 PASS" "$scanner_stdout"
assert_not_contains "redirected output has no ANSI" $'\033[' "$scanner_stdout"
assert_eq "parse probe count" 2 "$(< "$parse_case/curl.state")"
assert_eq "parse temporary cleanup" 0 "$(find "$parse_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

explicit_text_case="$TEST_TMP/explicit-text"
mkdir "$explicit_text_case"
print -r -- "explicit-text.example.test" > "$explicit_text_case/targets.txt"
run_scanner all_pass "$explicit_text_case/targets.txt" "$explicit_text_case" text
assert_eq "explicit text status" 0 "$scanner_status"
assert_contains "explicit text verdict" "[PASS]" "$scanner_stdout"
assert_contains "explicit text summary" "Scanned 1 domain(s):" "$scanner_stdout"
assert_not_contains "explicit text is not JSONL" '"schema_version"' "$scanner_stdout"

# JSONL mode emits exactly one versioned object per target and one final
# summary object, with no banner, progress, ANSI styling, or text summary.
json_case="$TEST_TMP/json"
mkdir "$json_case"
print -r -- "json.example.test" > "$json_case/targets.txt"
run_scanner all_pass "$json_case/targets.txt" "$json_case" jsonl
json_target='{"schema_version":1,"type":"target","target":"https://json.example.test","verdict":"PASS","detail":"HTTP 200","tor_attempts":1,"tor_attempt_limit":3,"clearnet_control":{"performed":false,"verdict":null},"tor_specific":null,"body_limited":false}'
json_summary='{"schema_version":1,"type":"summary","complete":true,"total":1,"counts":{"PASS":1,"CHALLENGE":0,"RATELIMIT":0,"FAIL":0,"DROP":0,"TIMEOUT":0,"CERT":0,"SOCKS":0,"WARN":0},"tor_specific_findings":0}'
assert_eq "JSONL scan status" 0 "$scanner_status"
assert_eq "JSONL stderr" "" "$scanner_stderr"
assert_eq "JSONL target and summary" "$json_target"$'\n'"$json_summary" "$scanner_stdout"
assert_not_contains "JSONL has no banner" "check_tor ·" "$scanner_stdout"
assert_not_contains "JSONL has no ANSI" $'\033[' "$scanner_stdout"
assert_eq "JSONL temporary cleanup" 0 \
    "$(find "$json_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

# A block on one circuit followed by success must not become a site-wide block
# and must not trigger a clearnet control request.
retry_case="$TEST_TMP/retry"
mkdir "$retry_case"
print -r -- "retry.example.test" > "$retry_case/targets.txt"
run_scanner retry_then_pass "$retry_case/targets.txt" "$retry_case"
assert_contains "retry final verdict" "[PASS]" "$scanner_stdout"
assert_contains "retry explanation" "blocked on 1 of 3 circuits" "$scanner_stdout"
assert_eq "retry probe count" 2 "$(< "$retry_case/curl.state")"
assert_eq "retry used isolated credentials" 2 "$(grep -c -- '--proxy-user' "$retry_case/curl.log")"

# A persistent Tor block is retried three times, compared with clearnet, and
# represented in both the per-target output and final summary.
block_case="$TEST_TMP/block"
mkdir "$block_case"
print -r -- "blocked.example.test" > "$block_case/targets.txt"
run_scanner persistent_tor_block "$block_case/targets.txt" "$block_case"
assert_contains "persistent verdict" "[FAIL]" "$scanner_stdout"
assert_contains "persistent circuit detail" "on 3 different circuits" "$scanner_stdout"
assert_contains "clearnet comparison" "clearnet OK → Tor-specific" "$scanner_stdout"
assert_contains "blocked summary count" "1 FAIL" "$scanner_stdout"
assert_contains "blocked target list" "blocked.example.test (FAIL)" "$scanner_stdout"
assert_eq "persistent probe count" 4 "$(< "$block_case/curl.state")"
assert_eq "three Tor probes" 3 "$(grep -c -- '--proxy-user' "$block_case/curl.log")"

# Structured block results expose retry and clearnet-control semantics without
# requiring consumers to interpret the human detail string.
json_block_case="$TEST_TMP/json-block"
mkdir "$json_block_case"
print -r -- "json-blocked.example.test" > "$json_block_case/targets.txt"
run_scanner persistent_tor_block "$json_block_case/targets.txt" "$json_block_case" jsonl
assert_contains "JSONL retry count" '"tor_attempts":3' "$scanner_stdout"
assert_contains "JSONL control verdict" \
    '"clearnet_control":{"performed":true,"verdict":"PASS"}' "$scanner_stdout"
assert_contains "JSONL Tor-specific result" '"tor_specific":true' "$scanner_stdout"
assert_contains "JSONL Tor-specific summary" '"tor_specific_findings":1' "$scanner_stdout"

json_inconclusive_case="$TEST_TMP/json-inconclusive"
mkdir "$json_inconclusive_case"
print -r -- "json-inconclusive.example.test" > "$json_inconclusive_case/targets.txt"
run_scanner inconclusive_control "$json_inconclusive_case/targets.txt" "$json_inconclusive_case" jsonl
assert_contains "JSONL inconclusive control verdict" \
    '"clearnet_control":{"performed":true,"verdict":"WARN"}' "$scanner_stdout"
assert_contains "JSONL inconclusive Tor specificity" '"tor_specific":null' "$scanner_stdout"
assert_contains "JSONL inconclusive summary count" '"tor_specific_findings":0' "$scanner_stdout"
assert_eq "JSONL inconclusive probe count" 4 "$(< "$json_inconclusive_case/curl.state")"

# Crossing the response-body cap is an intentional, inconclusive cutoff. It
# must not be retried, compared with clearnet, or reported as a Tor block.
oversized_case="$TEST_TMP/oversized"
mkdir "$oversized_case"
print -r -- "oversized.example.test" > "$oversized_case/targets.txt"
run_scanner oversized_body "$oversized_case/targets.txt" "$oversized_case"
assert_eq "oversized response status" 0 "$scanner_status"
assert_contains "oversized response verdict" "[WARNING]" "$scanner_stdout"
assert_contains "oversized response detail" "1 MiB inspection limit" "$scanner_stdout"
assert_eq "oversized response probe count" 1 "$(< "$oversized_case/curl.state")"
assert_not_contains "oversized response blocked list" \
    "Likely blocking or challenging Tor" "$scanner_stdout"
assert_eq "oversized response temporary cleanup" 0 \
    "$(find "$oversized_case/scanner-tmp" -type f | wc -l | tr -d ' ')"

json_oversized_case="$TEST_TMP/json-oversized"
mkdir "$json_oversized_case"
print -r -- "json-oversized.example.test" > "$json_oversized_case/targets.txt"
run_scanner oversized_body "$json_oversized_case/targets.txt" "$json_oversized_case" jsonl
assert_contains "JSONL body cutoff verdict" '"verdict":"WARN"' "$scanner_stdout"
assert_contains "JSONL explicit body cutoff" '"body_limited":true' "$scanner_stdout"
assert_contains "JSONL cutoff has no control" \
    '"clearnet_control":{"performed":false,"verdict":null}' "$scanner_stdout"
assert_contains "JSONL cutoff is not Tor-specific" '"tor_specific":null' "$scanner_stdout"

# Preflight failures preserve normal progress on stdout and diagnose the fatal
# condition on stderr.
preflight_case="$TEST_TMP/preflight"
mkdir "$preflight_case"
print -r -- "preflight.example.test" > "$preflight_case/targets.txt"
run_scanner preflight_fail "$preflight_case/targets.txt" "$preflight_case"
assert_eq "preflight failure status" 1 "$scanner_status"
assert_contains "preflight progress stdout" "Performing pre-flight check" "$scanner_stdout"
assert_contains "preflight diagnostic stderr" "Tor connection failed" "$scanner_stderr"

json_preflight_case="$TEST_TMP/json-preflight"
mkdir "$json_preflight_case"
print -r -- "json-preflight.example.test" > "$json_preflight_case/targets.txt"
run_scanner preflight_fail "$json_preflight_case/targets.txt" "$json_preflight_case" jsonl
assert_eq "JSONL preflight failure status" 1 "$scanner_status"
assert_eq "JSONL incomplete scan stdout" "" "$scanner_stdout"
assert_contains "JSONL preflight diagnostic stderr" "Tor connection failed" "$scanner_stderr"

if (( failures > 0 )); then
    print -u2 -- "$failures of $tests checks failed"
    exit 1
fi

print -- "All $tests offline integration checks passed."
