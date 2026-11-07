#!/usr/bin/env zsh

# check_tor.zsh—test whether a list of domains is reachable over the Tor
# network, and diagnose the nature of any blockage (WAF rule, JS challenge,
# rate limit, silent drop, TLS breakage) before deciding a site "blocks Tor".
# https://github.com/josephlhall/check_tor
#
# The legacy scan loop is deliberately serial: probes replace shared result
# variables and response files. Detailed mode invokes these same definitions in
# isolated processes so its coordinator can safely overlap different targets.

# ----------------------------------------------------------------- config ---

# %N is the current file even when sourced; $0 would identify the caller's
# shell in that mode and resolve the core against the wrong directory.
CHECK_TOR_DIR=${${(%):-%N}:A:h}
source "$CHECK_TOR_DIR/check_tor_core.zsh"

# Host and port of the Tor SOCKS proxy.
TOR_PROXY="localhost:9050"

# A site is only declared blocked after failing on this many different Tor
# circuits. Fresh circuits come from varying the SOCKS credentials: Tor's
# default IsolateSOCKSAuth forbids streams with different credentials from
# sharing a circuit, so no ControlPort is needed. Note this guarantees a
# separate *circuit*, not a different exit relay—two circuits can
# independently pick the same exit, so a repeat failure is suggestive of a
# site-wide policy rather than proof of one.
MAX_CIRCUITS=3

# Per-request timeouts, in seconds.
TIMEOUT_FIRST=60      # first attempt over Tor
TIMEOUT_RETRY=30      # retries on fresh circuits
TIMEOUT_CLEARNET=20   # control request without Tor
# Disabling the control suppresses the Tor-specific inference, not the
# underlying verdict from the automated Tor probes.
CLEARNET_ENABLED=1

# Retain at most 1 MiB of each response body. WAF fingerprints are normally
# near the start of an error page; accepting this finite prefix prevents an
# untrusted or endless response from consuming disk until the time limit. A
# fingerprint beyond the prefix can be missed, so reaching the cap is reported
# as inconclusive rather than as evidence that the site blocks Tor.
MAX_BODY_BYTES=$(( 1024 * 1024 ))
MAX_REDIRECTS=10
PREFLIGHT_TIMEOUT=10

# Browser-like headers reduce trivial bot-fingerprint differences, but they do
# not make curl equivalent to Chrome: TLS and JavaScript behavior still differ.
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
ACCEPT_HDR="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
LANG_HDR="Accept-Language: en-US,en;q=0.5"

# ----------------------------------------------------------------- output ---

RULE="─────────────────────────────────────────────────────────"

# Configure styling when main runs rather than when this file is sourced. A
# caller may source definitions in a non-interactive context and invoke main
# later with stdout attached to a terminal.
configure_output() {
    if [[ -t 1 ]] && (( ! ${+NO_COLOR} )); then
        RED=$'\033[31m' GRN=$'\033[32m' YEL=$'\033[33m' MAG=$'\033[35m'
        CYN=$'\033[36m' DIM=$'\033[2m'  BLD=$'\033[1m'  OFF=$'\033[0m'
    else
        RED="" GRN="" YEL="" MAG="" CYN="" DIM="" BLD="" OFF=""
    fi
}

# Transient one-line progress messages (only when stdout is a terminal).
transient()       { [[ ${OUTPUT_FORMAT:-text} == text && -t 1 ]] && printf '\r\033[K%s%s%s' "$DIM" "$1" "$OFF" }
clear_transient() { [[ ${OUTPUT_FORMAT:-text} == text && -t 1 ]] && printf '\r\033[K' }

print_line() {  # $1=verdict key  $2=url  $3=detail
    local label color
    case $1 in
        PASS)      label="PASS"        color=$GRN ;;
        FAIL)      label="FAIL"        color=$RED ;;
        CHALLENGE) label="CHALLENGE"   color=$CYN ;;
        RATELIMIT) label="RATE LIMIT"  color=$YEL ;;
        DROP)      label="DROP"        color=$RED ;;
        TIMEOUT)   label="TIMEOUT"     color=$YEL ;;
        CERT)      label="CERT ERROR"  color=$MAG ;;
        SOCKS)     label="SOCKS ERROR" color=$RED ;;
        *)         label="WARNING"     color=$YEL ;;
    esac
    clear_transient
    printf '[%s%s%s]%*s %s %s— %s%s\n' \
        "$color" "$label" "$OFF" $(( 12 - ${#label} )) '' "$2" "$DIM" "$3" "$OFF"
}

# Quote one shell string as a JSON string without requiring jq or another
# runtime dependency. JSON permits Unicode directly, but every ASCII control
# character must be escaped even when it came from an unusual target name or
# a curl diagnostic.
json_quote() {
    local value=$1 escaped="" char code i
    for (( i = 1; i <= ${#value}; i++ )); do
        char=${value[$i]}
        case $char in
            '"') escaped+='\"' ;;
            '\') escaped+='\\' ;;
            *)
                printf -v code '%d' "'$char"
                if (( code < 32 )); then
                    printf -v char '\\u%04x' "$code"
                fi
                escaped+=$char
                ;;
        esac
    done
    REPLY="\"$escaped\""
}

print_json_target() {
    local target=$1 verdict_key=$2 result_detail=$3 attempts=$4
    local control_performed=$5 control_verdict=$6 tor_specific_json=$7 body_limited=$8
    local target_json verdict_json detail_json control_verdict_json
    local control_enabled_json=false control_performed_json=false body_limited_json=false

    json_quote "$target"; target_json=$REPLY
    json_quote "$verdict_key"; verdict_json=$REPLY
    json_quote "$result_detail"; detail_json=$REPLY
    if (( control_performed )); then
        json_quote "$control_verdict"; control_verdict_json=$REPLY
    else
        control_verdict_json=null
    fi
    (( CLEARNET_ENABLED )) && control_enabled_json=true
    (( control_performed )) && control_performed_json=true
    (( body_limited )) && body_limited_json=true

    printf '{"schema_version":1,"type":"target","target":%s,"verdict":%s,"detail":%s,"tor_attempts":%d,"tor_attempt_limit":%d,"clearnet_control":{"enabled":%s,"performed":%s,"verdict":%s},"tor_specific":%s,"body_limited":%s}\n' \
        "$target_json" "$verdict_json" "$detail_json" "$attempts" "$MAX_CIRCUITS" \
        "$control_enabled_json" "$control_performed_json" "$control_verdict_json" \
        "$tor_specific_json" "$body_limited_json"
}

print_json_summary() {
    local total=$1 tor_specific_findings=$2
    printf '{"schema_version":1,"type":"summary","complete":true,"total":%d,"counts":{"PASS":%d,"CHALLENGE":%d,"RATELIMIT":%d,"FAIL":%d,"DROP":%d,"TIMEOUT":%d,"CERT":%d,"SOCKS":%d,"WARN":%d},"tor_specific_findings":%d}\n' \
        "$total" "${counts[PASS]:-0}" "${counts[CHALLENGE]:-0}" \
        "${counts[RATELIMIT]:-0}" "${counts[FAIL]:-0}" "${counts[DROP]:-0}" \
        "${counts[TIMEOUT]:-0}" "${counts[CERT]:-0}" "${counts[SOCKS]:-0}" \
        "${counts[WARN]:-0}" "$tor_specific_findings"
}

usage() {
    print -r -- "Usage: ./check_tor.zsh [options] <file_with_urls.txt>"
    print -r -- "       ./check_tor.zsh --help"
    print -r -- ""
    print -r -- "Scan each nonblank, non-comment target through a local Tor proxy."
    print -r -- "Targets without a scheme, and http:// targets, are tested as https://."
    print -r -- ""
    print -r -- "Options:"
    print -r -- "  --format text|jsonl       Select human text (default) or JSON Lines output."
    print -r -- "  --format jsonl-v2         Detailed requests and run records (requires Python 3.9+)."
    print -r -- "  --proxy HOST:PORT         Tor SOCKS proxy (default: localhost:9050)."
    print -r -- "  --circuits COUNT          Maximum Tor attempts, 1–100 (default: 3)."
    print -r -- "  --timeout-first SECONDS   First Tor attempt, 1–3600 (default: 60)."
    print -r -- "  --timeout-retry SECONDS   Later Tor attempts, 1–3600 (default: 30)."
    print -r -- "  --timeout-clearnet SECONDS  Clearnet control, 1–3600 (default: 20)."
    print -r -- "  --no-clearnet             Skip the clearnet control comparison."
    print -r -- "  -h, --help                Show this help and exit."
    print -r -- ""
    print -r -- "Detailed-mode options (require --format jsonl-v2):"
    print -r -- "  --run-id TEXT, --group-id TEXT  Opaque labels for downstream consumers."
    print -r -- "  --trials COUNT            Fixed Tor trials, 1–100; replaces failure retries."
    print -r -- "  --control conditional|always|never  Default: conditional."
    print -r -- "  --control-scope target|trial  Default: target; trial requires --trials."
    print -r -- "  --order tor-first|direct-first|counterbalanced  Default: tor-first."
    print -r -- "  --seed INTEGER            Required for counterbalanced order."
    print -r -- "  --max-partner-gap SECONDS Maximum paired start gap (default: 60)."
    print -r -- "  --reproducible            Explicit proxy routing; trial policies imply it."
    print -r -- "  --workers COUNT          Active target bundles, 1–32 (default: 1)."
    print -r -- "  --start-gap SECONDS       Global probe-start interval, 0–3600 (default: 0)."
    print -r -- ""
    print -r -- "Environment:"
    print -r -- "  NO_COLOR    Disable ANSI color styling."
    print -r -- ""
    print -r -- "Exit status:"
    print -r -- "  0  Scan completed, regardless of findings."
    print -r -- "  1  Invocation, input, dependency, or Tor preflight failure."
}

parse_bounded_integer() {
    local value=$1 option_name=$2 maximum=$3
    # Reject long digit strings before arithmetic expansion: shell integers
    # have platform-sized limits, while every public setting has a much
    # smaller bound. 10# then normalizes leading zeroes as decimal, never octal.
    if [[ "$value" != <-> ]] || (( ${#value} > 9 )); then
        print -u2 -r -- "Error: $option_name requires a positive integer no greater than $maximum."
        return 1
    fi
    value=$(( 10#$value ))
    if (( value < 1 || value > maximum )); then
        print -u2 -r -- "Error: $option_name requires a positive integer no greater than $maximum."
        return 1
    fi
    REPLY=$value
}

validate_proxy() {
    local value=$1 host port normalized_host
    # This option names a SOCKS endpoint only. Schemes, paths, and credentials
    # would imply curl proxy features the scanner does not support or preserve
    # in its measurement contract.
    if [[ -z "$value" || "$value" == *[[:space:]@/]* ]]; then
        print -u2 -r -- "Error: --proxy requires HOST:PORT without a URL scheme or credentials."
        return 1
    fi

    # Brackets make an IPv6 literal's colons unambiguous from the port
    # separator; unbracketed values must therefore contain exactly one colon.
    if [[ "$value" == \[*\]:* ]]; then
        host=${value%%]:*}
        host=${host#\[}
        port=${value##*]:}
        [[ -n "$host" && "$host" == *:* ]] || {
            print -u2 -r -- "Error: --proxy requires HOST:PORT without a URL scheme or credentials."
            return 1
        }
        normalized_host="[$host]"
    elif [[ "$value" == *:* && "${value%:*}" != *:* ]]; then
        host=${value%:*}
        port=${value##*:}
        [[ -n "$host" ]] || {
            print -u2 -r -- "Error: --proxy requires HOST:PORT without a URL scheme or credentials."
            return 1
        }
        normalized_host=$host
    else
        print -u2 -r -- "Error: --proxy requires HOST:PORT without a URL scheme or credentials."
        return 1
    fi

    parse_bounded_integer "$port" "--proxy port" 65535 || return 1
    REPLY="$normalized_host:$REPLY"
}

# ----------------------------------------------------------------- probes ---

# Each request owns these two tiny status files alongside BODY. Retain curl's
# transport result independently so a local reader or status-file failure cannot
# be mistaken for a native site outcome.
probe_curl() {
    local curl_result
    curl "$@"
    curl_result=$?
    print -r -- "$curl_result" > "$BODY.curl-status" || return 70
    return "$curl_result"
}

probe_body_sink() {
    local sink_result
    head -c "$MAX_BODY_BYTES" > "$BODY"
    sink_result=$?
    print -r -- "$sink_result" > "$BODY.sink-status" || return 70
    return "$sink_result"
}

probe_read_status() {
    local sink_result=""
    probe_exit=1 probe_exit_known=1
    if ! read -r probe_exit < "$BODY.curl-status" || [[ $probe_exit != <-> ]]; then
        probe_exit=1 probe_exit_known=0
        probe_local_failure=1
    fi
    if ! read -r sink_result < "$BODY.sink-status" || [[ $sink_result != 0 ]]; then
        probe_local_failure=1
    fi
    rm -f "$BODY.curl-status" "$BODY.sink-status" || probe_local_failure=1
}

# probe <url> <circuit-tag|""> <timeout>
# An empty circuit tag means a direct (clearnet) request with no proxy.
# The timeout is in seconds. Results replace the probe_* globals plus $BODY,
# $HDRS (every redirect hop), and $LASTH (the final hop only); callers must
# consume or copy them before the next probe.
probe() {
    # Detailed reproducible runs supply explicit proxy-bypass rules. Legacy
    # calls leave this dynamically scoped array unset and retain curl's behavior.
    local -a via=()
    (( ${+CHECK_TOR_PROBE_ARGS} )) && via=("${CHECK_TOR_PROBE_ARGS[@]}")
    # socks5-hostname keeps DNS resolution inside Tor. The tag is a disposable
    # SOCKS username, not a credential: with Tor's default IsolateSOCKSAuth,
    # changing it asks Tor to place the stream on a fresh circuit.
    [[ -n "$2" ]] && via+=(--socks5-hostname "$TOR_PROXY" --proxy-user "$2:x")
    probe_local_failure=0
    probe_body_limited_known=0
    probe_exit_known=0
    probe_exit=1 probe_code=000 probe_redirs="" probe_tls=0 probe_final="" probe_err="" probe_body_limited=0
    local response_file
    for response_file in "$BODY" "$HDRS" "$LASTH" "$BODY.curl-status" "$BODY.sink-status"; do
        : > "$response_file" || { probe_local_failure=1; return 1; }
    done
    probe_timeout=$3
    local out
    # curl's tab-delimited write-out is the probe's machine interface. Stderr
    # is suppressed because %{errormsg} captures it without mixing diagnostics
    # into scanner output. That field needs curl 7.75+; older curl leaves it
    # empty without shifting the preceding fields, so no version gate is needed.
    # --max-filesize cannot enforce a limit when a server omits Content-Length.
    # Put a byte-counting sink in front of the response file so chunked and
    # endless bodies are bounded too. curl may then report a write error after
    # head closes the pipe; probe_body_limited distinguishes that intentional
    # cutoff from an unrelated destination failure.
    # Ignore ambient curlrc credentials and TLS/request overrides. Keep -q first.
    # A shell-function invocation waits for its process substitutions in Zsh.
    # Without this wrapper, curl can exit before head has finished writing BODY,
    # leaving classification and the body-cap check racing that final write.
    out=$(probe_curl -q -s -o >(probe_body_sink) \
        -D "$HDRS" -L --max-redirs "$MAX_REDIRECTS" \
        -A "$USER_AGENT" -H "$ACCEPT_HDR" -H "$LANG_HDR" \
        "${via[@]}" --max-time "$3" \
        -w '%{http_code}\t%{num_redirects}\t%{time_appconnect}\t%{url_effective}\t%{errormsg}' \
        "$1" 2>/dev/null)
    probe_read_status
    local body_bytes
    if ! body_bytes=$(wc -c < "$BODY"); then
        probe_local_failure=1
        body_bytes=""
    fi
    body_bytes=${body_bytes//[[:space:]]/}
    if [[ $body_bytes == <-> ]]; then
        probe_body_limited_known=1
        probe_body_limited=$(( body_bytes >= MAX_BODY_BYTES ))
    else
        probe_local_failure=1
        probe_body_limited_known=0
    fi
    # IFS treats tabs as whitespace and collapses empty columns. Preserve them
    # so unavailable TLS/final-URL metadata cannot shift a diagnostic into a URL.
    local -a probe_fields=("${(@ps:\t:)out}")
    probe_code=${probe_fields[1]:-000}
    probe_redirs=${probe_fields[2]:-}
    probe_tls=${probe_fields[3]:-0}
    probe_final=${probe_fields[4]:-}
    probe_err=""
    (( ${#probe_fields} >= 5 )) && probe_err="${(pj:\t:)probe_fields[5,-1]}"

    # With -L, curl appends *every* redirect hop's headers to $HDRS. Isolate
    # the final block: a cf-ray on an intermediate redirect says nothing about
    # who served the response we actually landed on, and grepping the whole
    # file would credit that hop's WAF with the final hop's verdict.
    awk '/^HTTP\//{n=NR} {l[NR]=$0} END{for (i=n; i<=NR; i++) print l[i]}' \
        "$HDRS" > "$LASTH" || probe_local_failure=1
    return 0
}

# Parse and validate the complete invocation before any dependency check or
# network access. REPLY is the target file for legacy/source callers; reply is
# the ordered configuration tuple consumed by main. Keep that tuple and main's
# dynamically scoped locals in lockstep when adding a setting.
parse_args() {
    local output_format=text target_file="" argument
    local proxy=$TOR_PROXY circuits=$MAX_CIRCUITS
    local timeout_first=$TIMEOUT_FIRST timeout_retry=$TIMEOUT_RETRY
    local timeout_clearnet=$TIMEOUT_CLEARNET clearnet_enabled=$CLEARNET_ENABLED
    REPLY="" reply=()
    if (( $# == 1 )) && [[ "$1" == (-h|--help) ]]; then
        usage
        return 2
    fi

    while (( $# > 0 )); do
        argument=$1
        case $argument in
            --format)
                shift
                if (( $# == 0 )); then
                    print -u2 -r -- "Error: --format requires text or jsonl."
                    return 1
                fi
                output_format=$1
                ;;
            --format=*) output_format=${argument#*=} ;;
            --proxy|--circuits|--timeout-first|--timeout-retry|--timeout-clearnet)
                local option_name=$argument
                shift
                if (( $# == 0 )); then
                    print -u2 -r -- "Error: $option_name requires a value."
                    return 1
                fi
                case $option_name in
                    --proxy)
                        validate_proxy "$1" || return 1
                        proxy=$REPLY
                        ;;
                    --circuits)
                        parse_bounded_integer "$1" "$option_name" 100 || return 1
                        circuits=$REPLY
                        ;;
                    --timeout-first)
                        parse_bounded_integer "$1" "$option_name" 3600 || return 1
                        timeout_first=$REPLY
                        ;;
                    --timeout-retry)
                        parse_bounded_integer "$1" "$option_name" 3600 || return 1
                        timeout_retry=$REPLY
                        ;;
                    --timeout-clearnet)
                        parse_bounded_integer "$1" "$option_name" 3600 || return 1
                        timeout_clearnet=$REPLY
                        ;;
                esac
                ;;
            --proxy=*|--circuits=*|--timeout-first=*|--timeout-retry=*|--timeout-clearnet=*)
                local option_name=${argument%%=*} option_value=${argument#*=}
                case $option_name in
                    --proxy)
                        validate_proxy "$option_value" || return 1
                        proxy=$REPLY
                        ;;
                    --circuits)
                        parse_bounded_integer "$option_value" "$option_name" 100 || return 1
                        circuits=$REPLY
                        ;;
                    --timeout-first)
                        parse_bounded_integer "$option_value" "$option_name" 3600 || return 1
                        timeout_first=$REPLY
                        ;;
                    --timeout-retry)
                        parse_bounded_integer "$option_value" "$option_name" 3600 || return 1
                        timeout_retry=$REPLY
                        ;;
                    --timeout-clearnet)
                        parse_bounded_integer "$option_value" "$option_name" 3600 || return 1
                        timeout_clearnet=$REPLY
                        ;;
                esac
                ;;
            --no-clearnet) clearnet_enabled=0 ;;
            --)
                shift
                while (( $# > 0 )); do
                    if [[ -n "$target_file" ]]; then
                        print -u2 -r -- "Error: expected exactly one target file."
                        usage >&2
                        return 1
                    fi
                    target_file=$1
                    shift
                done
                break
                ;;
            -*)
                print -u2 -r -- "Error: unknown option '$argument'."
                usage >&2
                return 1
                ;;
            *)
                if [[ -n "$target_file" ]]; then
                    print -u2 -r -- "Error: expected exactly one target file."
                    usage >&2
                    return 1
                fi
                target_file=$argument
                ;;
        esac
        shift
    done

    if [[ "$output_format" != (text|jsonl) ]]; then
        print -u2 -r -- "Error: unsupported format '$output_format'; expected text or jsonl."
        return 1
    fi

    if [[ -z "$target_file" ]]; then
        print -u2 -r -- "Error: expected exactly one target file."
        usage >&2
        return 1
    fi

    if [[ ! -f "$target_file" ]]; then
        print -u2 -r -- "Error: file '$target_file' not found or is not a regular file."
        return 1
    fi

    if [[ ! -r "$target_file" ]]; then
        print -u2 -r -- "Error: file '$target_file' is not readable."
        return 1
    fi

    REPLY=$target_file
    reply=("$target_file" "$output_format" "$proxy" "$circuits" \
           "$timeout_first" "$timeout_retry" "$timeout_clearnet" "$clearnet_enabled")
}

load_targets() {
    local input_file=$1 line
    reply=()
    # Load and validate targets before checking dependencies or contacting Tor.
    # An input containing only whitespace and comments is operationally
    # equivalent to an empty file and is rejected rather than reported as a
    # successful scan.
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//$'\r'/}
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        reply+=("$line")
    done < "$input_file"

    if (( ${#reply[@]} == 0 )); then
        print -u2 -r -- "Error: file '$input_file' contains no targets."
        return 1
    fi
}

check_dependencies() {
    local -a required_commands=(curl awk grep head cut tr wc mktemp)
    local -a missing_commands=()
    local required_command
    for required_command in "${required_commands[@]}"; do
        (( $+commands[$required_command] )) || missing_commands+=("$required_command")
    done
    if (( ${#missing_commands[@]} > 0 )); then
        print -u2 -r -- "Error: missing required command(s): ${(j:, :)missing_commands}"
        return 1
    fi
}

warn_tracked_input() {
    local input_file=$1
    # Curated target lists can reveal sensitive associations, selection
    # criteria, or research priorities even when individual domains are public.
    # Warn loudly if this file is tracked by git.
    if (( $+commands[git] )) \
       && git -C "${input_file:A:h}" rev-parse --is-inside-work-tree &>/dev/null \
       && git -C "${input_file:A:h}" ls-files --error-unmatch "${input_file:A}" &>/dev/null; then
        print -u2 -r -- "[${YEL}WARNING${OFF}] '$input_file' is tracked by git and may be published."
        print -u2 -r -- "            If these are real targets, untrack them and keep the list"
        print -u2 -r -- "            outside the repo. See 'Handling target lists' in README.md."
        print -u2 -r -- ""
    fi
}

tor_preflight() {
    local tor_check exit_ip

    if [[ ${OUTPUT_FORMAT:-text} == text ]]; then
        echo "${BLD}check_tor${OFF} · https://github.com/josephlhall/check_tor"
        echo "Performing pre-flight check to ensure Tor is running..."
    fi
    # This checks more than whether a SOCKS port accepts connections: Tor's service
    # confirms that the request emerged from its network and reports the exit IP.
    tor_check=$(curl -q -s --socks5-hostname "$TOR_PROXY" --max-time "$PREFLIGHT_TIMEOUT" https://check.torproject.org/api/ip)

    if [[ "$tor_check" == *'"IsTor":true'* ]]; then
        exit_ip=${tor_check#*\"IP\":\"} exit_ip=${exit_ip%%\"*}
        [[ ${OUTPUT_FORMAT:-text} == text ]] && \
            echo "[${GRN}SUCCESS${OFF}] Tor connection verified (current exit: ${exit_ip:-unknown}). Starting scan..."
        return 0
    else
        print -u2 -r -- "[${RED}ERROR${OFF}] Tor connection failed. Did you remember to run 'tor-on'?"
        return 1
    fi
}

scan_target() {
    local url=$1 i=$2 total=$3
    local attempt tor_verdict tor_detail tor_body_limited
    local control_performed=0 control_verdict="" tor_specific_json=null
    local summary_included=0

    # Auto-format: upgrade http:// to https://, or add https:// if missing.
    url=${url/#http:\/\//https:\/\/}
    [[ "$url" =~ ^https?:// ]] || url="https://$url"

    # Retry only results for which another exit could plausibly change the
    # outcome. Certificate errors and unknown failures instead remain visible
    # for manual diagnosis without spending additional circuits.
    attempt=1
    while true; do
        transient "[$i/$total] $url — Tor circuit $attempt/$MAX_CIRCUITS"
        probe "$url" "c${RANDOM}x${RANDOM}" $(( attempt == 1 ? TIMEOUT_FIRST : TIMEOUT_RETRY ))
        classify
        blocky "$verdict" || break
        (( attempt == MAX_CIRCUITS )) && break
        (( attempt++ ))
    done
    # The clearnet control below calls classify again and overwrites its global
    # outputs, so preserve the final Tor result first.
    tor_verdict=$verdict tor_detail=$detail tor_body_limited=${probe_body_limited:-0}

    if (( attempt > 1 )); then
        if blocky "$tor_verdict"; then
            tor_detail+=", on $MAX_CIRCUITS different circuits"
        else
            tor_detail+=" (blocked on $(( attempt - 1 )) of $MAX_CIRCUITS circuits — circuit-dependent, not site-wide)"
        fi
    fi

    # For persistent blocks, run a clearnet control request and compare how
    # much worse Tor fared. If clearnet fares no better, this observation does
    # not support a Tor-specific inference; it cannot establish the site's
    # broader policy toward every kind of client.
    if blocky "$tor_verdict" && (( CLEARNET_ENABLED )); then
        transient "[$i/$total] $url — clearnet control check"
        probe "$url" "" $TIMEOUT_CLEARNET
        classify
        control_performed=1 control_verdict=$verdict
        compare_treatment "$tor_verdict" "$tor_detail" "$verdict"
        summary_included=$tor_specific
        # compare_treatment deliberately keeps inconclusive controls in the
        # human review list. Machine consumers need the stronger distinction:
        # null means the control could not establish Tor specificity.
        if [[ "$control_verdict" != (CERT|WARN) ]]; then
            (( tor_specific )) && tor_specific_json=true || tor_specific_json=false
        fi
    elif blocky "$tor_verdict"; then
        tor_detail+="; clearnet control disabled — Tor specificity unknown"
    fi

    if [[ ${OUTPUT_FORMAT:-text} == jsonl ]]; then
        print_json_target "$url" "$tor_verdict" "$tor_detail" "$attempt" \
            "$control_performed" "$control_verdict" "$tor_specific_json" "$tor_body_limited"
    else
        print_line "$tor_verdict" "$url" "$tor_detail"
    fi

    # Return the structured values the scan aggregator and future source-mode
    # callers need without requiring them to parse either output format.
    REPLY=$tor_verdict
    reply=("$url" "$tor_specific_json" "$tor_detail" "$attempt" \
           "$control_performed" "$control_verdict" "$tor_body_limited" "$summary_included")
}

print_summary() {
    local total=$1 key color b summary

    # zsh functions are dynamically scoped: counts and blocked are locals in
    # run_scan and visible here only for the duration of that call.
    echo "$RULE"
    summary="Scanned $total domain(s):"
    for key color in PASS "$GRN" CHALLENGE "$CYN" RATELIMIT "$YEL" FAIL "$RED" \
                     DROP "$RED" TIMEOUT "$YEL" CERT "$MAG" SOCKS "$RED" WARN "$YEL"; do
        (( ${counts[$key]:-0} > 0 )) && summary+=" ${color}${counts[$key]} ${key}${OFF} ·"
    done
    echo "${summary% ·}"
    if (( ${#blocked[@]} > 0 )); then
        echo "${RED}Likely blocking or challenging Tor:${OFF}"
        for b in "${blocked[@]}"; do echo "  • $b"; done
    fi
    echo "Scan complete."
}

run_scan() {
    local -a scan_targets=("$@") blocked=()
    local -A counts
    local total=$# i verdict_key normalized_url tor_specific summary_included
    local tor_specific_findings=0

    [[ ${OUTPUT_FORMAT:-text} == text ]] && echo "$RULE"

    # zsh arrays are one-indexed by default; keep this bound aligned with that
    # convention if target storage changes.
    for (( i = 1; i <= total; i++ )); do
        scan_target "${scan_targets[$i]}" "$i" "$total"
        verdict_key=$REPLY
        normalized_url=${reply[1]}
        tor_specific=${reply[2]}
        summary_included=${reply[8]}

        (( counts[$verdict_key]++ ))
        [[ "$tor_specific" == true ]] && (( tor_specific_findings++ ))
        if blocky "$verdict_key" && (( summary_included )); then
            blocked+=("$normalized_url ($verdict_key)")
        fi
    done

    if [[ ${OUTPUT_FORMAT:-text} == jsonl ]]; then
        print_json_summary "$total" "$tor_specific_findings"
    else
        print_summary "$total"
    fi
}

# The execution guard at the end of the file is the only automatic call to
# main. Keeping side effects here makes sourcing safe and lets tests or future
# callers load the reusable definitions without starting a scan.
main() {
    setopt localoptions localtraps
    local parse_status target_file
    local -a scan_targets

    # Keep the established CLI/parser and its source-callable contract intact.
    # The detailed coordinator is opt-in and invokes the same probe/classifier.
    local selected_format=text expect_format=0 arg
    for arg in "$@"; do
        if (( expect_format )); then
            selected_format=$arg
            expect_format=0
        elif [[ $arg == -- ]]; then
            break
        elif [[ $arg == --format ]]; then
            expect_format=1
        elif [[ $arg == --format=* ]]; then
            selected_format=${arg#*=}
        fi
    done
    if [[ $selected_format == jsonl-v2 ]]; then
        if (( ! $+commands[python3] )); then
            print -u2 -r -- "Error: --format jsonl-v2 requires Python 3.9 or newer."
            return 1
        fi
        # Keep main callable from a sourced shell: exec would replace its caller.
        # Forward cancellation to the coordinator, which owns its request groups,
        # and wait again if a signal interrupted our first wait. localtraps above
        # restores the caller's handlers when main returns.
        local detailed_pid="" detailed_status=0
        trap '[[ -z $detailed_pid ]] || kill -INT "$detailed_pid" 2>/dev/null || true' INT
        trap '[[ -z $detailed_pid ]] || kill -TERM "$detailed_pid" 2>/dev/null || true' TERM
        command python3 "$CHECK_TOR_DIR/check_tor_measure.py" "$@" &
        detailed_pid=$!
        while true; do
            if wait "$detailed_pid"; then
                detailed_status=0
            else
                detailed_status=$?
            fi
            kill -0 "$detailed_pid" 2>/dev/null || break
        done
        return "$detailed_status"
    fi

    configure_output

    parse_args "$@"
    parse_status=$?
    (( parse_status == 2 )) && return 0
    (( parse_status == 0 )) || return "$parse_status"
    target_file=$REPLY
    # These locals dynamically scope the selected configuration to the command
    # workflow. Sourcing the file leaves the documented defaults untouched.
    local OUTPUT_FORMAT=${reply[2]} TOR_PROXY=${reply[3]} MAX_CIRCUITS=${reply[4]}
    local TIMEOUT_FIRST=${reply[5]} TIMEOUT_RETRY=${reply[6]}
    local TIMEOUT_CLEARNET=${reply[7]} CLEARNET_ENABLED=${reply[8]}

    load_targets "$target_file" || return 1
    scan_targets=("${reply[@]}")

    check_dependencies || return 1
    warn_tracked_input "$target_file"

    # Allocate response files only after all offline validation succeeds. With
    # localtraps, cleanup runs when main returns and the caller's traps are
    # restored if main was invoked from a sourced script.
    BODY=$(mktemp) HDRS=$(mktemp) LASTH=$(mktemp)
    trap 'rm -f "$BODY" "$HDRS" "$LASTH" "$BODY.curl-status" "$BODY.sink-status"' EXIT INT TERM

    tor_preflight || return 1
    run_scan "${scan_targets[@]}"
}

# ZSH_EVAL_CONTEXT is exactly "toplevel" for an executed script and includes
# ":file" when sourced. Avoid $0 here: under sourcing it belongs to the caller.
if [[ $ZSH_EVAL_CONTEXT == toplevel ]]; then
    main "$@"
fi
