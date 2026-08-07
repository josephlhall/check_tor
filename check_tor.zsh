#!/usr/bin/env zsh

# check_tor.zsh—test whether a list of domains is reachable over the Tor
# network, and diagnose the nature of any blockage (WAF rule, JS challenge,
# rate limit, silent drop, TLS breakage) before deciding a site "blocks Tor".
# https://github.com/josephlhall/check_tor
#
# The scanner is deliberately serial. Each probe replaces a shared set of
# result variables and temporary response files; the scan loop classifies and
# snapshots those results before starting another probe.

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
transient()       { [[ -t 1 ]] && printf '\r\033[K%s%s%s' "$DIM" "$1" "$OFF" }
clear_transient() { [[ -t 1 ]] && printf '\r\033[K' }

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

usage() {
    print -r -- "Usage: ./check_tor.zsh <file_with_urls.txt>"
    print -r -- "       ./check_tor.zsh --help"
    print -r -- ""
    print -r -- "Scan each nonblank, non-comment target through a local Tor proxy."
    print -r -- "Targets without a scheme, and http:// targets, are tested as https://."
    print -r -- ""
    print -r -- "Options:"
    print -r -- "  -h, --help  Show this help and exit."
    print -r -- ""
    print -r -- "Environment:"
    print -r -- "  NO_COLOR    Disable ANSI color styling."
    print -r -- ""
    print -r -- "Exit status:"
    print -r -- "  0  Scan completed, regardless of findings."
    print -r -- "  1  Invocation, input, dependency, or Tor preflight failure."
}

# ----------------------------------------------------------------- probes ---

# probe <url> <circuit-tag|""> <timeout>
# An empty circuit tag means a direct (clearnet) request with no proxy.
# The timeout is in seconds. Results replace the probe_* globals plus $BODY,
# $HDRS (every redirect hop), and $LASTH (the final hop only); callers must
# consume or copy them before the next probe.
probe() {
    local -a via=()
    # socks5-hostname keeps DNS resolution inside Tor. The tag is a disposable
    # SOCKS username, not a credential: with Tor's default IsolateSOCKSAuth,
    # changing it asks Tor to place the stream on a fresh circuit.
    [[ -n "$2" ]] && via=(--socks5-hostname "$TOR_PROXY" --proxy-user "$2:x")
    : > "$BODY"; : > "$HDRS"; : > "$LASTH"
    probe_timeout=$3
    local out
    # curl's tab-delimited write-out is the probe's machine interface. Stderr
    # is suppressed because %{errormsg} captures it without mixing diagnostics
    # into scanner output. That field needs curl 7.75+; older curl leaves it
    # empty without shifting the preceding fields, so no version gate is needed.
    out=$(curl -s -o "$BODY" -D "$HDRS" -L --max-redirs 10 \
        -A "$USER_AGENT" -H "$ACCEPT_HDR" -H "$LANG_HDR" \
        "${via[@]}" --max-time "$3" \
        -w '%{http_code}\t%{num_redirects}\t%{time_appconnect}\t%{url_effective}\t%{errormsg}' \
        "$1" 2>/dev/null)
    probe_exit=$?
    IFS=$'\t' read -r probe_code probe_redirs probe_tls probe_final probe_err <<< "$out"
    probe_code=${probe_code:-000}

    # With -L, curl appends *every* redirect hop's headers to $HDRS. Isolate
    # the final block: a cf-ray on an intermediate redirect says nothing about
    # who served the response we actually landed on, and grepping the whole
    # file would credit that hop's WAF with the final hop's verdict.
    awk '/^HTTP\//{n=NR} {l[NR]=$0} END{for (i=n; i<=NR; i++) print l[i]}' \
        "$HDRS" > "$LASTH"
}

parse_args() {
    REPLY=""
    if (( $# == 1 )) && [[ "$1" == (-h|--help) ]]; then
        usage
        return 2
    fi

    if (( $# != 1 )); then
        print -u2 -r -- "Error: expected exactly one target file."
        usage >&2
        return 1
    fi

    if [[ ! -f "$1" ]]; then
        print -u2 -r -- "Error: file '$1' not found or is not a regular file."
        return 1
    fi

    if [[ ! -r "$1" ]]; then
        print -u2 -r -- "Error: file '$1' is not readable."
        return 1
    fi

    REPLY=$1
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
    local -a required_commands=(curl awk grep head cut tr mktemp)
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
    # A real target list names organizations that believe they are at risk and
    # are seeking protection they do not yet have. Published, it is a ready-made
    # reconnaissance aid. Warn loudly if this file is tracked by git.
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

    echo "${BLD}check_tor${OFF} · https://github.com/josephlhall/check_tor"
    echo "Performing pre-flight check to ensure Tor is running..."
    # This checks more than whether a SOCKS port accepts connections: Tor's service
    # confirms that the request emerged from its network and reports the exit IP.
    tor_check=$(curl -s --socks5-hostname "$TOR_PROXY" --max-time 10 https://check.torproject.org/api/ip)

    if [[ "$tor_check" == *'"IsTor":true'* ]]; then
        exit_ip=${tor_check#*\"IP\":\"} exit_ip=${exit_ip%%\"*}
        echo "[${GRN}SUCCESS${OFF}] Tor connection verified (current exit: ${exit_ip:-unknown}). Starting scan..."
    else
        print -u2 -r -- "[${RED}ERROR${OFF}] Tor connection failed. Did you remember to run 'tor-on'?"
        return 1
    fi
}

scan_target() {
    local url=$1 i=$2 total=$3
    local attempt tor_verdict tor_detail tor_specific

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
    tor_verdict=$verdict tor_detail=$detail

    if (( attempt > 1 )); then
        if blocky "$tor_verdict"; then
            tor_detail+=", on $MAX_CIRCUITS different circuits"
        else
            tor_detail+=" (blocked on $(( attempt - 1 )) of $MAX_CIRCUITS circuits — circuit-dependent, not site-wide)"
        fi
    fi

    # For persistent blocks, run a clearnet control request and compare how
    # much worse Tor fared. Equal or gentler treatment on clearnet means the
    # site is hostile to scripted clients generally, not to Tor.
    tor_specific=1
    if blocky "$tor_verdict"; then
        transient "[$i/$total] $url — clearnet control check"
        probe "$url" "" $TIMEOUT_CLEARNET
        classify
        compare_treatment "$tor_verdict" "$tor_detail" "$verdict"
    fi

    print_line "$tor_verdict" "$url" "$tor_detail"

    # Return the values the scan aggregator needs without leaking per-target
    # locals. REPLY is the verdict; reply contains normalized URL and the
    # Tor-specific flag.
    REPLY=$tor_verdict
    reply=("$url" "$tor_specific")
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
    local total=$# i verdict_key normalized_url tor_specific

    echo "$RULE"

    # zsh arrays are one-indexed by default; keep this bound aligned with that
    # convention if target storage changes.
    for (( i = 1; i <= total; i++ )); do
        scan_target "${scan_targets[$i]}" "$i" "$total"
        verdict_key=$REPLY
        normalized_url=${reply[1]}
        tor_specific=${reply[2]}

        (( counts[$verdict_key]++ ))
        if blocky "$verdict_key" && (( tor_specific )); then
            blocked+=("$normalized_url ($verdict_key)")
        fi
    done

    print_summary "$total"
}

# The execution guard at the end of the file is the only automatic call to
# main. Keeping side effects here makes sourcing safe and lets tests or future
# callers load the reusable definitions without starting a scan.
main() {
    setopt localoptions localtraps
    local parse_status target_file
    local -a scan_targets

    configure_output

    parse_args "$@"
    parse_status=$?
    (( parse_status == 2 )) && return 0
    (( parse_status == 0 )) || return "$parse_status"
    target_file=$REPLY

    load_targets "$target_file" || return 1
    scan_targets=("${reply[@]}")

    check_dependencies || return 1
    warn_tracked_input "$target_file"

    # Allocate response files only after all offline validation succeeds. With
    # localtraps, cleanup runs when main returns and the caller's traps are
    # restored if main was invoked from a sourced script.
    BODY=$(mktemp) HDRS=$(mktemp) LASTH=$(mktemp)
    trap 'rm -f "$BODY" "$HDRS" "$LASTH"' EXIT INT TERM

    tor_preflight || return 1
    run_scan "${scan_targets[@]}"
}

# ZSH_EVAL_CONTEXT is exactly "toplevel" for an executed script and includes
# ":file" when sourced. Avoid $0 here: under sourcing it belongs to the caller.
if [[ $ZSH_EVAL_CONTEXT == toplevel ]]; then
    main "$@"
fi
