#!/usr/bin/env zsh

# check_tor.zsh — test whether a list of domains is reachable over the Tor
# network, and diagnose the nature of any blockage (WAF rule, JS challenge,
# rate limit, silent drop, TLS breakage) before deciding a site "blocks Tor".
# https://github.com/josephlhall/check_tor

# ----------------------------------------------------------------- config ---

# IP and port of your Tor SOCKS proxy.
TOR_PROXY="localhost:9050"

# A site is only declared blocked after failing on this many different Tor
# circuits. Fresh circuits are obtained by varying SOCKS credentials, which
# Tor's default IsolateSOCKSAuth maps to separate circuits — no ControlPort
# needed. This separates "blocks all of Tor" from "one exit has a bad IP rep".
MAX_CIRCUITS=3

# Per-request timeouts, in seconds.
TIMEOUT_FIRST=60      # first attempt over Tor
TIMEOUT_RETRY=30      # retries on fresh circuits
TIMEOUT_CLEARNET=20   # control request without Tor

# Browser-like headers, to avoid trivial bot-fingerprint false positives.
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
ACCEPT_HDR="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
LANG_HDR="Accept-Language: en-US,en;q=0.5"

# ----------------------------------------------------------------- output ---

RED=$'\033[31m' GRN=$'\033[32m' YEL=$'\033[33m' MAG=$'\033[35m'
CYN=$'\033[36m' DIM=$'\033[2m'  BLD=$'\033[1m'  OFF=$'\033[0m'
RULE="─────────────────────────────────────────────────────────"

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

# ------------------------------------------------------------ arg parsing ---

if [[ -z "$1" ]]; then
    echo "Usage: ./check_tor.zsh <file_with_urls.txt>"
    exit 1
fi

if [[ ! -f "$1" ]]; then
    echo "Error: File '$1' not found."
    exit 1
fi

# ----------------------------------------------------------------- probes ---

BODY=$(mktemp) HDRS=$(mktemp)
trap 'rm -f "$BODY" "$HDRS"' EXIT INT TERM

# probe <url> <circuit-tag|""> <timeout>
# An empty circuit tag means a direct (clearnet) request with no proxy.
# Results land in: probe_exit, probe_code, probe_redirs, probe_tls,
# probe_final (effective URL after redirects), plus $BODY and $HDRS files.
probe() {
    local -a via=()
    [[ -n "$2" ]] && via=(--socks5-hostname "$TOR_PROXY" --proxy-user "$2:x")
    : > "$BODY"; : > "$HDRS"
    probe_timeout=$3
    local out
    out=$(curl -s -o "$BODY" -D "$HDRS" -L --max-redirs 10 \
        -A "$USER_AGENT" -H "$ACCEPT_HDR" -H "$LANG_HDR" \
        "${via[@]}" --max-time "$3" \
        -w '%{http_code} %{num_redirects} %{time_appconnect} %{url_effective}' \
        "$1")
    probe_exit=$?
    read -r probe_code probe_redirs probe_tls probe_final <<< "$out"
    probe_code=${probe_code:-000}
}

# Identify who issued the response we got, from headers and body. WAF block
# pages carry fingerprints — notably Cloudflare, which serves its 10xx error
# codes (1020 firewall rule, 1015 rate limit, ...) inside a plain HTTP 403.
blocker_id() {
    blocker=""
    local cf_err
    cf_err=$(grep -aoE 'error code: 10[0-9]{2}' "$BODY" | grep -oE '10[0-9]{2}' | head -1)
    if grep -qia '^cf-mitigated:.*challenge' "$HDRS"; then
        blocker="Cloudflare managed challenge"
    elif [[ -n "$cf_err" ]]; then
        case "$cf_err" in
            1020)           blocker="Cloudflare 1020: blocked by a firewall rule" ;;
            1015)           blocker="Cloudflare 1015: rate limited" ;;
            1006|1007|1008) blocker="Cloudflare $cf_err: IP banned" ;;
            *)              blocker="Cloudflare error $cf_err" ;;
        esac
    elif grep -qa 'Just a moment' "$BODY" || grep -qa 'cf-chl' "$BODY"; then
        blocker="Cloudflare JS challenge"
    elif grep -qia '^cf-ray:' "$HDRS"; then
        blocker="served by Cloudflare"
    elif grep -qia 'AkamaiGHost' "$HDRS"; then
        blocker="Akamai edge"
    elif grep -qia '^x-sucuri-id:' "$HDRS"; then
        blocker="Sucuri WAF"
    elif grep -qiaE 'x-iinfo|incap_ses' "$HDRS" "$BODY"; then
        blocker="Imperva/Incapsula WAF"
    fi
}

# Classify the last probe into a verdict + human detail. curl exit codes are
# checked before HTTP status codes: a non-zero curl exit means the status
# variable is meaningless.
classify() {
    verdict="" detail=""
    case $probe_exit in
        97|5)     verdict=SOCKS; detail="Tor exit couldn't connect to the host"; return ;;
        60|51|35) verdict=CERT;  detail="invalid, expired, or mismatched TLS certificate"; return ;;
        56)       verdict=DROP;  detail="connection reset mid-request — firewall likely dropping Tor"; return ;;
        52)       verdict=DROP;  detail="server accepted the connection, then went silent"; return ;;
        28|7)
            verdict=TIMEOUT
            if (( ${probe_tls:-0} > 0 )); then
                detail="TLS completed, then stalled for ${probe_timeout}s — possible tarpit"
            else
                detail="no response in ${probe_timeout}s — silent drop or dead host"
            fi
            return ;;
        47) verdict=WARN; detail="redirect loop (more than 10 redirects)"; return ;;
        0)  ;;
        *)  verdict=WARN; detail="curl exit $probe_exit (status $probe_code)"; return ;;
    esac

    blocker_id
    case $probe_code in
        200)
            if [[ "$probe_final" == *"/cdn-cgi/"* || "$blocker" == *challenge* ]]; then
                verdict=CHALLENGE detail="HTTP 200, but landed on a challenge page"
            else
                verdict=PASS detail="HTTP 200"
                (( probe_redirs > 0 )) && detail+=" after $probe_redirs redirect(s)"
            fi ;;
        401|403)
            if [[ "$blocker" == *challenge* ]]; then
                verdict=CHALLENGE detail="HTTP $probe_code — $blocker"
            else
                verdict=FAIL detail="HTTP $probe_code"
                [[ -n "$blocker" ]] && detail+=" — $blocker"
            fi ;;
        202)
            verdict=CHALLENGE detail="HTTP 202 — WAF challenge or async queue" ;;
        429)
            verdict=RATELIMIT detail="HTTP 429 — this exit's IP is rate-limited"
            [[ -n "$blocker" ]] && detail+=" — $blocker" ;;
        503)
            if [[ -n "$blocker" ]]; then
                verdict=CHALLENGE detail="HTTP 503 — $blocker (under-attack mode)"
            else
                verdict=WARN detail="HTTP 503 — origin unavailable"
            fi ;;
        301|302|303|307|308)
            verdict=WARN detail="HTTP $probe_code that couldn't be followed (no Location header?)" ;;
        *)
            verdict=WARN detail="HTTP $probe_code"
            [[ -n "$blocker" ]] && detail+=" — $blocker" ;;
    esac
}

# Verdicts that suggest a block, and are worth retrying / cross-checking.
blocky() { [[ $1 == (FAIL|CHALLENGE|RATELIMIT|DROP|TIMEOUT|SOCKS) ]] }

# -------------------------------------------------------------- pre-flight ---

echo "${BLD}check_tor${OFF} · https://github.com/josephlhall/check_tor"
echo "Performing pre-flight check to ensure Tor is running..."
tor_check=$(curl -s --socks5-hostname "$TOR_PROXY" --max-time 10 https://check.torproject.org/api/ip)

if [[ "$tor_check" == *'"IsTor":true'* ]]; then
    exit_ip=${tor_check#*\"IP\":\"} exit_ip=${exit_ip%%\"*}
    echo "[${GRN}SUCCESS${OFF}] Tor connection verified (current exit: ${exit_ip:-unknown}). Starting scan..."
else
    echo "[${RED}ERROR${OFF}] Tor connection failed. Did you remember to run 'tor-on'?"
    exit 1
fi

# -------------------------------------------------------------- main scan ---

# Read targets up front: skip blank lines and #comments, strip CR/whitespace.
targets=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line//$'\r'/}
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    targets+=("$line")
done < "$1"
total=${#targets[@]}

echo "$RULE"

typeset -A counts
blocked=()

for (( i = 1; i <= total; i++ )); do
    url=${targets[$i]}

    # Auto-format: upgrade http:// to https://, or add https:// if missing.
    url=${url/#http:\/\//https:\/\/}
    [[ "$url" =~ ^https?:// ]] || url="https://$url"

    # Try over Tor, re-trying block-ish results on fresh circuits.
    attempt=1
    while true; do
        transient "[$i/$total] $url — Tor circuit $attempt/$MAX_CIRCUITS"
        probe "$url" "c${RANDOM}x${RANDOM}" $(( attempt == 1 ? TIMEOUT_FIRST : TIMEOUT_RETRY ))
        classify
        blocky "$verdict" || break
        (( attempt == MAX_CIRCUITS )) && break
        (( attempt++ ))
    done
    tor_verdict=$verdict tor_detail=$detail

    if (( attempt > 1 )); then
        if blocky "$tor_verdict"; then
            tor_detail+=", on $MAX_CIRCUITS different circuits"
        else
            tor_detail+=" (blocked on $(( attempt - 1 )) of $MAX_CIRCUITS circuits — exit-dependent, not site-wide)"
        fi
    fi

    # For persistent blocks, run a clearnet control request: does the site
    # block Tor specifically, or does it block this scanner from anywhere?
    tor_specific=1
    if blocky "$tor_verdict"; then
        transient "[$i/$total] $url — clearnet control check"
        probe "$url" "" $TIMEOUT_CLEARNET
        classify
        if [[ "$verdict" == PASS ]]; then
            tor_detail+="; clearnet OK → Tor-specific"
        elif [[ "$verdict" == "$tor_verdict" ]]; then
            tor_detail+="; blocked on clearnet too → likely not Tor-specific"
            tor_specific=0
        else
            tor_detail+="; clearnet got: $verdict"
        fi
    fi

    print_line "$tor_verdict" "$url" "$tor_detail"
    (( counts[$tor_verdict]++ ))
    if blocky "$tor_verdict" && [[ "$tor_verdict" != TIMEOUT ]] && (( tor_specific )); then
        blocked+=("$url ($tor_verdict)")
    fi
done

# ---------------------------------------------------------------- summary ---

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
