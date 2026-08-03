#!/usr/bin/env zsh

# check_tor.zsh — test whether a list of domains is reachable over the Tor
# network, and diagnose the nature of any blockage (WAF rule, JS challenge,
# rate limit, silent drop, TLS breakage) before deciding a site "blocks Tor".
# https://github.com/josephlhall/check_tor

# ----------------------------------------------------------------- config ---

# IP and port of your Tor SOCKS proxy.
TOR_PROXY="localhost:9050"

# A site is only declared blocked after failing on this many different Tor
# circuits. Fresh circuits come from varying the SOCKS credentials: Tor's
# default IsolateSOCKSAuth forbids streams with different credentials from
# sharing a circuit, so no ControlPort is needed. Note this guarantees a
# separate *circuit*, not a different exit relay — two circuits can
# independently pick the same exit, so a repeat failure is suggestive of a
# site-wide policy rather than proof of one.
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

# A real target list names organizations that believe they are at risk and
# are seeking protection they do not yet have. Published, it is a ready-made
# reconnaissance aid. Warn loudly if this file is tracked by git.
if git -C "${1:A:h}" rev-parse --is-inside-work-tree &>/dev/null \
   && git -C "${1:A:h}" ls-files --error-unmatch "${1:A}" &>/dev/null; then
    echo "[${YEL}WARNING${OFF}] '$1' is tracked by git and may be published."
    echo "            If these are real targets, untrack them and keep the list"
    echo "            outside the repo. See 'Handling target lists' in README.md."
    echo ""
fi

# ----------------------------------------------------------------- probes ---

BODY=$(mktemp) HDRS=$(mktemp) LASTH=$(mktemp)
trap 'rm -f "$BODY" "$HDRS" "$LASTH"' EXIT INT TERM

# probe <url> <circuit-tag|""> <timeout>
# An empty circuit tag means a direct (clearnet) request with no proxy.
# Results land in: probe_exit, probe_code, probe_redirs, probe_tls,
# probe_final (effective URL after redirects), probe_err (curl's own error
# text), plus $BODY, $HDRS (every hop) and $LASTH (final hop only).
probe() {
    local -a via=()
    [[ -n "$2" ]] && via=(--socks5-hostname "$TOR_PROXY" --proxy-user "$2:x")
    : > "$BODY"; : > "$HDRS"; : > "$LASTH"
    probe_timeout=$3
    local out
    # %{errormsg} needs curl 7.75+; older curl skips it and leaves the field
    # empty rather than shifting the others, so no version gate is needed.
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

# Identify who issued the *final* response, from $LASTH and the body. WAF
# block pages carry fingerprints — notably Cloudflare, which still serves its
# 1xxx error codes (1020 firewall rule, 1015 rate limit, ...) in the body of a
# plain HTTP 403, though newer edges may also set a cf-error-type header.
# Strongest signals first: an explicit challenge marker beats an error code,
# which beats "Cloudflare merely fronted this".
blocker_id() {
    blocker=""
    local cf_err
    cf_err=$(grep -aoE 'error code: 1[0-9]{3}' "$BODY" | grep -oE '1[0-9]{3}' | head -1)
    if grep -qia '^cf-mitigated:.*challenge' "$LASTH"; then
        blocker="Cloudflare challenge (cf-mitigated)"
    elif [[ -n "$cf_err" ]]; then
        case "$cf_err" in
            1020)                blocker="Cloudflare 1020: blocked by a firewall rule" ;;
            1015)                blocker="Cloudflare 1015: rate limited" ;;
            1006|1007|1008|1106) blocker="Cloudflare $cf_err: IP banned" ;;
            *)                   blocker="Cloudflare error $cf_err" ;;
        esac
    elif grep -qa 'Just a moment' "$BODY" || grep -qa 'cf-chl' "$BODY"; then
        blocker="Cloudflare challenge page"
    elif grep -qia '^cf-error-type:' "$LASTH"; then
        blocker="Cloudflare error ($(grep -aim1 '^cf-error-type:' "$LASTH" | cut -d: -f2- | tr -d ' \r'))"
    elif grep -qia '^cf-ray:' "$LASTH"; then
        blocker="served by Cloudflare"
    elif grep -qia 'AkamaiGHost' "$LASTH"; then
        blocker="Akamai edge"
    elif grep -qiaE '^x-sucuri-(id|cache):' "$LASTH"; then
        blocker="Sucuri WAF"
    elif grep -qia '^x-iinfo:' "$LASTH" || grep -qia 'incap_ses' "$LASTH"; then
        blocker="Imperva/Incapsula WAF"
    fi
}

# Classify the last probe into a verdict + human detail. curl exit codes are
# checked before HTTP status codes: a non-zero curl exit means the status
# variable is meaningless.
classify() {
    verdict="" detail=""
    case $probe_exit in
        5)     verdict=SOCKS; detail="couldn't resolve the SOCKS proxy — is Tor still running?"; return ;;
        97)    # Covers every SOCKS5 reply Tor can return (host unreachable,
               # connection refused, network unreachable, ...). curl collapses
               # them all into one code, so lean on its error text for detail.
               verdict=SOCKS; detail="proxy/SOCKS handshake failed"
               [[ -n "$probe_err" ]] && detail+=" — $probe_err"
               return ;;
        60|51) verdict=CERT;  detail="TLS certificate verification failed"; return ;;
        35)    verdict=CERT;  detail="TLS handshake failed"
               [[ -n "$probe_err" ]] && detail+=" — $probe_err"
               return ;;
        56)    verdict=DROP;  detail="receive failure — connection likely reset mid-request"; return ;;
        52)    verdict=DROP;  detail="server accepted the connection, then went silent"; return ;;
        18)    verdict=DROP;  detail="response truncated mid-transfer"; return ;;
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
        *)  verdict=WARN; detail="curl exit $probe_exit"
            [[ -n "$probe_err" ]] && detail+=" — $probe_err"
            return ;;
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

# Rank a verdict by how badly it impedes a real user, into global `sev`:
#   0 = served fine   1 = passable with friction (a browser can solve it)
#   2 = impassable    -1 = inconclusive, tells us nothing either way
# Comparing the Tor verdict against the clearnet control this way is what
# separates "blocks Tor" from "blocks everyone": only a site that treats Tor
# *strictly worse* than an ordinary client is actually blocking Tor.
severity() {
    case $1 in
        PASS)                    sev=0 ;;
        CHALLENGE|RATELIMIT)     sev=1 ;;
        FAIL|DROP|TIMEOUT|SOCKS) sev=2 ;;
        *)                       sev=-1 ;;
    esac
}

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
        severity "$tor_verdict"; tor_sev=$sev
        severity "$verdict";     net_sev=$sev
        if (( net_sev < 0 )); then
            tor_detail+="; clearnet inconclusive ($verdict) — worth checking by hand"
        elif (( net_sev < tor_sev )); then
            if (( net_sev == 0 )); then
                tor_detail+="; clearnet OK → Tor-specific"
            else
                tor_detail+="; clearnet only got $verdict → escalated for Tor"
            fi
        else
            tor_detail+="; clearnet fares no better ($verdict) → likely not Tor-specific"
            tor_specific=0
        fi
    fi

    print_line "$tor_verdict" "$url" "$tor_detail"
    (( counts[$tor_verdict]++ ))
    if blocky "$tor_verdict" && (( tor_specific )); then
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
