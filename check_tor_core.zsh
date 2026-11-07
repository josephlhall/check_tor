# Decision logic shared by the scanner and its offline regression tests.
# Callers provide probe_* globals and BODY/LASTH fixture paths.

# grep's exit 1 means no match; any other failure makes classification
# unavailable. Keep this flag in the caller shell rather than in a pipeline or
# command substitution, so v2 cannot mistake a failed inspection for a PASS.
classify_matches() {
    local match_status
    grep "$@"
    match_status=$?
    (( match_status > 1 )) && probe_local_failure=1
    return "$match_status"
}

# Identify who issued the final response, from $LASTH and the body.
blocker_id() {
    blocker=""
    local cf_err match_status error_header
    cf_err=$(grep -aom1 -E 'error code: 1[0-9]{3}' "$BODY")
    match_status=$?
    if (( match_status > 1 )); then
        probe_local_failure=1
        return 70
    fi
    # -m1 limits matching lines; a line may still contain several matches.
    # Shell extraction avoids pipelines that could hide a utility failure.
    local -a cf_matches=("${(@f)cf_err}")
    cf_err=${cf_matches[1]#'error code: '}
    if classify_matches -qia '^cf-mitigated:.*challenge' "$LASTH"; then
        blocker="Cloudflare challenge (cf-mitigated)"
    elif [[ -n "$cf_err" ]]; then
        case "$cf_err" in
            1020)                blocker="Cloudflare 1020: blocked by a firewall rule" ;;
            1015)                blocker="Cloudflare 1015: rate limited" ;;
            1006|1007|1008|1106) blocker="Cloudflare $cf_err: IP banned" ;;
            *)                   blocker="Cloudflare error $cf_err" ;;
        esac
    elif classify_matches -qa 'Just a moment' "$BODY" || classify_matches -qa 'cf-chl' "$BODY"; then
        blocker="Cloudflare challenge page"
    elif classify_matches -qia '^cf-error-type:' "$LASTH"; then
        error_header=$(grep -aim1 '^cf-error-type:' "$LASTH")
        match_status=$?
        if (( match_status > 1 )); then
            probe_local_failure=1
            return 70
        fi
        error_header=${error_header#*:}
        error_header=${error_header//[$' \r']/}
        blocker="Cloudflare error ($error_header)"
    elif classify_matches -qia '^cf-ray:' "$LASTH"; then
        blocker="served by Cloudflare"
    elif classify_matches -qia 'AkamaiGHost' "$LASTH"; then
        blocker="Akamai edge"
    elif classify_matches -qiaE '^x-sucuri-(id|cache):' "$LASTH"; then
        blocker="Sucuri WAF"
    elif classify_matches -qia '^x-iinfo:' "$LASTH" || classify_matches -qia 'incap_ses' "$LASTH"; then
        blocker="Imperva/Incapsula WAF"
    fi
    (( ! ${probe_local_failure:-0} ))
}

# Classify the last probe into a verdict + human detail.
classify() {
    verdict="" detail=""
    # A capped prefix is deliberately inconclusive even if curl also returned
    # an HTTP status or write error. Treating partial content as authoritative
    # could create a false block or trigger misleading Tor/clearnet retries.
    if (( ${probe_body_limited:-0} )); then
        verdict=WARN detail="response body reached the 1 MiB inspection limit"
        return
    fi
    case $probe_exit in
        5)     verdict=SOCKS; detail="couldn't resolve the SOCKS proxy — is Tor still running?"; return ;;
        97)
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

    blocker_id || { probe_local_failure=1; return 70; }
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

# Rank a verdict by how badly it impedes a real user.
severity() {
    case $1 in
        PASS)                    sev=0 ;;
        CHALLENGE|RATELIMIT)     sev=1 ;;
        FAIL|DROP|TIMEOUT|SOCKS) sev=2 ;;
        *)                       sev=-1 ;;
    esac
}

# Compare a persistent Tor verdict with its clearnet control.
# Inputs: $1=Tor verdict, $2=Tor detail, $3=clearnet verdict.
# Results: tor_detail and tor_specific globals.
compare_treatment() {
    local tor_verdict_input=$1 net_verdict=$3
    tor_detail=$2
    tor_specific=1

    severity "$tor_verdict_input"; local tor_sev=$sev
    severity "$net_verdict";       local net_sev=$sev
    if (( net_sev < 0 )); then
        tor_detail+="; clearnet inconclusive ($net_verdict) — worth checking by hand"
    elif (( net_sev < tor_sev )); then
        if (( net_sev == 0 )); then
            tor_detail+="; clearnet OK → Tor-specific"
        else
            tor_detail+="; clearnet only got $net_verdict → escalated for Tor"
        fi
    else
        tor_detail+="; clearnet fares no better ($net_verdict) → likely not Tor-specific"
        tor_specific=0
    fi
}
