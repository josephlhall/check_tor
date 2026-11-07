#!/usr/bin/env zsh
# Private one-observation bridge. The coordinator owns its directory/session;
# stdout is a bounded metadata protocol, never a response or diagnostic log.
emulate -L zsh
setopt no_unset
source "${0:A:h}/check_tor.zsh"
if [[ ${1:-} == --settings && $# == 1 ]]; then
    json_quote "$USER_AGENT"; ua=$REPLY
    json_quote "$ACCEPT_HDR"; accept=$REPLY
    json_quote "$LANG_HDR"; language=$REPLY
    printf '{"user_agent":%s,"accept_header":%s,"language_header":%s,"max_body_bytes":%d,"redirect_limit":%d,"preflight_timeout":%d,"curlrc":"disabled_by_q_first","url_globbing":"disabled"}\n' \
        "$ua" "$accept" "$language" "$MAX_BODY_BYTES" "$MAX_REDIRECTS" "$PREFLIGHT_TIMEOUT"
    exit 0
fi
(( $# == 6 )) || exit 70
request_dir=$1 route=$2 url=$3 timeout=$4 reproducible=$5 phase=$6
BODY=$request_dir/body HDRS=$request_dir/headers LASTH=$request_dir/last_headers
TOR_PROXY=${CHECK_TOR_PROXY:-localhost:9050}
# A scheduled observation must make one URL transfer. v2 accepts literal URL
# braces and ranges; curl must not expand them into additional requests.
typeset -a CHECK_TOR_PROBE_ARGS=(--globoff)
if [[ $reproducible == 1 ]]; then
    if [[ $route == direct ]]; then
        CHECK_TOR_PROBE_ARGS+=(--noproxy '*')
    else
        CHECK_TOR_PROBE_ARGS+=(--noproxy '')
    fi
fi
# These are local invocation/configuration/resource failures, not observations
# of a negative site response. Exit 23 is expected only when our finite body
# sink deliberately reaches its cap; otherwise it is a local write failure.
check_local_transport() {
    case $probe_exit in
        1|2|3|4|26|27|43|45|48|53|54|58|59|66|77|82|126|127) return 1 ;;
        23) (( probe_body_limited )) || return 1 ;;
    esac
    (( probe_exit < 128 )) || return 1
    return 0
}

tag=""
[[ $route == tor ]] && tag="c${RANDOM}x${RANDOM}"
# File/setup failures must not masquerade as transport observations.
probe_local_failure=0
probe_body_limited_known=0
probe_exit_known=0
for response_file in "$BODY" "$HDRS" "$LASTH" "$BODY.curl-status" "$BODY.sink-status"; do
    : > "$response_file" || exit 70
done
verified=null result_verdict=null result_detail=null local_error=null
if [[ $phase == preflight ]]; then
    # This request deliberately retains the legacy preflight HTTP behavior:
    # no redirects/browser headers, exactly one Tor API check. The bounded
    # private sink prevents retaining an unlimited unexpected response.
    typeset -a preflight_via=()
    [[ $reproducible == 1 ]] && preflight_via=(--noproxy '')
    probe_curl -q -s --socks5-hostname "$TOR_PROXY" --max-time "$PREFLIGHT_TIMEOUT" \
        "${preflight_via[@]}" \
        -w $'\nCHECK_TOR_META\t%{http_code}\t%{num_redirects}\t%{url_effective}\t%{errormsg}' \
        https://check.torproject.org/api/ip > >(probe_body_sink) 2>/dev/null
    probe_read_status
    probe_code=000 probe_redirs='' probe_final='' probe_err=''
    metadata=${${(f)"$(<"$BODY")"}[-1]}
    if [[ $metadata == CHECK_TOR_META$'\t'* ]]; then
        typeset -a metadata_fields=("${(@ps:\t:)metadata}")
        probe_code=${metadata_fields[2]:-000}
        probe_redirs=${metadata_fields[3]:-}
        probe_final=${metadata_fields[4]:-}
        (( ${#metadata_fields} >= 5 )) && probe_err="${(pj:\t:)metadata_fields[5,-1]}"
    fi
    verified=false
    [[ $(<"$BODY") == *'"IsTor":true'* ]] && verified=true
    body_bytes=$(wc -c < "$BODY") || { probe_local_failure=1; body_bytes=""; }
    body_bytes=${body_bytes//[[:space:]]/}
    probe_body_limited=0
    if [[ $body_bytes == <-> ]]; then
        probe_body_limited_known=1
        probe_body_limited=$(( body_bytes >= MAX_BODY_BYTES ))
    else
        probe_local_failure=1 probe_body_limited_known=0
    fi
else
    probe "$url" "$tag" "$timeout"
    [[ -n $tag ]] && probe_err=${probe_err//$tag/[redacted]}
    if (( ! probe_local_failure )) && check_local_transport; then
        classify
        if (( ! probe_local_failure )); then
            json_quote "$verdict"; result_verdict=$REPLY
            json_quote "$detail"; result_detail=$REPLY
        fi
    fi
fi
# Preserve transport facts already obtained even when local processing failed.
# The coordinator marks these records incomplete and stops the schedule.
if (( probe_local_failure )); then
    local_error='"local_response_processing_failed"'
elif ! check_local_transport; then
    local_error='"local_curl_setup_or_io_failed"'
fi
code=null redirs=null final=null err=null limited=false transport_exit=null
(( probe_exit_known )) && transport_exit=$probe_exit
[[ $probe_code == <-> && $probe_code != 000 ]] && code=$(( 10#$probe_code ))
[[ $probe_redirs == <-> ]] && redirs=$(( 10#$probe_redirs ))
[[ -n $probe_final ]] && { json_quote "$probe_final"; final=$REPLY; }
[[ -n $probe_err ]] && { json_quote "$probe_err"; err=$REPLY; }
(( probe_body_limited )) && limited=true
(( probe_body_limited_known )) || limited=null
printf '{"verdict":%s,"detail":%s,"http_status":%s,"curl_exit":%s,"curl_error":%s,"final_url":%s,"redirect_count":%s,"body_limited":%s,"tor_verified":%s,"local_error":%s}\n' \
 "$result_verdict" "$result_detail" "$code" "$transport_exit" "$err" "$final" "$redirs" "$limited" "$verified" "$local_error"
