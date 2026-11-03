#!/usr/bin/env zsh
# Explicit network preflight; never reads target files or starts Tor.
setopt ERR_EXIT NO_UNSET PIPE_FAIL

if (( $# )); then
    if (( $# == 1 )) && [[ $1 == --help ]]; then
        print -r -- "Usage: ./scripts/check-curl-trust.zsh"
        print -r -- "Check the current PATH curl and its effective trust settings against GitHub"
        print -r -- "and four fixed eMudhra rejection controls. Uses current proxy settings."
        exit 0
    fi
    print -u2 -- "Usage: ./scripts/check-curl-trust.zsh [--help]"
    exit 1
fi

curl_bin=${commands[curl]:-}
if [[ -z $curl_bin ]]; then
    print -u2 -- "curl trust preflight: curl is unavailable."
    exit 1
fi

# Match the scanner: -q suppresses ambient curlrc credentials, cookies and
# verification overrides; PATH and CA/proxy environment settings still apply.
# Replacing its CA bundle here would prove a different trust configuration.
print -r -- "Checking effective curl trust: $curl_bin"
if ! "$curl_bin" -q --silent --show-error --fail --output /dev/null \
        --connect-timeout 10 --max-time 20 https://github.com/; then
    print -u2 -- "curl trust preflight: positive control failed; trust is unproven."
    exit 1
fi

for host in \
    dv-g3b-emudhra.we-have-a-problem.com \
    dv-g3b-aaa-emudhra.we-have-a-problem.com \
    dv-g3b-noct-emudhra.we-have-a-problem.com \
    dv-g3b-aaa-noct-emudhra.we-have-a-problem.com; do
    curl_rc=0
    "$curl_bin" -q --silent --show-error --output /dev/null \
        --connect-timeout 10 --max-time 20 "https://$host/" 2>/dev/null || curl_rc=$?
    # DNS/proxy/connection errors do not establish certificate rejection.
    if (( curl_rc != 60 )); then
        print -u2 -- "curl trust preflight: $host returned curl $curl_rc; expected certificate rejection (60)."
        exit 1
    fi
done
print -r -- "curl trust controls passed: GitHub reachable; all four affected chains rejected."
