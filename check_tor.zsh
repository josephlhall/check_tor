#!/usr/bin/env zsh

# Set this to the IP and port of your Tor SOCKS proxy
TOR_PROXY="localhost:9050"

# 1. Check if a file argument was provided
if [[ -z "$1" ]]; then
    echo "Usage: ./check_tor.zsh <file_with_urls.txt>"
    exit 1
fi

# 2. Verify the file actually exists
if [[ ! -f "$1" ]]; then
    echo "Error: File '$1' not found."
    exit 1
fi

echo "Performing pre-flight check on the Internet to ensure Tor is running..."
tor_check=$(curl -s --socks5-hostname "$TOR_PROXY" --max-time 10 https://check.torproject.org/api/ip)

if [[ "$tor_check" == *"\"IsTor\":true"* ]]; then
    echo "[\033[32mSUCCESS\033[0m] Tor connection verified! Starting domain scan..."
else
    echo "[\033[31mERROR\033[0m] Tor connection failed. Did you remember to run 'tor-on'?"
    exit 1
fi

echo "---------------------------------------------------------"

# 3. Read the provided file line by line
while IFS= read -r url || [[ -n "$url" ]]; do
    # Skip any empty lines in the text file
    [[ -z "$url" ]] && continue
    
    # Auto-format: Upgrade http:// to https://, or add https:// if missing entirely
    url=${url/#http:\/\//https:\/\/}
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi

    # Fetch just the HTTP status code, routing DNS through the SOCKS5 proxy
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --socks5-hostname "$TOR_PROXY" --max-time 30 "$url")
    curl_exit_code=$?
    
    if [[ $curl_exit_code -eq 97 ]]; then
        echo "[\033[31mSOCKS ERROR\033[0m] $url (Tor connection to host failed)"
    elif [[ $curl_exit_code -eq 60 || $curl_exit_code -eq 51 || $curl_exit_code -eq 35 ]]; then
        echo "[\033[35mCERT ERROR\033[0m] $url (Invalid or expired SSL Certificate)"
    elif [[ $curl_exit_code -eq 28 || $curl_exit_code -eq 7 ]]; then
        echo "[\033[33mTIMEOUT\033[0m] $url (Connection dropped/timed out)"
    elif [[ "$http_code" == "200" || "$http_code" == "301" || "$http_code" == "302" || "$http_code" == "308" ]]; then
        echo "[\033[32mPASS\033[0m] $url (Status: $http_code)"
    elif [[ "$http_code" == "403" || "$http_code" == "1020" || "$http_code" == "401" ]]; then
        echo "[\033[31mFAIL\033[0m] $url (Status: $http_code - Likely blocking Tor)"
    else
        echo "[\033[33mWARNING\033[0m] $url (Status: $http_code, cURL exit: $curl_exit_code)"
    fi
done < "$1"

echo "---------------------------------------------------------"
echo "Scan complete."
