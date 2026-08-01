# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`check_tor` is a single `zsh` script (`check_tor.zsh`, ~70 lines — the entire codebase) written
for Project Galileo. It tests whether a list of domains is reachable over the Tor network,
surfacing WAF blocks, TLS misconfigurations, and SOCKS failures that would prevent Tor users
(e.g., at-risk journalists/activists/NGOs) from reaching those sites.

There is no build system, package manager, test suite, linter, or CI in this repo — there is
nothing to build/lint/test. The only "command" is running the script itself:

```zsh
chmod +x check_tor.zsh
./check_tor.zsh <file_with_urls.txt>   # e.g. ./check_tor.zsh targets.txt
```

This requires a local Tor SOCKS proxy running on `localhost:9050` (start via a `tor-on` alias
documented in README.md, or `brew services start tor` / `sudo service tor start`).

## Contribution policy

Per `CONTRIBUTING.md`, this repo is **not accepting outside contributions, feature requests, or
pull requests** — it's published CC0 as an as-is utility. Do not propose opening a PR against
this repo; if the user wants changes, just make them directly (or suggest forking if they ask
about upstreaming).

## Architecture / control flow

Everything lives in `check_tor.zsh`. Reading it top to bottom is the whole mental model:

1. `TOR_PROXY="localhost:9050"` (line 4) — the only config value, hardcoded, no env override.
2. Arg validation — requires exactly one CLI arg (path to a newline-delimited list of domains).
3. Pre-flight check — curls `https://check.torproject.org/api/ip` through the SOCKS proxy and
   greps for `"IsTor":true` before scanning anything; exits with an error telling the user to
   run `tor-on` if Tor isn't confirmed active.
4. Main loop — reads the target file line by line:
   - Normalizes each URL: `http://` → `https://`, or prepends `https://` if no scheme is given.
   - Fetches just the HTTP status code via `curl -o /dev/null -w "%{http_code}"`, routing DNS
     through SOCKS5 (`--socks5-hostname`), following redirects (`-L`), spoofing a Chrome/Windows
     User-Agent + Accept headers (to avoid trivial WAF/bot-fingerprint false positives), with a
     60s timeout.
   - Classifies the result from **both** the curl exit code and HTTP status code, in this
     priority order: curl exit 97 → `SOCKS ERROR`; curl exit 60/51/35 → `CERT ERROR`; curl exit
     28/7 → `TIMEOUT`; HTTP 200/301/302/307/308 → `PASS`; HTTP 403/1020/401 → `FAIL` (likely a
     WAF blocking Tor); HTTP 202 → `CHALLENGE` (WAF JS challenge / async queue, e.g. Cloudflare);
     anything else → `WARNING` (prints both codes for manual triage).
   - Output is color-coded via inline ANSI escapes; there's no structured output format (no
     JSON/CSV) and the script never writes files itself.

When changing the classification logic, keep the curl-exit-code checks ahead of the
HTTP-status-code checks (a non-zero curl exit means the status-code variable is meaningless/empty),
and update the "Output Legend" section of `README.md` to match.

## Data files are not code

`targets.txt` and `scans/*.txt` (both currently untracked) are the user's real target domain
lists and dated archives of them — not fixtures or test data. Treat them as data to be read/used
as-is, not something to refactor or restructure. `targets-EXAMPLE.txt` (tracked) is the template
users are meant to copy from. `package-lock.json` is a stray, functionally unused artifact (no
`package.json` exists) — not part of the project.
