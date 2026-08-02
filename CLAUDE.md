# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`check_tor` is a single `zsh` script (`check_tor.zsh`, ~280 lines — the entire codebase) written
for Project Galileo. It tests whether a list of domains is reachable over the Tor network,
surfacing WAF blocks, TLS misconfigurations, and SOCKS failures that would prevent Tor users
(e.g., at-risk journalists/activists/NGOs) from reaching those sites, and diagnoses whether a
block is Tor-specific and which WAF/CDN issued it.

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

1. Config block at the top — `TOR_PROXY` (localhost:9050), `MAX_CIRCUITS` (3), the three
   timeouts, and the spoofed browser headers. All hardcoded, no env overrides.
2. Output helpers — ANSI color vars, `print_line` (padded/aligned verdict column), and
   `transient`/`clear_transient` for `\r`-overwritten progress lines (tty-only).
3. Arg validation — requires exactly one CLI arg (path to a newline-delimited list of domains;
   blank lines and `#` comments are skipped, CRs and surrounding whitespace stripped).
4. `probe()` — one curl invocation. Writes body/headers to mktemp files (`$BODY`/`$HDRS`),
   captures `%{http_code} %{num_redirects} %{time_appconnect} %{url_effective}` into
   `probe_*` globals. Second arg is a circuit tag passed as `--proxy-user "$tag:x"` —
   Tor's default `IsolateSOCKSAuth` gives each distinct credential its own circuit;
   an empty tag means a direct clearnet request (no proxy).
5. `blocker_id()` — fingerprints the responder from `$HDRS`/`$BODY`: Cloudflare 10xx error
   codes (which appear in the *body* of an HTTP 403, never on the status line),
   `cf-mitigated: challenge`, `cf-ray`, Akamai/Sucuri/Imperva signatures. Sets `$blocker`.
6. `classify()` — sets `verdict` + `detail` from **both** the curl exit code and HTTP status,
   curl exits first: 97/5 → `SOCKS`; 60/51/35 → `CERT`; 56/52/18 → `DROP` (reset / empty reply /
   truncated transfer — silent firewall drops); 28/7 → `TIMEOUT` (detail distinguishes post-TLS stall from no
   response, via `time_appconnect`); 47 → redirect-loop `WARN`. Then HTTP: 200 → `PASS`
   (unless it landed on a `/cdn-cgi/` challenge page → `CHALLENGE`); 401/403 → `FAIL` or
   `CHALLENGE` (if managed challenge); 202 → `CHALLENGE`; 429 → `RATELIMIT`; 503 → `CHALLENGE`
   if a WAF fingerprint is present else `WARN`; anything else → `WARN`.
7. Pre-flight check — curls `https://check.torproject.org/api/ip` through the SOCKS proxy and
   greps for `"IsTor":true` (also reports the current exit IP); exits with an error telling
   the user to run `tor-on` if Tor isn't confirmed active.
8. Main loop, per target: normalize URL (`http://` → `https://`, or prepend `https://`);
   probe over Tor, retrying block-ish verdicts (`blocky()`: FAIL/CHALLENGE/RATELIMIT/DROP/
   TIMEOUT/SOCKS) on up to `MAX_CIRCUITS` fresh circuits; if still blocked, run a clearnet
   control probe and compare the two with `severity()` (PASS=0, CHALLENGE/RATELIMIT=1,
   FAIL/DROP/TIMEOUT/SOCKS=2, anything else=-1 for inconclusive). Only a strictly *lower*
   clearnet severity means Tor-specific; equal-or-worse clearnet clears the site as merely
   script-hostile, and a negative clearnet severity is reported as inconclusive but still
   listed. Prints one aligned, color-coded line per domain.
9. Summary — per-verdict counts plus a "Likely blocking or challenging Tor" list (every blocky
   verdict whose clearnet control fared better, or was inconclusive). No structured output
   format (no JSON/CSV); the script never writes files itself except its two mktemp scratch
   files (cleaned by trap).

When changing the classification logic, keep the curl-exit-code checks ahead of the
HTTP-status-code checks (a non-zero curl exit means the status-code variable is meaningless/empty),
and update the "Output Legend" and "How results are diagnosed" sections of `README.md` to match.
The script can be exercised end-to-end without a Tor daemon by putting a mock `curl` earlier in
`$PATH` that keys off the requested hostname and the presence of `--socks5-hostname`.

## Data files are not code

`targets.txt` and `scans/*.txt` (both currently untracked) are the user's real target domain
lists and dated archives of them — not fixtures or test data. Treat them as data to be read/used
as-is, not something to refactor or restructure. `targets-EXAMPLE.txt` (tracked) is the template
users are meant to copy from. `package-lock.json` is a stray, functionally unused artifact (no
`package.json` exists) — not part of the project.
