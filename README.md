# Tor Reachability Scanner

A `zsh` utility script for Project Galileo that probes a list of domains through
a local Tor SOCKS proxy. It classifies automated HTTPS outcomes such as HTTP
refusals, challenge-like responses, TLS failures, and SOCKS failures. For a
persistent block-like result, an automated clearnet control can show whether
the Tor request fared worse. Recognized response signatures can suggest the
edge or WAF involved; they do not by themselves establish site policy or human
Tor Browser usability. By Joseph Lorenzo Hall, PhD
(<https://josephhall.org/>)

## Prerequisites & Installation

This script requires `zsh`, `curl`, and a local `tor` proxy to run.

### For macOS
1. **Install dependencies via Homebrew:**
   ```zsh
   brew install tor
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your `~/.zshrc` for easy proxy management:
   ```zsh
   alias tor-on='brew services start tor'
   alias tor-off='brew services stop tor'
   alias tor-stat='brew services info tor'
   alias tor-reset='brew services restart tor'
   ```

### For Linux / ChromeOS (Debian/Ubuntu)
1. **Install dependencies via APT:**
   ```zsh
   sudo apt update && sudo apt install zsh tor curl -y
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your shell profile (e.g., `~/.zshrc`) to map to the system service:
   ```zsh
   alias tor-on='sudo service tor start'
   alias tor-off='sudo service tor stop'
   alias tor-stat='sudo service tor status'
   alias tor-reset='sudo service tor restart'
   ```

*Run `source ~/.zshrc` to apply any alias changes.*

## Setup

1. Place `check_tor.zsh` somewhere convenient, and copy `targets-EXAMPLE.txt` to create your own list. Keep real target lists **outside** this repository—see [Handling target lists](#handling-target-lists).
2. Make the script executable:
   ```zsh
   chmod +x check_tor.zsh
   ```

## Usage

1. **Start the Tor proxy:**
   Ensure your local proxy is running on `localhost:9050` before scanning the Internet.
   ```zsh
   tor-on
   ```

2. **Populate your target list:**
   Copy `targets-EXAMPLE.txt` and add the domains you want to test, one per line. The script will automatically format them to enforce `https://`. Blank lines and lines starting with `#` are ignored.
   ```zsh
   mkdir -p ~/tor-targets
   cp targets-EXAMPLE.txt ~/tor-targets/mylist.txt
   emacs ~/tor-targets/mylist.txt
   ```

3. **Run the scanner:**
   Pass your text file as an argument to the script.
   ```zsh
   ./check_tor.zsh ~/tor-targets/mylist.txt
   ```

   Exactly one readable target file is required. A file containing only blank
   lines and comments is rejected before the scanner contacts Tor. Run
   `./check_tor.zsh --help` to see the command contract without starting Tor.

   For automation, select JSON Lines explicitly:

   ```zsh
   ./check_tor.zsh --format jsonl ~/tor-targets/mylist.txt
   ```

   The scanner keeps its established behavior unless options override it:

   | Option | Default | Accepted value |
   |---|---:|---|
   | `--proxy` | `localhost:9050` | SOCKS proxy as `HOST:PORT` |
   | `--circuits` | `3` | `1`–`100` Tor attempts |
   | `--timeout-first` | `60` | `1`–`3600` seconds |
   | `--timeout-retry` | `30` | `1`–`3600` seconds |
   | `--timeout-clearnet` | `20` | `1`–`3600` seconds |
   | `--no-clearnet` | off | Skip the non-Tor control request |

   For example, this uses a different local SOCKS port, tries two circuits,
   and skips the clearnet comparison:

   ```zsh
   ./check_tor.zsh --proxy localhost:9150 --circuits 2 --no-clearnet \
     ~/tor-targets/mylist.txt
   ```

   Without the clearnet control, persistent block-like results still describe
   what the automated Tor requests observed, but Tor specificity remains
   unknown. The scanner's HTTP request profile and 1 MiB response inspection
   cap are intentionally fixed; these settings do not make `curl` impersonate
   Tor Browser.

4. **Stop the Tor proxy (when finished):**
   ```zsh
   tor-off
   ```

### Output, color, and exit status

Scan results and progress are written to stdout. Invocation, input, dependency,
and Tor preflight failures are written to stderr. This allows redirected output
to contain scan results without mixing in fatal diagnostics.

Color is enabled when stdout is an interactive terminal. Redirected output is
plain text. Set [`NO_COLOR`](https://no-color.org/) to any value to disable
color explicitly:

```zsh
NO_COLOR=1 ./check_tor.zsh ~/tor-targets/mylist.txt
```

Exit status `0` means the scan completed, even if it found blocked or degraded
targets. Exit status `1` means the command could not complete because invocation,
input, a required command, or the Tor preflight failed.

### Machine-readable output

`--format jsonl` writes one JSON object per target followed by one summary
object. It emits no banner, transient progress, ANSI styling, or prose summary.
Fatal errors remain on stderr and exit with status `1`; if scanning cannot
begin, stdout is empty. Findings in a completed scan retain status `0`.

Each object contains `"schema_version": 1` and a `type` of `target` or
`summary`. Target records include:

* `target`, `verdict`, and a human-readable `detail`
* `tor_attempts` and `tor_attempt_limit`
* `clearnet_control.enabled`, `performed`, and its nullable `verdict`
* nullable `tor_specific`, which is `true` or `false` only after a conclusive
  clearnet comparison
* `body_limited`, which distinguishes the response-body cutoff from other
  `WARN` results

The final summary has `complete: true`, the total, every verdict count, and the
number of Tor-specific findings. Consumers should branch on structured fields,
not parse `detail`. New optional fields may be added within schema version 1;
removing a field or changing its meaning or type requires a new schema version.

JSONL output contains the scanned targets and is sensitive operational data.
Store it outside this repository with restrictive permissions; do not add it to
Git or place it under a publicly accessible path.

## Measurement limitations and validation

`check_tor` measures how sites respond to automated `curl` requests over Tor;
its verdicts are not validated claims about human Tor Browser usability. It
does not reproduce Tor Browser's TLS and browser fingerprint, JavaScript,
cookies, session state, or interactive challenge behavior. The next
methodological work is to calibrate scanner verdicts against paired manual
observations in Tor Browser and an ordinary non-Tor browser—not to begin
continuous feature expansion. See
[MEASUREMENT-VALIDATION.md](MEASUREMENT-VALIDATION.md) for the living research
plan. The protocol freeze and dry run are tracked in
[issue #32](https://github.com/josephlhall/check_tor/issues/32); the subsequent
stratified pilot is tracked in
[issue #33](https://github.com/josephlhall/check_tor/issues/33) and depends on
that frozen protocol.

## Releases and versioning

`check_tor` is released software and uses annotated Semantic Versioning tags
(`vMAJOR.MINOR.PATCH`). Use patch for backward-compatible fixes or material
documentation corrections, minor for backward-compatible capabilities, and
major for incompatible public CLI, behavior, or structured-output contract
changes. An issue's release-impact classification predicts the appropriate next
version when a release is cut; closing an issue never creates a tag by itself.

A release may deliberately collect a coherent accepted issue set. Tag only the
final verified commit after that complete scope passes the offline suites.
Normally publish a GitHub Release for a `check_tor` tag so users and future
contributors receive a curated change summary; if a tag is intentionally only
a source checkpoint, record that decision before tagging.

## Testing

All tests are deterministic and offline. They use synthetic `.example.test`
targets and temporary files; they never inspect `targets.txt`, `scans/`, or
`*.private.txt`. You do not need a running Tor proxy or Internet access.

The repository has two complementary suites:

* `tests/check_tor_test.zsh` exercises the decision logic directly, including
  curl and HTTP classification, WAF fingerprints, retry eligibility, severity,
  and Tor-versus-clearnet comparisons.
* `tests/check_tor_integration_test.zsh` invokes `check_tor.zsh` as a user would.
  It places a controlled fake `curl` first in `PATH` to test argument failures,
  source-safe loading, target parsing and normalization, circuit retries,
  clearnet controls, validated setting overrides, output summaries, curl
  arguments, and temporary-file cleanup without reaching the network.

Run the complete local validation from the repository root:

```zsh
test -x check_tor.zsh
zsh -n check_tor.zsh check_tor_core.zsh tests/*.zsh
zsh tests/check_tor_test.zsh
zsh tests/check_tor_integration_test.zsh
git diff --check
```

A successful run reports `All 66 offline checks passed.` and
`All 128 offline integration checks passed.` The **Offline tests** GitHub Actions
workflow runs the same syntax and test commands on Ubuntu and macOS for every
pull request and push to `main`; it can also be started manually.

## Handling target lists

**Do not commit real target lists.** A list of domains being checked for Tor reachability is a list of organizations that believe they are at risk and are seeking protection they do not yet have. Each domain is individually public, but the curated set is not—published, it is a pre-filtered reconnaissance aid that also implies which organizations are currently unprotected.

Three things in this repository exist to prevent that:

* `targets-EXAMPLE.txt` ships well-known public sites and deliberate TLS test endpoints, so the example list is safe to scan and to publish.
* `targets.txt`, `scans/`, and `*.private.txt` are gitignored, so a real list does not become a commit by accident.
* The script prints a warning if the target file you pass it is tracked by git.

The safest arrangement is to keep real lists entirely outside the repository:

```zsh
mkdir -p ~/tor-targets
cp targets-EXAMPLE.txt ~/tor-targets/mylist.txt
./check_tor.zsh ~/tor-targets/mylist.txt
```

If a real list has already been committed, deleting it in a new commit is **not** enough—it stays in history and is retrievable with one command. Rewriting history (`git filter-repo --invert-paths --path <file>`) and force-pushing is the minimum, and you should assume anything public for a meaningful period may already have been cloned, forked, or archived independently.

## How results are diagnosed

The script does more than fetch a status code:

* **Multiple attempts before treating a result as persistent.** A block-like
  result (FAIL, CHALLENGE, RATE LIMIT, DROP, TIMEOUT, SOCKS ERROR) is retried up
  to the configured attempt limit. Disposable SOCKS usernames request circuit
  isolation without a ControlPort, but they do not prove that every attempt
  used a distinct exit. Persistence across the sampled attempts is therefore
  not proof of a site-wide policy. A later PASS is reported with a note that
  the automated observation was circuit-dependent.
* **An automated clearnet control, compared by severity.** A result that
  remains block-like across the Tor attempts is re-tested with `curl` *without*
  Tor. The built-in severity ordering determines whether the Tor result was
  strictly worse, no worse, or inconclusive. This comparison can support a
  `tor_specific` inference about the paired automated requests; it does not
  substitute for an ordinary-browser or Tor Browser usability comparison.
* **Blocker fingerprinting.** Response headers and bodies are inspected for
  recognized Cloudflare error codes (1020 firewall rule, 1015 rate limit,
  1006/1007/1008 IP ban—these ride inside an HTTP 403, not on the status line),
  `cf-mitigated: challenge` (managed challenge), Akamai, Sucuri, and
  Imperva/Incapsula signatures. These signatures identify likely response
  infrastructure or mechanisms, not necessarily who selected the policy.
  Response-body inspection is limited to the first 1 MiB per probe. If a body
  reaches that limit, the result is an inconclusive warning rather than block
  evidence; a fingerprint appearing only later in the response may be missed.
* **Summary.** Text output ends with per-verdict counts and a manual-review
  list. That list includes results where the automated clearnet control fared
  better as well as results whose control was inconclusive. In JSONL, use the
  nullable `tor_specific` field for each target and
  `tor_specific_findings` for the count of conclusive Tor-worse comparisons.

## Output Legend

The script evaluates `curl` exit codes, HTTP status codes, and response contents to provide specific diagnostics:

* **[PASS]** (Green): The final automated response was HTTP 200 after following
  redirects. If earlier attempts were block-like, the detail records that the
  observed result changed across attempts. This does not establish rendered or
  interactive browser usability.
* **[CHALLENGE]** (Cyan): The response matched a challenge-like condition: a
  Cloudflare managed challenge (403 + `cf-mitigated`), a recognized WAF-backed
  503, an async queue (202), or a 200 ending on a `/cdn-cgi/` challenge page.
  Whether a human Tor Browser session can pass it remains a validation
  question.
* **[RATE LIMIT]** (Yellow): The automated Tor response was HTTP 429. Shared
  exit use can contribute to rate limiting, but the verdict alone does not
  identify intent or establish the human browser outcome.
* **[FAIL]** (Red): The final automated Tor attempts returned HTTP 401 or 403.
  A recognized response signature is included when available. Consult the
  clearnet-control fields before inferring that the refusal was Tor-specific.
* **[DROP]** (Red): `curl` reported a receive failure (exit 56), empty reply
  (exit 52), or truncated transfer (exit 18). The verdict records the transport
  symptom without proving whether a firewall, origin, exit, or transient
  network condition caused it.
* **[CERT ERROR]** (Purple): `curl` could not complete certificate validation or
  the TLS handshake, so no usable HTTP response was classified.
* **[SOCKS ERROR]** (Red): `curl` could not resolve the configured SOCKS proxy
  or complete its proxy/SOCKS handshake. This diagnoses the proxy path, not a
  destination-site policy.
* **[TIMEOUT]** (Yellow): `curl` timed out or could not establish the
  connection. When available, the detail distinguishes a stall after TLS from
  a failure before any response; the causal explanation remains uncertain.
* **[WARNING]** (Yellow): Anything else—including unexpected status codes,
  redirect loops, unusual `curl` failures, and the intentional response-body
  cutoff—is left for manual triage.

## License

This project is dedicated to the public domain under CC0 1.0 Universal. See the `LICENSE` file for details.
