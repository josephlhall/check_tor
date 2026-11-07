# Tor Reachability Scanner

A `zsh` utility script that probes a list of domains through a local Tor SOCKS
proxy. It classifies automated HTTPS outcomes such as HTTP
refusals, challenge-like responses, TLS failures, and SOCKS failures. For a
persistent block-like result, an automated clearnet control can show whether
the Tor request fared worse. Recognized response signatures can suggest the
edge or WAF involved; they do not by themselves establish site policy or the
practical access available to a human Tor Browser user. By Joseph Lorenzo Hall, PhD
(<https://josephhall.org/>)

## Prerequisites & Installation

This script requires `zsh`, `curl`, and a local `tor` proxy to run. At runtime
it also uses standard command-line utilities (`awk`, `grep`, `head`, `cut`,
`tr`, `wc`, and `mktemp`), which are available by default on supported macOS
and Debian/Ubuntu installations. The optional `--format jsonl-v2` measurement
mode additionally requires Python 3.9 or newer (standard library only).

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

1. Keep `check_tor.zsh`, `check_tor_core.zsh`, and `scripts/` together; detailed mode also needs `check_tor_probe.zsh` and `check_tor_measure.py` alongside them. Copy `targets-EXAMPLE.txt` to create your own list. Keep real target lists **outside** this repository—see [Handling target lists](#handling-target-lists).
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

3. **Qualify curl trust and run the scanner:**
   Run the explicit trust controls in the same shell and environment as the
   measurement. Continue only if they pass:
   ```zsh
   ./scripts/check-curl-trust.zsh && ./check_tor.zsh ~/tor-targets/mylist.txt
   ```

   This preflight makes five HTTPS requests using current proxy settings: GitHub is the positive
   control, and four fixed `emudhra.we-have-a-problem.com` subdomains must fail
   with curl certificate-verification status 60. DNS, proxy, timeout, and other
   transport failures leave trust unproven and stop the command. It never
   starts Tor or reads your targets. The scanner does not run these external
   controls implicitly.

   The check uses the actual `curl` selected by `PATH` and its CA/proxy
   environment, without substituting a different CA bundle. Both the checker
   and scanner suppress `.curlrc` with `-q`; ambient cookies, credentials,
   `insecure`, and request-profile changes from that file are ignored. Configure
   any intended CA bundle through `CURL_CA_BUNDLE` (and, where relevant,
   `SSL_CERT_FILE`/`SSL_CERT_DIR`) in the same environment for both commands.
   Repeat qualification after changing curl, CA files, the host, or that
   environment. A passing result covers these controls, not all TLS security.

   The [upstream runner-image incident](https://github.com/actions/runner-images/issues/15228)
   affected macOS system and stale Homebrew trust independently. Follow
   [Apple's affected-root guidance](https://support.apple.com/en-us/149555)
   and verify the curl you will actually use. The checker reports failure
   without changing host trust.

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
   | `--max-redirects` | `10` | `0`–`100` redirects followed per target/control probe |
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
   unknown. The scanner's browser-like headers and 1 MiB response inspection
   cap are intentionally fixed; these settings do not make `curl` impersonate
   Tor Browser.

   Redirect counting excludes the initial request. With `--max-redirects 0`,
   only that request is made; with `1`, one redirect may be followed. A terminal
   response reached exactly within the budget keeps its normal classification.
   If another redirect would need following, the scanner reports an inconclusive
   warning: access beyond that boundary is unobserved, and a finite chain can
   reach the limit just as a cycle can. This stop does not cause failure-driven
   retries or conditional clearnet controls. Detailed mode still honors explicit
   fixed trials and always-controls. Tor preflight keeps its separate policy
   of following no redirects.

   [Detailed output](DETAILED-OUTPUT.md#redirect-observations) adds bounded,
   sanitized hop evidence and the next destination left unvisited. Text and
   JSONL v1 keep their existing schemas and report the stop in human detail.

4. **Stop the Tor proxy (when finished):**
   ```zsh
   tor-off
   ```

### Output, color, and exit status

Scan output and progress are written to stdout. Invocation, input, dependency,
and Tor preflight failures are written to stderr. This allows redirected output
to capture completed scan output without mixing in fatal diagnostics.

In text mode, a successful Tor preflight reports the current exit IP on stdout.
Treat captured text output accordingly. JSONL mode emits no preflight prose or
exit IP, but its target records remain sensitive operational data.

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

### Detailed requests, fixed trials, and bounded concurrency

`--format jsonl-v2` preserves individual requests and explicit run start/end
records. With no new policy options, it observes the existing failure retries
and conditional controls. `--trials` selects a fixed number of observations;
`--control always --control-scope trial` pairs a direct control with each Tor
trial, including successful ones. Optional ordering, a recorded seed, partner-gap
flags, bounded target workers, and global probe-start pacing support repeatable
schedules. All these policies retain the existing probe and classifier.

This mode requires Python 3.9+ and has its own versioned contract. It does not
change text output or JSONL v1. Read [Detailed measurement output](DETAILED-OUTPUT.md)
for examples, supported combinations, record identities, routing guarantees,
clock and interruption semantics, and limits on interpreting paired results.
Missing terminal records mean incomplete runs, not successful completion.

## Measurement limitations and validation

`check_tor` measures how sites respond to automated `curl` requests over Tor;
its verdicts are not guarantees about practical access in Tor Browser. It does
not reproduce Tor Browser's TLS and browser fingerprint, JavaScript, cookies,
session state, or interactive challenge behavior.

A deliberately stratified 26-case manual pilot under `TACP-0.2` produced
initial calibration evidence: 20 strong agreements, one scanner-optimistic
case, and five inconclusive comparisons. Those selected, repeated cases are not
an accuracy score or prevalence estimate. See the sanitized
[pilot calibration results](VALIDATION-PILOT-RESULTS.md) and
[MEASUREMENT-VALIDATION.md](MEASUREMENT-VALIDATION.md) for interpretation and
follow-up. The governed protocol packet and procedural records are available in
the
[Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md),
[ethics and data-stewardship policy](ETHICS-AND-DATA-STEWARDSHIP.md), and
[reference-endpoint catalog](REFERENCE-ENDPOINTS.md), with dry-run evidence in
[VALIDATION-DRY-RUN.md](VALIDATION-DRY-RUN.md) and the issue #33 experiment
design in [VALIDATION-PILOT-MANIFEST.md](VALIDATION-PILOT-MANIFEST.md).
The [prospective reference protocol](VALIDATION-REFERENCE-PROTOCOL.md) and
[preparation packet](VALIDATION-REFERENCE-PACKET.md) record issue #39's
owner-approved methodological preparation; they grant no live authority.
`TACP-0.2` remains the methodological basis for the completed pilot. The closed
[issue #32](https://github.com/josephlhall/check_tor/issues/32) tracks the
protocol freeze and dry run; [issue #33](https://github.com/josephlhall/check_tor/issues/33)
tracks the completed pilot; [issue #39](https://github.com/josephlhall/check_tor/issues/39)
tracks the prospective preparation.

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

## Trust-control maintenance

The `macos-latest` CI job builds a temporary CA bundle from preinstalled
Apple and Homebrew PEM stores. It requires Apple’s bundle and valid, complete
certificates and excludes the two roots identified by DER SHA-256 in the
incident's [public root list](https://emudhra.we-have-a-problem.com/roots.json).
The bundle and empty CA directory are scoped to checkout and its Git guard.
Checkout's Node runtime selects the filtered OpenSSL store with
`--use-openssl-ca`.

Before checkout, Apple curl uses runner defaults to reach GitHub and must reject
all four incident chains. A separate guard resolves the same PATH Git as
checkout, applies the filtered settings, and requires a successful public
GitHub query and certificate-specific rejection of all four incident chains.
The Git guard uses an empty working directory and home, ignores ambient Git
configuration, credentials and proxies, and prohibits redirects and interactive
authentication. Either guard can stop the job before checkout. GitHub provisions
the runner and acquires actions before these steps. After checkout, Linux and
macOS check the effective measurement curl with runner defaults.

Offline regression checks for the filter and preflight use Python 3, public
root fixtures, and fake curl and Git responses. Python 3 is needed for these
maintenance tests and CI bootstrap, and Python 3.9+ is also
required for detailed `--format jsonl-v2` scanning. Text and JSONL v1 scanning
do not require Python. Run these tests with the complete offline validation
sequence below.

The public root fixtures in `tests/fixtures/distrusted-roots.pem` are the
emSign ECC Root CA-G3 and AAA Certificate Services roots, identified against
the incident root list. `retained-root.pem` is a public root used to exercise
OpenSSL’s PEM parser offline. These fixtures are test data, never a configured
CA bundle.
Hosted execution of these workflow controls is required before claiming the
runner mitigation has been verified in GitHub Actions.

A separate [default-trust workflow](.github/workflows/macos-tls-defaults.yml)
checks the runner's preinstalled TLS clients without checkout, installation,
CA overrides, or trust repair. It runs manually or for pull requests that change
its workflow or offline tests. It checks Apple clients, clients selected by PATH,
and installed standard Homebrew clients, recording the runner image and client
versions. Every client must reach the positive control and reject all four
incident chains; acceptance and inconclusive network failures fail the run.
Results continue to be collected after individual failures.

The November 6, 2026 qualification passed for all eight Apple, PATH, and
Homebrew clients on the ARM64 `macos-26-arm64` image `20261102.0473.1`
(macOS 26.7.2, build `25G332`). The ordinary job used the same image revision,
selected `/usr/bin/curl` and `/opt/homebrew/bin/git`, and found zero affected
roots in the PEM files it filtered.
[Default-trust run](https://github.com/josephlhall/check_tor/actions/runs/42311169871/job/128212690512)
and [ordinary run](https://github.com/josephlhall/check_tor/actions/runs/42323039298/job/128251831777).

The upstream issue closed after the image rollout.
[November 6 closure comment](https://github.com/actions/runner-images/issues/15228#issuecomment-6691723697).

Retiring the remaining checkout settings requires
the runner-bundled Node runtime selected by the pinned checkout action and its
HTTPS transport, plus checkout's PATH Git, to pass a legitimate HTTPS control
and certificate-specific rejection of all four incident chains with default
trust on the relevant hosted image and architecture. Record the image and
client versions and verify ordinary hosted checkout after removing the settings.
The existing qualification covers curl, Git and Python on ARM64. GitHub's
runner provisioning and action acquisition need separate provider evidence.

## Testing

The regression suites are deterministic and offline. They use synthetic
`.example.test` targets and temporary files; they never inspect `targets.txt`, `scans/`, or
`*.private.txt`. You do not need a running Tor proxy or Internet access.

The repository has seven complementary suites:

* `tests/check_tor_test.zsh` exercises the decision logic directly, including
  curl and HTTP classification, WAF fingerprints, retry eligibility, severity,
  and Tor-versus-clearnet comparisons.
* `tests/check_tor_integration_test.zsh` invokes `check_tor.zsh` as a user would.
  It places a controlled fake `curl` first in `PATH` to test argument failures,
  source-safe loading, target parsing and normalization, circuit retries,
  clearnet controls, validated setting overrides, output summaries, curl
  arguments, and temporary-file cleanup without reaching the network.
* `tests/test_measurement.py` checks detailed records, trial/control policies,
  routing, seeded ordering, global pacing, worker limits, cancellation, and
  output failures using synthetic per-request fake-curl fixtures. Live readers
  see only atomically published JSON records. An explicit bounded barrier
  establishes worker overlap, and separate signal fixtures check cancellation
  without carrying a failed case's processes into the next case.
* `tests/test_redirects.py` models redirect chains with a separate synthetic
  destination-contact log. It checks follow limits, exact-budget terminal
  responses, both routes and all formats, relative URLs, cycles, hostile
  metadata, redaction, and retained-evidence bounds. A separate real-curl HTTP
  fixture checks native URL resolution and actual contact boundaries using
  dynamically allocated loopback ports, explicit hostname mappings, disabled
  proxies, and DNS-free server setup.
* `tests/test_transport_review.py` uses real curl with local `file://` fixtures
  to check literal URL handling, plus fake-curl fixtures for detailed request
  configuration and classifier failures. It does not exercise real connection
  faults; additional real connection-failure coverage remains tracked in
  [issue #47](https://github.com/josephlhall/check_tor/issues/47).
* `tests/test_curl_trust.py` checks the macOS bundle filter against the two
  public affected roots and verifies positive-control and certificate-specific
  negative-control handling with fake curl and Git clients, including connection
  failures and credential/configuration isolation.
* `tests/macos_tls_defaults_test.py` validates the separate default-trust probe
  offline, without contacting control hosts or modifying trust stores.

Run the complete local validation from the repository root:

```zsh
test -x check_tor.zsh
zsh -n check_tor.zsh check_tor_core.zsh check_tor_probe.zsh scripts/*.zsh tests/*.zsh
zsh tests/check_tor_test.zsh
zsh tests/check_tor_integration_test.zsh
python3 -m unittest discover -s tests -p 'test_measurement.py'
python3 -m unittest discover -s tests -p 'test_transport_review.py'
python3 -m unittest discover -s tests -p 'test_redirects.py'
python3 -m unittest discover -s tests -p 'test_curl_trust.py'
python3 -m unittest discover -s tests -p 'macos_tls_defaults_test.py'
git diff --check
```

A successful run reports passing Zsh checks and a Python unittest `OK` result.
The **Offline tests** GitHub Actions workflow runs the same syntax and test
commands on Ubuntu and macOS for every pull request and push to `main`; it can
also be started manually. Its separate trust qualification steps make the five
fixed HTTPS curl control requests and, on macOS, five Git control queries before
running the offline suites.

## Handling target lists

**Do not commit real target lists.** Operational target lists can reveal
sensitive associations, selection criteria, or research priorities even when
individual domains are public. Inclusion does not establish an organization’s
protection status or participation in any program.

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
  substitute for an ordinary-browser or Tor Browser access comparison.
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
  interactive browser access or task completion.
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
  redirect follow limits, unusual `curl` failures, and the intentional response-body
  cutoff—is left for manual triage.

## License

This project is dedicated to the public domain under CC0 1.0 Universal. See the `LICENSE` file for details.
