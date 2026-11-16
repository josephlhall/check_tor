<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/branding/check-tor-reverse.svg">
  <img src="assets/branding/check-tor.svg" width="128" height="128" alt="check_tor logo: an onion outline with a checkmark">
</picture>

# Tor Reachability Scanner

`check_tor` sends automated requests through a local Tor proxy and reports what
happened, including HTTP refusals, challenge-like responses, and connection
failures. If a result such as a refusal or timeout persists, the scanner can
compare the outcome with a second request outside Tor. Use Tor Browser to
check whether a person can load a page or complete a task. Curl and Tor Browser
can receive different responses or handle the same response differently.

`check_tor` is an independent volunteer project by a Tor donor and fan. It is
not affiliated with or endorsed by [The Tor Project](https://www.torproject.org/).

## Run your first scan

### Install and start Tor

Open a terminal in a checkout or an extracted [tagged release](https://github.com/josephlhall/check_tor/releases).
The scanner needs Zsh and curl on `PATH`, plus the standard utilities `awk`,
`grep`, `head`, `cut`, `tr`, `wc`, and `mktemp`.

Install and start Tor on **macOS with Homebrew**.

```zsh
brew install tor
brew services start tor
```

Use these commands on **Debian or Ubuntu**, including in a ChromeOS Linux
environment that runs services.

```zsh
sudo apt update && sudo apt install zsh tor curl
sudo service tor start
```

The scanner connects to Tor’s SOCKS proxy at `localhost:9050` by default. If your Tor
service listens elsewhere, pass `--proxy HOST:PORT` when you run the scan.

### Prepare a private target list

Keep `check_tor.zsh` and its helper files together. Store your list of sites in
a private directory outside the source tree. From the scanner directory, make
a private copy of the example list.

```zsh
umask 077
mkdir -p "$HOME/tor-targets"
cp -i targets-EXAMPLE.txt "$HOME/tor-targets/mylist.txt"
```

Edit the copy and put one domain or URL on each line. Blank lines and lines
starting with `#` are ignored. The scanner trims whitespace and requires at
least one target. It adds `https://` to bare targets and rewrites an initial
`http://` to `https://`. Curl can follow redirects from that starting URL.

### Run the scan

Pass the path to your target list.

```zsh
./check_tor.zsh "$HOME/tor-targets/mylist.txt"
```

Before requesting your targets, the scanner checks that its proxy reaches
Tor by contacting `check.torproject.org`. Some target results then trigger a
[comparison outside the configured Tor proxy](#retries-and-comparisons).
Add `--no-clearnet` to skip that comparison.

If you started Tor for this scan, stop it afterward with
`brew services stop tor` on macOS or `sudo service tor stop` on Debian or Ubuntu.

## Read the results

Start with the verdict next to each target. For example, `FAIL` means curl
received HTTP 401 or 403 without a recognized challenge signature. If the
comparison request returned `PASS`, the sampled Tor request fared worse.
Open the site in Tor Browser if you need to know whether a person can
complete a task.

### Retries and comparisons

In the default scan, the scanner retries `FAIL`, `CHALLENGE`, `RATELIMIT`,
`DROP`, `TIMEOUT`, and `SOCKS` up to the attempt limit. Each Tor attempt uses
a disposable SOCKS username to request circuit isolation. Circuits can share
an exit relay, so repeated observations can share an exit. If a later attempt
passes, the result detail records that the outcome changed.

If the final Tor result is still one of those verdicts, the default scan
makes a comparison request without the configured Tor SOCKS proxy. Curl's
environment proxy settings still apply in text mode and JSONL v1.
`HTTPS_PROXY` or `ALL_PROXY` can route the comparison through a proxy, and
`NO_PROXY` can bypass the configured Tor proxy for matching hosts. Review
those settings before using the comparison as evidence about Tor versus
direct access. Detailed mode can [set both routes
explicitly](DETAILED-OUTPUT.md#routing-and-request-configuration).

The comparison ranks `PASS` as least severe, then `CHALLENGE` and `RATELIMIT`,
then `FAIL`, `DROP`, `TIMEOUT`, and `SOCKS`. A `CERT` or `WARN` comparison is
inconclusive. The text summary groups targets where Tor fared worse and
targets with inconclusive comparisons under “Likely blocking or challenging
Tor”. Check the details for the reason each target appears there.

### Output legend

| Text label | JSON verdict | What curl observed |
| --- | --- | --- |
| `PASS` | `PASS` | Final HTTP 200 with no recognized challenge condition. |
| `CHALLENGE` | `CHALLENGE` | HTTP 202, HTTP 200/401/403 with a recognized challenge signature, HTTP 200 with `/cdn-cgi/` in the final URL, or HTTP 503 with a recognized provider or challenge signature. |
| `RATE LIMIT` | `RATELIMIT` | HTTP 429. A shared Tor exit can contribute to rate limiting. |
| `FAIL` | `FAIL` | HTTP 401 or 403 without a recognized challenge signature. |
| `DROP` | `DROP` | Receive failure, empty reply, or truncated transfer (curl `56`, `52`, or `18`). |
| `CERT ERROR` | `CERT` | Certificate verification or TLS handshake failure. |
| `SOCKS ERROR` | `SOCKS` | Proxy resolution or SOCKS handshake failure. |
| `TIMEOUT` | `TIMEOUT` | Curl timed out or could not connect. Detail indicates when curl reported a completed TLS handshake. |
| `WARNING` | `WARN` | An inconclusive outcome, such as a redirect or response-body limit, unexpected HTTP status, or other curl error. |

The scanner recognizes response signatures such as Cloudflare error codes and
challenge markers and headers associated with Akamai, Sucuri, and
Imperva/Incapsula. These markers can help identify the infrastructure serving
the final response. Responsibility for the site's policy requires separate
evidence. When a response body reaches the inspection limit, the scanner
reports `WARN` because later content may change how the response is understood.

## Options and output formats

Run `./check_tor.zsh --help` for the full command reference without starting a
scan. The following options apply to ordinary scans and detailed measurements.

| Option | Default | What it controls |
| --- | --- | --- |
| `--format text\|jsonl\|jsonl-v2` | `text` | Human-readable output, per-target JSON Lines, or per-request measurement records. |
| `--proxy HOST:PORT` | `localhost:9050` | Tor SOCKS endpoint. Use brackets around an IPv6 literal. |
| `--circuits N` | `3` | Maximum Tor attempts for failure-driven retries, from 1 to 100. |
| `--max-redirects N` | `10` | Redirects curl may follow per Tor or comparison probe, from 0 to 100. |
| `--max-body-bytes SIZE` | `1MiB` | Maximum bytes retained from each target response on either route, from 1 byte through 10 MiB. |
| `--timeout-preflight N` | `20` | Each Tor verification request’s timeout in seconds, from 1 to 3600. |
| `--timeout-first N` | `180` | First Tor attempt's timeout in seconds, from 1 to 3600. |
| `--timeout-retry N` | `180` | Later Tor attempts' timeout in seconds, from 1 to 3600. |
| `--timeout-clearnet N` | `20` | Comparison request's timeout in seconds, from 1 to 3600. |
| `--no-clearnet` | Comparison enabled | Skip the comparison request. Tor specificity then remains unknown. |

### Timeouts and request limits

The 180-second Tor target timeouts give slow requests more time to finish and
can increase scan duration. Record the effective timeouts when comparing
runs. The startup check for Tor (the preflight) has a separate timeout, set
with `--timeout-preflight N` in any output mode. It defaults to 20 seconds.
The scanner reports a terminal preflight timeout on stderr. This setting affects each
verification request and is independent of the target request timeouts.

The redirect budget excludes the initial request. With `--max-redirects 1`,
curl can reach the first redirect destination. If that destination sends
another redirect, the scanner reports an inconclusive warning and leaves
subsequent access unobserved. A terminal response within the budget keeps
its normal classification. Reaching the limit triggers neither a failure
retry nor a conditional comparison. Explicit fixed trials and always-controls
in detailed mode still apply. The Tor preflight never follows redirects.

Use `--max-body-bytes 10MiB` to inspect larger responses. Supply a whole
number of bytes (for example, `10485760`) or attach a case-insensitive
`KiB` or `MiB` suffix, as in `512KiB`. One KiB is 1,024 bytes and one MiB
is 1,048,576 bytes. The scanner applies the cap separately to each Tor and
direct target probe, including repeated trials. Reaching it is inconclusive
even when curl reports HTTP 200. Larger caps can increase download and
inspection time and temporary disk use, especially with concurrent workers.
Request timeouts still apply. Tor preflight has its own fixed 1 MiB cap and
fails verification if it reaches that cap.

### HTTPS certificate verification

Curl verifies HTTPS certificates using its configured trust store. Keep curl
and that store updated. If you need a custom CA bundle, set `CURL_CA_BUNDLE`
and, where applicable, `SSL_CERT_FILE` or `SSL_CERT_DIR`. The scanner ignores
`.curlrc`, so settings in that file do not affect its requests.

### Text and JSON Lines v1

Text mode writes the scan to stdout, including the exit IP if Tor preflight
succeeds. Transient progress and color appear only at a terminal. Set
[`NO_COLOR`](https://no-color.org/) to disable color. The scanner writes errors
to stderr, and a failed Tor preflight can leave the opening text on stdout.

Use `--format jsonl` for automation. Save the scanner output to a private
file outside the repository.

```zsh
./check_tor.zsh --format jsonl "$HOME/tor-targets/mylist.txt" \
  > "$HOME/tor-targets/results.jsonl"
```

JSONL v1 writes one JSON object per input occurrence, then a summary. A
failure before the scan begins leaves stdout empty. Both text and JSONL v1
return `0` for a completed scan regardless of the verdicts and `1` for an
invocation, input, dependency, or Tor preflight failure.

Each JSONL v1 record has `schema_version: 1` and `type: "target"` or
`type: "summary"`. Target records include:

- `target`, `verdict`, and a human-readable `detail`
- `tor_attempts` and `tor_attempt_limit`
- `clearnet_control.enabled`, `clearnet_control.performed`, and nullable
  `clearnet_control.verdict`
- `tor_specific` as `true` when the Tor result was worse, `false` when the
  control fared no better, and `null` when no conclusive comparison was made
- `body_limited` for the final Tor response's body cutoff

A completed summary has `complete: true`, `total`, every verdict in `counts`,
and `tor_specific_findings`, which counts conclusive Tor-worse comparisons.
Use the structured fields for decisions. Treat `detail` as display text.
Schema v1 may gain optional fields. Removing a field or changing its meaning
or type requires a new schema version.

### Detailed measurement output

Use `--format jsonl-v2` when you need every observation, fixed trials, or a
specific schedule for Tor and direct comparisons. This mode requires Python
3.9 or newer and uses only its standard library. This example schedules three
Tor/direct pairs per target, starting each pair with Tor.

The scheduling options in this example make the direct requests bypass
proxies set in the environment.

```zsh
./check_tor.zsh --format jsonl-v2 --trials 3 \
  --control always --control-scope trial \
  "$HOME/tor-targets/mylist.txt" > "$HOME/tor-targets/observations.jsonl"
```

The records identify which requests belong together and include timings,
redirect evidence, and a terminal run state. They also retain bounded
`Onion-Location` and onion `Alt-Svc` evidence from the final response on each
route. The scanner does not contact an advertised service. You can change
pair order, let different hostnames overlap, and pace the start of probes.
Direct requests can reveal your ordinary connection to target sites. Repeated trials can
share a Tor exit and other conditions, so treat them as repeated observations
rather than independent samples.

The optional `--execution-policy paired-cautious` prioritizes finishing
started pairs. After a completed HTTP 429 on either route, it stops pending
work for that hostname and continues with other hostnames. With fixed trials
and a comparison on every trial, `--rate-limit-stop after-pair` lets the
other request in the same pair start if it was still waiting.
A run that otherwise succeeds but omits work exits `3` and records
`state: "policy_stopped"` with `complete: false`. Check the
[cautious policy reference](DETAILED-OUTPUT.md#cautious-collection-and-completion)
before enabling it in an automated workflow.

See the [detailed output reference](DETAILED-OUTPUT.md) for the scheduling
options, routing guarantees, record fields, and how to interpret partial runs.

### Retrying Tor verification

Detailed mode normally verifies Tor once before starting targets. Opt in to
`--format jsonl-v2 --preflight-retry transient` to allow up to three
verification requests. Eligible transport failures wait 15 seconds before the
second attempt and 30 seconds before the third. Each uses the selected
`--timeout-preflight` and a fixed 1 MiB body cap. With timeout `T`, one
attempt permits up to `T` seconds of transport wait. Three attempts permit
up to `3 × T + 45` seconds including backoff, plus any extra global
`--start-gap` pacing and local process overhead. Targets start only after
completed, valid Tor verification.

Retries apply to specified transport errors when curl reports no HTTP
response. See [Tor verification and retries](DETAILED-OUTPUT.md#tor-verification-and-retries)
for the eligible errors and the records a JSONL v2 reader needs to handle.

## Handling target lists

Keep operational target lists and raw results outside the repository in a
private directory. Even when individual domains are public, their inclusion
in a list can reveal sensitive associations or research priorities. Text
output may include the observed Tor exit IP. Both JSON formats can contain
sensitive URLs or other data that identify the scan.

`targets-EXAMPLE.txt` contains public examples. Git ignores `targets.txt`,
`scans/`, and `*.private.txt`. The text and JSONL v1 scanner can warn about
tracked inputs when Git is available. Keep files outside the checkout even
if they match an ignore rule.

If a sensitive list enters Git history, stop sharing it and follow the
[incident process](ETHICS-AND-DATA-STEWARDSHIP.md#incident-response). Removing
the file in a later commit leaves earlier copies in Git history. Published
copies may also persist in clones, forks, or archives.

## Measurement validation

Start with the [offline experiment guide](EXPERIMENTS.md) to compare controlled
HTTP responses and TLS failures with scanner observations. It includes a
reusable local runner, saved-run inspection, and a capture recipe for future
authorized measurements.

The completed TACP-0.2 pilot compared scanner results with practical access in
Tor Browser. Of 26 cases, 20 strongly agreed, one scanner result was more
optimistic than the browser outcome, and five comparisons were inconclusive.
The study deliberately chose 14 endpoints to exercise different verdicts
and repeated some endpoints. Interpret these counts as evidence about the
selected cases. Estimating accuracy or blocking prevalence across sites
would require a different sample. See the [pilot
results](VALIDATION-PILOT-RESULTS.md) and [measurement
roadmap](MEASUREMENT-VALIDATION.md) for methods, limits, and follow-up.
The [reference lab qualification](reference-lab/QUALIFICATION.md) records a
later, separate set of checks on controlled examples.

### Background on the Tor timeouts

A preliminary comparison of automated Tor and direct retrieval covered
785 civil-society and technology organization hostnames. A later configuration
appeared to produce more successful observations. It raised the route budget
from 60 to 180 seconds, the redirect limit from one
to ten, and the response-body limit from 1 MiB to 10 MiB. The comparison
cannot isolate the effect of the timeout.

## Testing

Run the offline checks from the repository root with Zsh, curl, and
Python 3.9 or newer. The local TLS tests also need the `openssl` command to
generate temporary test certificates; it is not a scanner dependency. The
tests use synthetic targets and temporary files. The transport, redirect, and
TLS suites open loopback connections. No Tor process or Internet access is
needed.

```zsh
(
  set -e
  test -x check_tor.zsh
  for script in check_tor.zsh check_tor_core.zsh check_tor_probe.zsh tests/*.zsh; do
    zsh -n "$script"
  done
  zsh tests/check_tor_test.zsh
  zsh tests/check_tor_integration_test.zsh
  python3 -m unittest discover -s tests -p 'test_measurement.py'
  python3 -m unittest discover -s tests -p 'test_transport_review.py'
  python3 -m unittest discover -s tests -p 'test_redirects.py'
  python3 -m unittest discover -s tests -p 'test_retry_after.py'
  python3 -m unittest discover -s tests -p 'test_tls.py'
  python3 -m unittest discover -s tests -p 'test_inspect.py'
  git diff --check
)
```

The Zsh tests cover verdicts and the ordinary CLI. The Python tests cover
detailed measurements, transport and redirect behavior, `Retry-After` and
onion advertisement evidence, and real curl certificate validation against a
local HTTPS server.
The loopback TLS and transport tests cover certificate trust and hostname
checks, stalls during and after a TLS handshake, an empty HTTP reply, and a
server-side truncated response. The stall tests verify the stage reached on the
server and use a two-second curl deadline without asserting elapsed time. The
empty-reply test uses a clean close so the result is independent of how the OS
reports a TCP reset. TLS uses a disposable CA without changing the machine’s
trust store. These fixtures cover curl and scanner behavior on the local
connection. Live Tor and browser comparisons use a separate study protocol.

The [Offline tests workflow](.github/workflows/offline-tests.yml) runs those
suites on Ubuntu and macOS for pull requests and pushes to `main`, and can run
on demand. On macOS, it also runs the Python suites with Apple’s system
Python. A separate Ubuntu job installs nginx and exercises the optional lab
and experiment runner. The tests make no requests to public control hosts.

For interactive experiments and retained observations, follow the
[experiment guide](EXPERIMENTS.md).

The optional [local HTTPS reference lab](reference-lab/OPERATIONS.md) has its
own loopback tests. nginx is a lab dependency. Routine scanner checks use the
tools listed above.

After installing nginx, run all lab fixtures with:

```sh
python3 -m unittest discover -s reference-lab -p 'test_*.py' -v
```

These tests use local HTTPS and synthetic inputs. The
[browser-header and Tor-address conditions](reference-lab/CONDITIONS.md) and
[managed-challenge recipe](reference-lab/CHALLENGE.md) use temporary hosting
when separately approved for a live run.

## Releases and license

Use the tagged source from [GitHub
Releases](https://github.com/josephlhall/check_tor/releases). The
[release guide](RELEASING.md) documents how maintainers choose versions and
verify releases.

Created by [Joseph Lorenzo Hall](https://josephhall.org/), 2026. The project
is dedicated to the public domain under [CC0 1.0 Universal](LICENSE).

See the [branding guide](BRANDING.md) for artwork and suggested visual style.
