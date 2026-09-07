# Tor Access Comparison Pilot Manifest

> **Status:** PILOT COMPLETE — PUBLIC NOTE REVIEWED; BASELINE PARITY VERIFIED
>
> **Issue:** [#33](https://github.com/josephlhall/check_tor/issues/33)
>
> **Protocol:** `TACP-0.2` (`FROZEN FOR ISSUE #33`)
>
> **Human reviewer and observer:** Joseph Lorenzo Hall
>
> **Prepared:** 2026-09-07
>
> **Live authority:** Granted by the human reviewer on 2026-09-07 under this manifest and `TACP-0.2`
>
> **Reserve authority:** Granted on 2026-09-07 for `R25` then `R26` after the primary queue produced one included `FAIL`
>
> **Collection result:** Closed after `R26`; all frozen stratum targets satisfied and `R27`-`R30` unused
>
> **Analysis authority:** Granted on 2026-09-07 for private aggregate analysis only
>
> **Public note:** [VALIDATION-PILOT-RESULTS.md](VALIDATION-PILOT-RESULTS.md)

This manifest supplies the experiment-level decisions that the frozen
[Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md) deliberately leaves
open. It governs a bounded, deliberately selected pilot. It does not estimate
Internet-wide Tor blocking prevalence, authorize unlisted endpoints, or permit
live collection before the human reviewer accepts this manifest and separately
passes the live-readiness checkpoint.

## Research question and stopping rule

The pilot asks how `check_tor` verdicts correspond to the practical access a
human observes in Tor Browser and in an ordinary clearnet browser under
`TACP-0.2`.

The primary queue contains 24 preassigned cases in four batches of six. Up to
six reserve cases may be run, in their listed order, only when:

- fewer than 20 primary cases remain includable after approved exclusions or
  halts; or
- after the primary queue, fewer than six included cases have an observed
  `PASS` verdict; or
- after the primary queue, fewer than two included cases have an observed
  `CHALLENGE` verdict or fewer than two have an observed `FAIL` verdict.

Collection stops after the 24 primary cases when neither reserve condition
applies. It always stops at 30 attempted case slots. A stopped, excluded, or
inconclusive case remains visible and is not silently replaced. Any reserve use
and its frozen trigger are recorded before the reserve case begins.

The contemporaneous scanner result defines the observed stratum. Expected
behavior supports design only and is never used to recode an observation.
Candidate screening is not permitted. If a target stratum cannot be filled
from this preapproved queue, the shortfall is a pilot limitation rather than a
reason to probe for more endpoints.

### Target allocation

The target allocation is intentionally directional because the observed
verdict is unknown until the case runs:

| Observed scanner stratum | Target | Design basis |
|---|---:|---|
| `PASS` | At least 6 | Purpose-built success cases and deliberately public ordinary content |
| `CHALLENGE` | At least 2 | Purpose-built HTTP 202 cases exercise the scanner's documented 202 semantics; ordinary cases may add ecological observations |
| `FAIL` | At least 2 | Purpose-built HTTP 403 cases exercise refusal semantics; ordinary cases may add ecological observations |
| `RATELIMIT` | Up to 2 safely obtained | Purpose-built HTTP 429 cases exercise recording but do not establish organic rate limiting |
| `DROP` | Record if naturally observed | No governed public endpoint is approved to induce a transport drop |
| `TIMEOUT` | Record if naturally observed | No governed public endpoint is approved to induce a long, potentially burdensome timeout |
| `CERT`, `SOCKS`, `WARN`, or other | Up to 4 planned plus naturally observed cases | Certificate cases preserve boundary coverage; other outcomes remain visible |

Failure to observe `DROP` or `TIMEOUT` does not activate reserve cases. Their
safe absence answers whether the current governed catalog can support those
strata and must be reported plainly.

## Host and remote observation

The Maryland Mac mini is the only measurement host. The Chromebook may be used
for planning, review, and remote control of that Mac mini. Scanner, Tor Browser,
ordinary-browser, time capture, and private storage all remain on the Mac mini;
no Chromebook-native measurement enters the pilot.

Remote observation is permitted through an owner-controlled encrypted remote
desktop session that displays and controls the Mac mini browsers. The exact
remote-control product and client version are recorded in the private
environment record at live-readiness review. Remote display latency is a known
limit on fine-grained timing and is recorded in each affected case's
uncertainty fields.

A case starts only when the observer has an uninterrupted 15-minute window and
the remote session is stable. If the remote session disconnects during a case:

1. record the last directly observed state and the disconnect time;
2. do not reconstruct timestamps or browser outcomes;
3. mark the event as a protocol deviation; and
4. halt the case when safety or comparability is affected.

Mac mini inaccessibility between cases pauses the pilot without creating a
protocol deviation. The next case keeps its assigned slot and order after
live-readiness conditions are rechecked.

## Frozen environment choice

The pilot evaluates the current default scanner behavior through explicit
settings. The values below were read on the Mac mini on 2026-09-07 and must be
reverified at Checkpoint B before any live authority is granted.

| Field | Frozen choice or current value |
|---|---|
| Scanner repository and commit | `josephlhall/check_tor` at `c11c0211dc5b6e98a78cdcc38ed95d2ce5e562a6` (`v1.4.0-12-gc11c021`) |
| JSONL schema | `1` |
| Scanner proxy | `localhost:9050` |
| Tor attempt limit | `3` |
| First/retry/clearnet timeouts | `60` / `30` / `20` seconds |
| Automated clearnet control | Enabled |
| HTTP request profile and response cap | Fixed by the scanner commit; current cap 1 MiB |
| Operating system | macOS 26.6.2 (build 25G83), arm64 |
| `zsh` | 5.9 (`arm64-apple-darwin25.0`) |
| `curl` | Apple `/usr/bin/curl` 8.7.1, reporting `x86_64-apple-darwin25.0` |
| Tor | Homebrew Tor 0.4.9.11 at `/opt/homebrew/opt/tor` |
| Tor Browser | Batch 1 used 15.0.20; batch 2 preflight found 15.0.21; stock configuration and `Standard` security level are visually reconfirmed after a version change |
| Ordinary browser | Batch 1 used Firefox 155.0; batch 2 preflight found 155.0.1; dedicated unsigned-in owner-only profile; fresh private window per case |
| Time synchronization | macOS `timed` service running; automatic-time setting must be visually reconfirmed |
| Diagnostic I5 | Disabled for every pilot case |

A change in a version or operational value is recorded at Checkpoint B. It
requires a new `TACP` revision only when it materially changes the per-case
method; otherwise the accepted current value becomes the pilot environment
record. Scanner code and JSONL schema remain unchanged during collection.

Before batch 2, the human reviewer accepted the Tor Browser 15.0.21 and Firefox
155.0.1 patch releases as batch-specific environment drift that does not alter
the frozen method. Records preserve the versions per batch, and analysis treats
the drift as a comparability limitation rather than silently pooling it away.

## Private storage and retention

Checkpoint B creates and verifies this owner-only tree outside the repository;
the exact local root is recorded only in the untracked checkpoint ledger and
the approved private environment record:

```text
issue-33-private-root/
  structured/
  raw/
    firefox-profile/
    tor-data/
    torrc
```

The root, both data directories, and the dedicated Firefox profile use mode
`0700`. Joseph Lorenzo Hall is the only approved person with access. The root
must be excluded from Time Machine before collection, and the exclusion must be
reverified after creation. No other sync or backup service may cover it.

The task-specific `torrc` fixes the SOCKS listener at `127.0.0.1:9050`, keeps
the Tor data directory under `raw/`, and uses `AvoidDiskWrites 1`. Tor remains
stopped until live authority; its configuration is verified offline at
Checkpoint B.

Each case uses one external target file and one restricted JSONL destination in
`raw/`. Raw JSONL, stderr, target files, Tor state, browser state, and any other
transient artifact are deleted after the structured row passes its audit and
no later than 30 days after collection. Structured observations remain through
issue #33 review and are deleted or formally extended within 90 days after
that review closes. Deletion records name the tier, date, and covered location
without reproducing content.

Screenshots and free-form raw notes are disabled. Credentials, cookies, tokens,
packet captures, unrestricted traces, personal form data, observed exit IPs,
and unrelated private content are not collected. Any accidental prohibited or
unexpectedly replicated material invokes the incident process in
[ETHICS-AND-DATA-STEWARDSHIP.md](ETHICS-AND-DATA-STEWARDSHIP.md).

## Endpoint packet

Every endpoint below is deliberately public. Purpose-built entries rely on the
authorization and stewardship basis already documented in
[REFERENCE-ENDPOINTS.md](REFERENCE-ENDPOINTS.md). The eight ordinary-content
entries come from `targets-EXAMPLE.txt`; their inclusion, association, public
task, and limits require the human approval of this manifest.

`HTTPBIN-STATUS-202` is a pilot-local proposed catalog entry for
`https://httpbin.org/status/202`. It uses the same purpose-built public
`/status/:code` service and documentation basis as the governed 403 and 429
entries. The official httpbin documentation was rechecked on 2026-09-07 and
states that this route returns the requested status code. Its expected scanner
result is `CHALLENGE` because the frozen scanner classifies HTTP 202 that way.
A browser's stable empty 202 response is recorded under the rubric without
calling it an interactive challenge.

| Entry | Approved start URL | Public task and navigation | Authorization and association | Interaction limit |
|---|---|---|---|---|
| `HTTPBIN-LINKS-2` | `https://httpbin.org/links/2` | Identify the simple public content; follow the first displayed first-party link | Purpose-built public client-test service; low publication sensitivity | One scanner invocation; one direct load and one first-party link per browser; one protocol reload at most |
| `HTTPBIN-STATUS-202` | `https://httpbin.org/status/202` | Record the stable response; navigation not applicable | Purpose-built public client-test service; low publication sensitivity; documentation eligibility verified 2026-09-07 | One scanner invocation and one direct load per browser; no navigation; one protocol reload at most |
| `HTTPBIN-STATUS-403` | `https://httpbin.org/status/403` | Record the stable response; navigation not applicable | Purpose-built public client-test service; low publication sensitivity | One scanner invocation and one direct load per browser; no navigation; one protocol reload at most |
| `HTTPBIN-STATUS-429` | `https://httpbin.org/status/429` | Record the stable response; navigation not applicable | Purpose-built public client-test service; low publication sensitivity; not evidence of organic rate limiting | One scanner invocation and one direct load per browser; no navigation; one protocol reload at most |
| `TLS-EXPIRED-BADSSL` | `https://expired.badssl.com/` | Record the certificate boundary; do not bypass a warning; navigation not applicable | Purpose-built public browser-test service; low publication sensitivity | One scanner invocation and one direct load per browser; no warning bypass or reload |
| `TLS-SELF-SIGNED-BADSSL` | `https://self-signed.badssl.com/` | Record the certificate boundary; do not bypass a warning; navigation not applicable | Purpose-built public browser-test service; low publication sensitivity | One scanner invocation and one direct load per browser; no warning bypass or reload |
| `TORPROJECT-HOME` | `https://www.torproject.org/` | Identify meaningful homepage content; follow one visible first-party About link | Deliberately public ordinary content from the repository example list; association approved only through this manifest; publication sensitivity requires final review | One scanner invocation; one direct load and one first-party navigation per browser; one protocol reload at most |
| `EFF-HOME` | `https://www.eff.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget |
| `WIKIPEDIA-PORTAL` | `https://www.wikipedia.org/` | Identify the language portal; follow the visible English Wikipedia first-party link | Same ordinary-content basis; final association review required | Same global case budget |
| `INTERNET-ARCHIVE-HOME` | `https://archive.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget; no search, media playback, login, or download |
| `MOZILLA-HOME` | `https://www.mozilla.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget; no download |
| `LETS-ENCRYPT-HOME` | `https://letsencrypt.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget |
| `IETF-HOME` | `https://www.ietf.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget |
| `PROPUBLICA-HOME` | `https://www.propublica.org/` | Identify meaningful homepage content; follow one visible first-party About link | Same ordinary-content basis; final association review required | Same global case budget; no newsletter, donation, login, or form interaction |

The ordinary-content set spans independent public-interest, standards,
knowledge, archival, and software operators. Edge or WAF provider is recorded
as `unknown` unless supported by public evidence reviewed before collection.
This pilot does not probe for provider identity or force a provider quota.
Missing Cloudflare, Akamai, Imperva/Incapsula, Sucuri, custom-WAF, or no-obvious-
WAF coverage is reported as a limitation rather than inferred from page
appearance or filled through extra traffic.

### Eligibility and expectation record

The verification date below records a review of the stated authorization and
selection evidence. It is not a live outcome or a guarantee that the endpoint
will behave as expected. Checkpoint B repeats the eligibility review without
using unplanned requests; the contemporaneous case remains authoritative.

| Entry or group | Expected behavior and principal confounder | Stability and statefulness | Verification basis and date | Retirement trigger |
|---|---|---|---|---|
| `HTTPBIN-LINKS-2` | Scanner expected `PASS`; browsers expected to complete the simple public task; service availability and redirects may change | Expected low statefulness | Governed catalog record based on httpbin operator documentation; reviewed 2026-09-07, catalog verification 2026-08-29 | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `HTTPBIN-STATUS-202` | Scanner expected `CHALLENGE`; browsers may show a stable empty response rather than an interactive challenge, making semantic interpretation central | Expected low statefulness; deliberate response does not establish WAF behavior | [Official httpbin route documentation](https://github.com/postmanlabs/httpbin/blob/master/httpbin/templates/httpbin.1.html) reviewed 2026-09-07 | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `HTTPBIN-STATUS-403` | Scanner expected `FAIL`; browsers expected to observe the deliberate refusal; no operator intent is inferred | Expected low statefulness | Governed catalog record based on httpbin operator documentation; reviewed 2026-09-07, catalog verification 2026-08-29 | Same governed catalog trigger |
| `HTTPBIN-STATUS-429` | Scanner expected `RATELIMIT`; browsers expected to observe the deliberate status; this is not organic rate limiting | Expected low statefulness | Governed catalog record based on httpbin operator documentation; reviewed 2026-09-07, catalog verification 2026-08-29 | Same governed catalog trigger |
| `TLS-EXPIRED-BADSSL` | Scanner expected `CERT`; browsers expected to stop at a certificate boundary; warning presentation and timing may differ | Purpose-built but behavior can change without notice | Governed catalog record based on badssl public project documentation; reviewed 2026-09-07, catalog verification 2026-08-28 | Operator withdrawal, changed purpose, unexpected content, or stewardship stop |
| `TLS-SELF-SIGNED-BADSSL` | Scanner expected `CERT`; browsers expected to stop at a certificate boundary; warning presentation and timing may differ | Purpose-built but behavior can change without notice | Governed catalog record based on badssl public project documentation; reviewed 2026-09-07, catalog verification 2026-08-28 | Same governed catalog trigger |
| Eight ordinary-content entries | No verdict, WAF, Tor policy, or browser outcome is presumed; content, dependencies, geography, and edge treatment may change | Current statefulness unknown; no prior state may be retained | Repository-owned `targets-EXAMPLE.txt` safe-example designation and public-task proportionality reviewed 2026-09-07; final association and navigation review is the human Checkpoint A decision | Operator request, loss of deliberately public status, unexpected content, unavailable approved navigation, or stewardship stop |

Public operator/contact references remain those in the governed catalog for
httpbin and badssl. For ordinary content, use the operator's published contact
or abuse path only when response is necessary; do not generate contact traffic
as part of eligibility screening.

## Preassigned cases, order, and batches

`S-T-O` means scanner, Tor Browser, ordinary browser. `T-S-O` means Tor Browser,
scanner, ordinary browser. Each batch balances three cases of each order. A
repeated endpoint receives the opposite primary order on its second planned
observation.

| Slot | Batch | Entry | Order | Role |
|---|---:|---|---|---|
| P01 | 1 | `HTTPBIN-LINKS-2` | S-T-O | Purpose-built success |
| P02 | 1 | `HTTPBIN-STATUS-403` | T-S-O | Purpose-built refusal |
| P03 | 1 | `HTTPBIN-STATUS-202` | S-T-O | Purpose-built 202 semantics |
| P04 | 1 | `TORPROJECT-HOME` | T-S-O | Ordinary public content |
| P05 | 1 | `TLS-EXPIRED-BADSSL` | S-T-O | Certificate boundary |
| P06 | 1 | `EFF-HOME` | T-S-O | Ordinary public content |
| P07 | 2 | `HTTPBIN-STATUS-429` | S-T-O | Purpose-built 429 semantics |
| P08 | 2 | `WIKIPEDIA-PORTAL` | T-S-O | Ordinary public content |
| P09 | 2 | `TLS-SELF-SIGNED-BADSSL` | S-T-O | Certificate boundary |
| P10 | 2 | `INTERNET-ARCHIVE-HOME` | T-S-O | Ordinary public content |
| P11 | 2 | `MOZILLA-HOME` | S-T-O | Ordinary public content |
| P12 | 2 | `LETS-ENCRYPT-HOME` | T-S-O | Ordinary public content |
| P13 | 3 | `HTTPBIN-LINKS-2` | T-S-O | Repeated purpose-built success |
| P14 | 3 | `HTTPBIN-STATUS-403` | S-T-O | Repeated purpose-built refusal |
| P15 | 3 | `HTTPBIN-STATUS-202` | T-S-O | Repeated purpose-built 202 semantics |
| P16 | 3 | `TORPROJECT-HOME` | S-T-O | Repeated ordinary content |
| P17 | 3 | `TLS-EXPIRED-BADSSL` | T-S-O | Repeated certificate boundary |
| P18 | 3 | `EFF-HOME` | S-T-O | Repeated ordinary content |
| P19 | 4 | `HTTPBIN-STATUS-429` | T-S-O | Repeated purpose-built 429 semantics |
| P20 | 4 | `WIKIPEDIA-PORTAL` | S-T-O | Repeated ordinary content |
| P21 | 4 | `TLS-SELF-SIGNED-BADSSL` | T-S-O | Repeated certificate boundary |
| P22 | 4 | `INTERNET-ARCHIVE-HOME` | S-T-O | Repeated ordinary content |
| P23 | 4 | `IETF-HOME` | T-S-O | Ordinary public content |
| P24 | 4 | `PROPUBLICA-HOME` | S-T-O | Ordinary public content |
| R25 | Reserve | `HTTPBIN-STATUS-202` | S-T-O | Frozen `CHALLENGE` reserve |
| R26 | Reserve | `HTTPBIN-STATUS-403` | T-S-O | Frozen `FAIL` reserve |
| R27 | Reserve | `HTTPBIN-LINKS-2` | S-T-O | Frozen includable-case reserve |
| R28 | Reserve | `TORPROJECT-HOME` | T-S-O | Frozen ordinary-content reserve |
| R29 | Reserve | `IETF-HOME` | S-T-O | Frozen ordinary-content reserve |
| R30 | Reserve | `PROPUBLICA-HOME` | T-S-O | Frozen ordinary-content reserve |

Run one case at a time. Do not reorder cases to chase a verdict. If a case is
excluded or halted, continue with the next assigned slot only after the human
reviews whether the same safety concern affects it. A batch closes only after
every attempted row is audited and transient raw artifacts are minimized.

## Per-case procedure and timestamp capture

Every case follows `TACP-0.2`, including New Identity before Tor Browser, a
fresh private ordinary-browser window, at most one protocol-defined reload,
and the fixed public task. The optional I5 diagnostic remains disabled.

The coordinator captures each instrument start immediately before releasing
the action and captures its end immediately after the stable outcome report.
Use UTC ISO 8601 timestamps from the Mac mini. Browser timing fields measure
the observed Mac mini state; remote latency and any uncertainty are recorded
separately. If action-time capture fails, use null and record the available
coordinator bounds as a deviation. Never reconstruct timing from screenshots,
files, or memory.

Before closing a case:

1. record the paired-window end and any deviation;
2. close the private Firefox window and verify the task-specific Firefox
   process is stopped when the batch ends;
3. audit every required structured field, including null versus false and the
   nested browser objects;
4. preserve scanner JSON values exactly; and
5. delete the case's transient raw files after the row passes audit.

## Batch and pause rules

Each batch contains six planned cases and may be split across days. Stop only
between fully normalized cases unless a halt condition requires an immediate
stop. At each batch gate, the human reviewer checks:

- case approval, actual order, and the 15-minute paired window;
- exact primary-instrument timestamps or an explicit deviation;
- scanner fields copied without recoding;
- separate Tor Browser and ordinary-browser outcomes and uncertainty;
- endpoint interaction limits and any stop signals;
- owner-only permissions and Time Machine exclusion;
- row-audit completion and raw-artifact deletion; and
- whether the remaining approved cases are still safe and useful.

A pause for travel, Mac mini downtime, or owner availability is ordinary. On
resume, recheck repository commit, environment versions, Tor and browser state,
time sync, private-root protection, backup exclusion, endpoint eligibility,
order, and the next case files before starting the next case.

## Live-readiness gate

Checkpoint B must pass every item below before the human separately grants live
authority:

- the manifest status and approval record are current;
- scanner commit, clean scanner files, explicit settings, and JSONL schema are
  verified;
- macOS, `zsh`, `curl`, Tor, Tor Browser, security level, extensions, Firefox,
  and dedicated-profile state are verified;
- the `timed` service and automatic-time setting are verified;
- the issue #33 private root exists with `0700` permissions, correct ownership,
  separate directories, and confirmed Time Machine exclusion;
- the remote-control product/path, observer location, and stable-session rule
  are recorded;
- endpoint authorization, association, public tasks, and interaction limits
  remain approved; the `HTTPBIN-STATUS-202` documentation check passed on
  2026-09-07;
- batch-one case records and one-case raw-file paths are prepared outside Git;
- screenshots, free-form raw notes, and I5 remain disabled;
- the contact mailbox and incident path are available; and
- the human reviewer states explicit authority for live issue #33 collection.

Approval of this manifest advances only to live-readiness review. It does not
by itself authorize a request to any endpoint.

## Analysis and publication gate

Private analysis recomputes the verdict/access matrix from audited structured
rows and separates `STRONG_AGREEMENT`, `ACCEPTABLE_SEMANTIC_AGREEMENT`, scanner
optimism, scanner pessimism, uncertainty, and deviations. Mechanisms remain
hypotheses unless directly established. Counts are conditional on deliberately
selected strata and are never presented as prevalence.

The public note may contain reviewed aggregate counts, the matrix, sanitized
descriptions whose association is safe, limitations, and warranted follow-up.
It must not contain private rows, raw JSONL, observed IPs, screenshots, session
data, private paths, or sensitive targets. The human reviewer approves every
public association, causal label, policy statement, and publication claim.

## Approval record

- Manifest decision: Accepted for live-readiness preflight
- Reviewer: Joseph Lorenzo Hall
- Decision date (UTC): 2026-09-07
- Amendments: Batch-specific Tor Browser 15.0.21 and Firefox 155.0.1 patch-version drift accepted before batch 2; method unchanged
- Live-readiness decision: Checkpoint B accepted on 2026-09-07
- Live collection authority: Granted on 2026-09-07 under this manifest and `TACP-0.2`
- Continuation authority: Each six-case batch still requires its own human gate
- Primary collection decision: Checkpoint C4 accepted on 2026-09-07; P22 retained as included `INCONCLUSIVE` without rerun
- Reserve trigger: One included primary case produced `FAIL`, below the frozen minimum of two
- Reserve collection authority: Granted on 2026-09-07 for `R25` followed by `R26` only; stop before analysis
- Reserve collection decision: Checkpoint C5 completed on 2026-09-07; `R25` observed `CHALLENGE`, `R26` observed `FAIL`, all frozen stratum targets are satisfied, and collection stopped with `R27`-`R30` unused
- Analysis authority: Granted on 2026-09-07 through the Checkpoint D resume gate for private aggregate analysis only; that gate did not itself authorize public-note construction
- Analysis decision: Accepted on 2026-09-07 through the Checkpoint E resume gate without amendment
- Public-note construction authority: Granted on 2026-09-07 for sanitized aggregate findings and maintained-document reconciliation only; at that gate, final review, issue mutation, and shipping remained gated
- Public-note review: Checkpoint E2 accepted on 2026-09-07 after a presentation correction; aggregate findings and public associations accepted without substantive amendment
- Final proof: Completed on 2026-09-07 with fresh source-to-public, privacy, link, rendering, syntax, core-suite, and baseline-parity integration evidence; issue mutation and shipping remain gated
