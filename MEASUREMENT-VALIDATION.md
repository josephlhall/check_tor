# Validating the `check_tor` Measurement Model

`check_tor` reports how websites respond to automated requests over Tor. This
research asks how those reports relate to a person's ability to use the same
site in Tor Browser, and where the scanner's language needs qualification.

The first pilot completed 26 deliberately selected cases across 14 endpoints.
It found 20 strong agreements, one case where the scanner reported `PASS` but
Tor Browser could not reach meaningful content, and five inconclusive
comparisons. All three `CHALLENGE` cases used synthetic HTTP 202 responses;
none demonstrated a visible browser challenge. These findings identify limits
worth investigating, but the selected and repeated cases cannot estimate
general accuracy or the prevalence of Tor blocking. The
[pilot report](VALIDATION-PILOT-RESULTS.md) gives the counts and interpretation.

This document explains the research direction and how to find its evidence.
The completed studies retain their original methods. The approved next
protocol, `TACP-0.4`, prepares reference experiments but does not authorize
endpoint construction, outreach, screening, or collection.

## Find the method or evidence

| Reader's question | Authoritative document |
|---|---|
| What did the first pilot find? | [Pilot calibration results](VALIDATION-PILOT-RESULTS.md) |
| How were its cases chosen and scheduled? | [Completed pilot manifest](VALIDATION-PILOT-MANIFEST.md) |
| What procedure and fields governed that pilot? | [Frozen `TACP-0.2` protocol](VALIDATION-PROTOCOL.md) |
| What did the earlier five-case dry run change? | [Dry-run evidence and freeze decision](VALIDATION-DRY-RUN.md) |
| What rules would govern the next reference observations? | [Prospective `TACP-0.4` protocol](VALIDATION-REFERENCE-PROTOCOL.md) |
| Which reference conditions are planned, and what remains to prepare? | [Reference experiment packet](VALIDATION-REFERENCE-PACKET.md) |
| How are endpoints described and reviewed? | [Reference endpoint catalog](REFERENCE-ENDPOINTS.md) |
| What interactions and data handling are permitted? | [Ethics and data-stewardship policy](ETHICS-AND-DATA-STEWARDSHIP.md) |
| What can today's scanner record? | [Detailed measurement output](DETAILED-OUTPUT.md) and the [README](README.md) |

## Next research steps

[Issue #39](https://github.com/josephlhall/check_tor/issues/39) completed the
`TACP-0.3` protocol and reference packet, approved on 2026-09-25. The owner
approved `TACP-0.4` on 2026-11-07 to clarify when observations advance, how
delays are measured, and how matching browser outcome categories compare.
The [revision history](VALIDATION-REFERENCE-PROTOCOL.md#revision-history)
preserves the earlier method. The protocol and packet specify
five conditions: normal navigation, an intelligible HTTP 202 page, an
authorized challenge, client-dependent refusal, and a Tor-versus-clearnet
difference. Each condition needs an expectation supported independently of
the scanner result, such as operator documentation or a reviewed endpoint
configuration. That prevents selecting cases merely because they yield the
verdict being tested.

The next steps are:

1. [Qualify a first batch in issue #41](https://github.com/josephlhall/check_tor/issues/41).
   Select normal navigation and at least one substantive reference condition.
   Record the exact tasks, permissions, environment, private storage, order,
   traffic limits, and the owner's readiness decision. Conditions needing
   construction or permission may remain deferred; construction and outreach
   require separate authorization.
2. [Collect and report that batch in issue #42](https://github.com/josephlhall/check_tor/issues/42)
   only after #41's prerequisites and explicit live authority are satisfied.
   Account for every attempted, unavailable, and halted case; audit private
   observations and publish only reviewed, sanitized findings.

The reference packet limits the planned experiment to at most seven analytic
cases across at most five condition endpoints. A missing condition remains
visible rather than being replaced after outcomes are known. Timing or
classification questions must be resolved through a reviewed prospective
protocol revision before collection, without recoding the completed pilot.

Later work may examine additional verdicts, repeated dates, browser security
levels, edge providers, or agreement between reviewers. Same-exit comparisons
or selected exit regions would need a separately reviewed design and changes
to the current restrictions. Expand only when the remaining question and the
meaning of the added variation are clear.

## The central measurement question

Four related questions require different evidence:

1. Does the server accept HTTP traffic from Tor exits?
2. Does it treat automated Tor traffic worse than comparable automated non-Tor traffic?
3. Can a person using Tor Browser reach meaningful content and complete a public task?
4. Is that person materially disadvantaged compared with an ordinary browser user?

The scanner directly supports automated comparisons in question 2. Its default
policy retries certain failures and, if they persist, sends a control without
the configured Tor SOCKS proxy. In legacy modes, environment proxy settings
still affect that route; the [README](README.md#read-the-results) explains the
comparison limits. Questions 3 and 4 require browser observations. Tor Browser's TLS and HTTP
fingerprints, JavaScript, cookies, session state, and rendering differ from
curl's behavior, even when curl sends browser-like headers.

For example, repeated HTTP 403 responses can establish refusal of the sampled
automated requests while Tor Browser completes the public task. That result
may call for clearer verdict language rather than a classifier change. Human
challenge solving remains prohibited in the approved study; a hypothetical
browser capability does not authorize exercising it.

## Measurement principles

### Validate claims against the task

A verdict is useful when its wording describes the observed request and its
limits. Evaluate scanner optimism and pessimism separately: optimism can hide
a barrier to Tor Browser users, while pessimism can overstate a site-wide
block. Neither repeated refusals nor an edge signature establishes an
operator's intent.

Browser outcomes distinguish normal completion, completion with friction,
severely degraded use, blocking under the permitted actions, and inconclusive
evidence. Define the public task before collection and apply the exact rubric
in the chosen protocol. The historical and prospective protocols have distinct
rules; this summary does not replace either one.

### Compare the clients within a bounded window

Pair scanner observations with Tor Browser and an ordinary non-Tor browser.
The ordinary browser shows whether the same problem also affected that
observed non-Tor session; one comparison cannot establish what every visitor
would experience. Record exact UTC times because origin health,
rate limits, challenges, and exit reputation can change between observations.

Requests can also affect later results. Preassign scanner/browser order and
keep volume low so that the test is less likely to induce a rate limit or
change session state. Record delays, deviations, and missing observations
instead of adding unplanned requests to obtain a complete comparison.

### Distinguish real-world comparison from causal explanation

The scanner and Tor Browser may use different exits, and the protocol does
not verify whether they match. Comparing them around the same time addresses
practical access under ordinary conditions;
it does not isolate exit reputation from client behavior. Distinct circuits
also do not guarantee distinct exits.

Record agreement separately from explanations. Client behavior, exit
reputation, timing, or origin state may explain a disagreement, but they remain
competing hypotheses unless independent evidence isolates the cause. A later
same-exit experiment could help answer some of these questions; it is outside
the approved comparison protocols.

### Freeze decisions before observing outcomes

Record the scanner commit and settings, software versions, browser security
level, task, order, attempts, timing limits, inclusion rules, and observation
fields before collection. Preserve deviations explicitly. Changing a rule to
fit an observed result undermines the comparison even if the resulting labels
appear more consistent.

## Current measurement capabilities

Detailed records and scheduling policies shipped in
[PR #55](https://github.com/josephlhall/check_tor/pull/55), completing issues
#51–#53. The approved `TACP-0.4` preparation still specifies JSONL v1; it has not
been migrated to detailed output or a new schedule. The completed `TACP-0.2`
pilot also retains its original instrument and findings.

The optional `--execution-policy paired-cautious` schedule prioritizes ready
partners and omits further work for an input hostname after an explicit HTTP
429. Those omissions are missing observations, not measured negative responses
or replacement trials. Detailed records distinguish a shortened schedule from
full coverage and scanner failure. Bounded `Retry-After` evidence records
server metadata with explicit clock limitations; it cannot establish when
access will succeed. Offline tests establish this policy's software behavior,
not its calibration against browser access.

## Optional detailed scanner observations

The opt-in `--format jsonl-v2` contract preserves individual automated requests,
run lifecycle, effective settings, and explicit target/trial/pair identities.
[Detailed measurement output](DETAILED-OUTPUT.md) defines that instrument and
its fixed-trial, control-order, routing, concurrency, and pacing policies.
The existing text and JSONL v1 interfaces and default stopping rules remain
available. Neither the new format nor its scheduling options amend frozen
`TACP-0.2` or retroactively add evidence to the completed pilot.

Fixed trials retain successful as well as unsuccessful observations. They do
not make repeated requests statistically independent. Paired paths are
sequential, their start-to-start gap is recorded, and late or missing partners
remain visible. A shared target-level control is not a matched control for
every trial. Native verdicts remain automated curl outcomes, not browser
access claims or evidence of deliberate site policy.

The configurable redirect boundary (`--max-redirects`, default ten) counts
redirects followed after the initial request. Zero and one enable bounded
observations. If curl stops because another redirect would exceed that budget,
`WARN` means subsequent access was not observed; it establishes neither a loop
nor inaccessibility nor Tor blocking. Terminal responses reached within the
budget keep their usual classification. Intentional stops do not trigger
failure retries or conditional controls; fixed trials and always-controls keep
their explicit schedules, and preflight remains separate.

Detailed records preserve bounded, sanitized followed-hop evidence and an
unvisited next destination where available, alongside the native final visited
URL, HTTP status, and redirect count. Evidence quality and missing/truncated
metadata are explicit; an unvisited destination has no observed response.
[The output contract](DETAILED-OUTPUT.md#redirect-observations) defines the
finite bounds and sensitive query/fragment handling. Freeze the chosen redirect
limit prospectively for new studies. Synthetic offline chain/contact tests
establish software behavior only; they add no live findings or evidence to
frozen protocols or completed pilots.

Bounded workers share Tor and network capacity. Global pacing controls the
coordinator's top-level probe invocations, including preflight; it does not
bound redirect hops, packet starts, or aggregate traffic to a provider reached
through several hostnames. New scheduling policies use explicit reproducible
proxy routing while preserving TLS trust configuration. Legacy mode records
inherited routing as uncertain rather than asserting that a nominal direct
request necessarily bypassed every configured proxy.

Offline fixtures establish record and scheduling behavior, including failure
and interruption handling. They do not establish live-site accuracy, distinct
exit relays, browser equivalence, or calibration of any new collection design.
Future governed measurement must freeze its chosen settings and protocol
prospectively. Raw detailed output remains sensitive and belongs outside the
repository; it contains no response bodies or exit-IP enrichment.

## Completed studies and their records

| Date | Completed work | Evidence |
|---|---|---|
| 2026-08-30 | Issue #32 established the measurement contract, endpoint catalog, ethics policy, and five-case dry run under `TACP-0.1`; one post-run revision produced frozen `TACP-0.2`. | [Dry-run report](VALIDATION-DRY-RUN.md) and [protocol revision history](VALIDATION-PROTOCOL.md#revision-history) |
| 2026-09-07 | Issue #33 completed the stratified 26-case manual pilot, private review, and public calibration report under `TACP-0.2`. | [Manifest](VALIDATION-PILOT-MANIFEST.md) and [results](VALIDATION-PILOT-RESULTS.md) |
| 2026-09-25 | Issue #39 completed the prospective `TACP-0.3` method and reference-condition preparation. | [Original protocol](https://github.com/josephlhall/check_tor/blob/ec80623c2ec737ee2aecfc70eae99ca8e02bf602/VALIDATION-REFERENCE-PROTOCOL.md) and [packet](https://github.com/josephlhall/check_tor/blob/ec80623c2ec737ee2aecfc70eae99ca8e02bf602/VALIDATION-REFERENCE-PACKET.md) |
| 2026-11-07 | The owner approved `TACP-0.4` for future observations, clarifying timing and comparison by browser outcome category. | [Revision history](VALIDATION-REFERENCE-PROTOCOL.md#revision-history) |

The five-case dry run tested whether the procedure could be followed and what
fields were missing. It was not an accuracy study. The subsequent pilot used
a deliberately stratified design, balanced scanner/browser order, and a frozen
observation window. Its reviewer recorded browser outcomes, classified
agreement, and considered competing explanations without changing the scanner
mid-pilot. The evidence did not justify a classifier change.

The earlier roadmap's draft flat observation form and execution checklist have
been superseded by the linked protocol and manifest. Those documents preserve
the exact fields, instrument settings, queues, revisions, and approval records
used in the completed studies. New scanner options do not amend those records.

## Questions that remain

The pilot answered some of its original questions only within the selected
cases. Its [interpretation by verdict](VALIDATION-PILOT-RESULTS.md#interpretation-by-verdict)
explains the evidence and its limits:

- `PASS` did not guarantee Tor Browser task completion. The one optimistic
  case leaves client, exit, and other causal explanations unresolved.
- The three synthetic HTTP 202 cases did not test visible challenge friction
  or whether a browser could pass a genuine challenge.
- The deliberate `FAIL`, `RATELIMIT`, and certificate-error cases blocked both
  browsers, so they did not establish differential treatment of Tor users.
- The pilot did not observe `DROP`, `TIMEOUT`, browser friction, severely
  degraded access, or scanner pessimism. Those remain coverage gaps.

A useful follow-up should explain which gap it addresses, how the new
observations could distinguish alternatives, and what would remain unknown.
Possible outputs include clearer verdict descriptions, an interpretation
guide, examples of recurring disagreements, and regression tests for any
verified deterministic bug. Change classification code only when evidence
identifies a correctable problem; maximizing agreement with this small sample
is not a research objective.

## Data handling and repository boundaries

The [stewardship policy](ETHICS-AND-DATA-STEWARDSHIP.md) controls endpoint
eligibility, permitted interactions, traffic budgets, storage, retention,
incidents, and publication. Each live study needs its own approved scope and
authority; earlier dry-run or pilot approval does not extend to later work.

Use deliberately selected public validation cases or authorized controlled
endpoints. Non-public operational or historical lists are ineligible. Keep raw
JSONL, screenshots, browser notes, observed IP addresses, and other restricted
artifacts outside this repository. An ignored directory inside the checkout is
not an acceptable private study-data root.

Commit only methods, reviewed aggregate findings, and deliberately public case
descriptions whose association is safe to disclose. Do not publish private
endpoints, cookies, tokens, credentials, personal information, or raw records.
Approve storage and retention before collection, and keep request volume and
interactions within the selected protocol.

## Model-assisted interpretation

Models may help organize approved evidence and suggest hypotheses for human
review. Useful tasks include drafting verdict explanations, grouping repeated
disagreements, identifying missing case coverage, proposing falsifiable
follow-up questions, and checking that each interpretation separates direct
observations from inferences. A consistent case summary can include the
scanner verdict, browser outcomes, likely and alternative explanations,
confidence, and any proposed follow-up.

An earlier planning proposal suggested a review after each 5–10 paired
observations, retaining well-supported hypotheses for follow-up. This was not
an adopted change to the frozen methods. Any future workflow must follow the
chosen protocol and the [model-use data rules](ETHICS-AND-DATA-STEWARDSHIP.md#model-assisted-work).
Models must not receive restricted raw artifacts or other data not approved
for that model and purpose. Human review remains authoritative for browser
classification, causal claims, protocol changes, and publication.

## What success looks like

The research succeeds when users understand what the scanner measures, how its
verdicts relate to browser access, and which conclusions the evidence cannot
support. A repeatable procedure, an interpretation guide grounded in actual
observations, and a clear reason to pursue or decline further collection are
useful outcomes even when the scanner code does not change.

## Curl trust qualification

Before new measurements, run `scripts/check-curl-trust.zsh` in the measurement
shell and require success before invoking the scanner, as described in the
README. It tests the selected curl and CA environment with one positive and
four affected-chain negative controls; transport failures do not prove distrust.
The preflight is separate from Tor measurements and makes no target requests.
Both commands ignore `.curlrc` to prevent ambient credentials, disabled TLS
verification, or a changed request profile. Environment CA/proxy settings still
apply and must remain the same between qualification and measurement.

This is an operational prerequisite for future measurements, not new
calibration evidence. Existing pilot findings retain their historical runtime
and protocol context; no live rerun or broader trust validation is established
by the offline trust-control tests.

## Initial hypotheses by verdict

This table preserves the initial planning hypotheses and descriptions. It is
historical context, not the current verdict reference or a set of validated
predictions. In particular, a challenge-like HTTP response need not present a
browser challenge, and a SOCKS failure need not originate at the exit. Use the
[README verdict reference](README.md#output-legend) for current software
behavior and the [pilot results](VALIDATION-PILOT-RESULTS.md) for observed
browser outcomes.

| `check_tor` verdict | What the scanner directly observed | Initial human-experience hypothesis |
|---|---|---|
| `PASS` | A successful automated response over Tor after redirects, possibly after an earlier exit-specific problem | Strong predictor that Tor Browser reaches meaningful content and completes the public task |
| `CHALLENGE` | The edge returned a recognizable challenge or challenge-like response | Predictor of user friction; browser may solve or pass the challenge |
| `RATELIMIT` (`RATE LIMIT` in text output) | HTTP 429 over Tor | Predictor of unreliable or severely degraded access, especially on shared exits |
| `FAIL` | Repeated HTTP 401/403 responses across the configured Tor attempts | Strong evidence that automated Tor requests are refused; may overstate complete human blocking |
| `DROP` | Connection reset, empty reply, or truncated transfer | Predictor of serious impairment; browser behavior may still differ |
| `TIMEOUT` | No timely meaningful response | Predictor of degradation, but sensitive to patience, protocol, origin health, and exit conditions |
| `CERT` (`CERT ERROR` in text output) | TLS certificate validation prevented an HTTP exchange | Likely user-visible security failure, though browsers may present different interstitial behavior |
| `SOCKS` (`SOCKS ERROR` in text output) | The Tor exit could not complete the connection | Often exit-specific or network-specific rather than evidence of site policy |
| `WARN` (`WARNING` in text output) | The result fell outside a confident classification | Should remain inconclusive unless manual review establishes a recurring pattern |
