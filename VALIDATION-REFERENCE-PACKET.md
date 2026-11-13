# Task-Based Reference Experiment Preparation Packet

The existing normal-navigation candidate can advance to readiness review.
The readable HTTP 202 fixture is available locally. It needs live deployment,
operator permission, and qualification. The other three conditions still need
construction or permission and may be deferred. The owner approved offline
preparation with a budget of zero remote requests. A later manifest must identify the endpoints and receive
explicit authority before live preflight or collection.

> **Issue:** [#39](https://github.com/josephlhall/check_tor/issues/39)
>
> **Protocol:** [`TACP-0.4`](VALIDATION-REFERENCE-PROTOCOL.md)
>
> **Status:** APPROVED PREPARATION PACKET — no live authority
>
> **Owner approval:** Original preparation approved 2026-09-25 UTC. The
> `TACP-0.4` timing and browser-comparison revision was approved 2026-11-07;
> condition dispositions and the planning budget remain unchanged.
>
> **Scanner baseline reviewed:** `567faea7ab4e65ebdc8d3176169e98d5ab4ff8d5`

In the [completed pilot](VALIDATION-PILOT-RESULTS.md), none of the 26
deliberately selected cases produced browser `FRICTION` or
`SEVERELY_DEGRADED`. All three `CHALLENGE` cases used purpose-built HTTP 202
responses, and the only observed Tor Browser disadvantage coincided with
scanner `PASS`. Those findings explain why the packet proposes the
conditions below. The expected outcomes are hypotheses for a later study.

The preparation uses the scanner's schema version 1 output (`--format jsonl`),
a 1 MiB target-body cap on both routes, and one Tor verification request per
invocation. Freeze the scanner commit, exact command, and effective cap in
the readiness manifest. Changes to the cap, startup retry policy, or output
schema require prospective protocol and manifest approval.
[Readiness issue #41](https://github.com/josephlhall/check_tor/issues/41)

## Reference-condition specifications

Before a case, document what the endpoint is intended to do using its
operator's documentation or a reviewed configuration. This gives the
reviewer an expectation independent of the scanner verdict being tested.
A proposed configuration describes a condition to build. Review the
configuration and verify eligibility before using it as evidence. A condition
can stay deferred if construction, permission, or independent evidence is
unavailable.

| Condition | Status |
|---|---|
| [`REF-NORMAL`](#ref-normal-ordinary-content-with-working-navigation) | Candidate for later preflight, subject to current verification and new approval |
| [`REF-202`](#ref-202-intelligible-http-202-status) | Local fixture available. Live deployment, qualification, and operator authorization pending. |
| [`REF-CHALLENGE`](#ref-challenge-managed-challenge) | Requires construction and operator permission |
| [`REF-CLIENT`](#ref-client-client-dependent-refusal) | Requires construction, permission, and a stable rule that distinguishes the clients |
| [`REF-TOR-DIFF`](#ref-tor-diff-tor-versus-direct-requests) | Requires construction, permission, and a reviewable Tor classification rule |

### `REF-NORMAL` Ordinary content with working navigation

Use the documented public test-service purpose and the existing catalog entry
as the evidence for the expected behavior. The task is to load `/links/2`,
identify the page's simple content, and follow the first displayed first-party
link. Both browsers should complete that task. The scanner may return `PASS`.
This controlled example tests simple navigation. Content, redirects, and
service availability can change, so verify the entry again before seeking
approval for live use. [Catalog entry `HTTPBIN-LINKS-2`](REFERENCE-ENDPOINTS.md#httpbin-links-2)

### `REF-202` Intelligible HTTP 202 status

Configure a route to return HTTP 202 with a human-readable explanation that the
request was accepted or is pending. Record the configured status and task with
their versions. The browser task is to read the explanation. Navigation is
not applicable. The configured response should exercise the scanner's
`CHALLENGE` rule while allowing the browser task to succeed without a challenge.
That would be a disagreement in what the label means for the task. HTTP 202
alone provides no evidence of a challenge mechanism or browser friction.
[RFC 9110 §15.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.3)

The pilot's documented httpbin `/status/202` route produced an empty page in
both browsers. The [local reference lab](reference-lab/OPERATIONS.md) serves a
readable 202 example with a fixed response. Its operator handoff describes
what must be verified and authorized before R02 can be selected.

### `REF-CHALLENGE` Managed challenge

Use an operator-authorized HTTPS page with low-sensitivity static content and
a documented managed challenge rule limited to that path. Review the rule and
configuration to establish what to expect. The task is to reach the content
and complete one harmless first-party navigation if authorized.

A challenge may finish automatically, cause friction, or present an interaction
the protocol prohibits. Dynamic challenge selection can make observations
vary. Stop at a prohibited interaction under the reference protocol. The
scanner may classify a response as challenge-like, but JSONL v1 does not show
the live challenge header or the browser outcome. Cloudflare documents a
challenge-response header. The approved packet does not collect that header.
Deterministic Turnstile test keys would exercise their own flow, so evidence
for a managed challenge requires a managed challenge rule. Construction and
operator permission are pending.
[Cloudflare challenge-response documentation](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/) · [Turnstile test documentation](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)

### `REF-CLIENT` Client-dependent refusal

Use an operator-controlled static page with a versioned rule that
deterministically distinguishes a documented difference in the actual,
unmodified client request profiles. Review the configuration and request
profiles, then check the rule independently before observing the case. The
browser task is to reach the page content and follow one safe link.

The rule should refuse the unchanged scanner request on both the Tor and
direct paths while allowing the browser task. A scanner `FAIL` alongside
browser success would be a pessimistic task comparison without an automated
Tor disadvantage. The scanner already sends browser-like headers, so a guessed
`User-Agent` distinction is insufficient. Record browser or scanner
version changes and exit variation. Defer the condition if the project cannot
justify a stable way to distinguish the clients.

### `REF-TOR-DIFF` Tor versus direct requests

Use an operator-controlled static page with a versioned, reviewable rule.
Record the current Tor classification source and a snapshot of the rule.
The configuration establishes what to expect. A rule may refuse a request it
classifies as Tor and permit a direct request. Give both browsers the same
harmless public task.

Compare the automated Tor and direct results separately from the two browser
outcomes. A difference in one comparison does not establish the other. The
scanner and Tor Browser may use different exits, and exit membership and edge
conditions can change. The plan does not include a same-exit experiment. Defer
the condition if the current classification source cannot be reviewed.

For each future case, complete the [catalog schema](REFERENCE-ENDPOINTS.md#catalog-schema).
Record the lifecycle state, visibility, who controls the endpoint, authorization,
publication sensitivity, evidence for the expected instrument behavior,
stability, whether previous requests or session state can affect later results,
interaction limit, verification method and date, owner and contact, and what
would retire the entry. The condition IDs are planning labels.
`HTTPBIN-LINKS-2` is the only existing catalog entry proposed for these
conditions. Its documented purpose was verified for the dry run. Recheck
that evidence and obtain approval for the specific batch through
[issue #41](https://github.com/josephlhall/check_tor/issues/41).

## Approved planning shape and traffic accounting

The approved preparation design is **one primary case per eligible condition**,
plus one preassigned repeat of `REF-CHALLENGE` and `REF-TOR-DIFF` only if those
conditions become eligible. That is at most **seven analytic cases** across at
most five condition endpoints. The repeat tests procedural stability, not
independence or prevalence. Give each repeat the opposite scanner/Tor-Browser
order. Freeze all slots before collection and retain attempted, unavailable,
and halted slots in the accounting. There are no outcome-triggered reserves.
If fewer conditions become eligible, run only their preassigned slots and
report the missing condition; do not substitute a different site or chase a
verdict. Carry this shape into a future live manifest or obtain owner review
for a prospective revision.

Planning slot order, to be finalized with actual approved entry IDs:

| Slot | Condition | Primary order | Dependency |
|---|---|---|---|
| R01 | `REF-NORMAL` | S-T-O | Current catalog review |
| R02 | `REF-202` | T-S-O | Constructed 202 status task |
| R03 | `REF-CHALLENGE` | S-T-O | Managed challenge authorization |
| R04 | `REF-CLIENT` | T-S-O | Stable documented client rule |
| R05 | `REF-TOR-DIFF` | S-T-O | Reviewed Tor-classification rule |
| R06 | `REF-CHALLENGE` repeat | T-S-O | R03 eligible; run regardless of R03 outcome unless a safety stop applies |
| R07 | `REF-TOR-DIFF` repeat | T-S-O | R05 eligible; run regardless of R05 outcome unless a safety stop applies |

`S-T-O` is scanner, Tor Browser, ordinary browser; `T-S-O` puts Tor Browser
first. The five primary slots alternate as closely as an odd count permits.
The later manifest should balance the **eligible** subset where possible
without moving a case after its outcome is known. Run one case at a time,
with a 15-minute paired window, and pause for an audited structured row and
artifact minimization before the next case. A condition absent at readiness
stays unavailable for this run; bringing it back requires a reviewed manifest
revision before any new traffic.

The approved planning ceiling per case is one scanner invocation: **one** Tor
preflight request to `check.torproject.org`, up to **three** Tor endpoint attempts, and
up to **one** conditional direct clearnet endpoint request. A first `PASS`
stops scanner retries; `CERT` and `WARN` also stop at the reviewed scanner baseline. Each
browser gets one direct load, at most one rule-triggered reload, and at most
one approved first-party navigation: up to **three top-level actions per
browser**. Thus the seven-case maximum budgets at most **7 preflight + 21 Tor
endpoint + 7 direct-control requests and 42 browser top-level actions**.
Redirects and subresources may multiply actual HTTP requests, so constructed
pages should be minimal static content without third-party resources, and
eligibility review must reject unexpectedly heavy pages or endpoints and
record any lower entry limit. This ceiling is a planning maximum, not
permission to spend it.

**Candidate preflight budget:** documentation and offline configuration review
only, with **zero remote requests** under this preparation issue. The later
readiness packet must name and separately cap any proposed live eligibility
check, including its scanner preflight and browser actions, before making it.
Count that traffic in addition to the analytic ceiling; do not hide it as
free setup or recycle old pilot authority. A preflight result cannot be
silently promoted into an analytic case, and a failure cannot trigger
unplanned endpoint screening. The owner may approve a lower ceiling or defer
conditions rather than fund remote preflight.

## Future live-readiness manifest fields

This template is deliberately unresolved. A reviewer must be able to see
every value below before separately authorizing any live preflight or case:

| Gate | Value to freeze or decision required |
|---|---|
| Protocol and approval | `TACP-0.4` revision, review date, reviewer, accepted timing and interpretation rules, unresolved conditions |
| Case selection | Approved catalog entry IDs, exact URLs kept private when required, independent expectation evidence and date, public task/navigation, authorization, association/publication review, lower entry limit, final slot/order/repeats |
| Instrument and host | Scanner commit and exact options, JSONL schema, effective target-body cap, preflight attempt budget, OS and tool versions, Tor/Tor Browser and ordinary-browser versions, security level, time sync, observer mode, fresh-state controls |
| Traffic | Per-case and aggregate ceiling, any lower endpoint limit, redirect/subresource weight assessment, exact preflight request/action budget, stopping and no-substitution rules |
| Private data | Owner-only external root, storage permissions, backup/sync exclusion, raw versus structured paths, access list, raw audit/deletion deadline, structured retention/deletion or extension date, no screenshot or cookie collection |
| Safety and authority | Operator contact/opt-out and incident path, current permission, halt triggers, separate explicit authority for preflight and collection, analysis and publication review gates |

The issue #33 host values, approved private root, authority, and retention
dates were specific to its completed pilot and are **not inherited**. An
approved packet may leave construction or permission conditions deferred;
it must identify them and cannot say it is ready for live use until every
required gate for the selected cases is resolved.

## Prospective observation and analysis table

Enter browser task facts and rubric outcomes before agreement or mechanism
interpretation. Retain a private case row under the stewardship policy; a
public result may show only reviewed aggregates or deliberately public cases.
The table below summarizes the analysis record. Retain the
[`TACP-0.2` base fields](VALIDATION-PROTOCOL.md#observation-record) with the
prospective additions below. For `TACP-0.4`, deadline expiry is distinct from
observed stability: retain the affected action and expiry in the structured
note, and use null with a reason for that action's unobserved stable time.
Retain later stability after a permitted reload. The browser-level stable-time
field is null only if no stable final task outcome was observed. This
prospective recording rule does not recode historical records.

| Layer | Fields and rule |
|---|---|
| Predeclared case | `case_id`, `condition_id`, `catalog_entry_id`, `endpoint_group_id`, `protocol_id`, expectation source/version/date, approved task, planned order, repeat link, approval/authorization, limits |
| Direct scanner | Target JSONL record or explicit `NO_TARGET_RECORD` reason; preserve exact `verdict`, `tor_attempts`, `tor_attempt_limit`, `clearnet_control` object, nullable `tor_specific`, `body_limited`, schema version, timestamps, and raw-artifact reference outside Git. `detail` is contextual prose, not a parser input. |
| Browser facts | Separate Tor/ordinary task records: start/end, per-action content/navigation and stable seconds, wait-limit expiry and affected action, permitted reload trigger, navigation result, meaningful content, visible challenge and automatic completion, `interaction_boundary`, `technical_failure_observed`, observer exposure, uncertainty, and independent rubric outcome. |
| Automated comparison | `AUTOMATED_TOR_WORSE`, `SAME_OR_NOT_WORSE`, or `UNDETERMINED`, based only on a performed, conclusive scanner clearnet control and the preserved `tor_specific` value; record `NOT_PERFORMED` distinctly when absent. |
| Browser comparison | `TOR_BROWSER_WORSE`, `SAME_TASK_OUTCOME`, `ORDINARY_BROWSER_WORSE`, or `UNDETERMINED`, based on the two outcome categories. Missing or inconclusive observations give `UNDETERMINED`; matching conclusive categories give `SAME_TASK_OUTCOME`. Retain times and impediments separately without ranking within a category. |
| Interpretation | Scanner-to-Tor-Browser category (`STRONG_AGREEMENT`, `ACCEPTABLE_SEMANTIC_AGREEMENT`, prospective `SEMANTIC_DISAGREEMENT`, `SCANNER_PESSIMISTIC`, `SCANNER_OPTIMISTIC`, or `INCONCLUSIVE`), evidence statement, likely and alternative mechanism as hypotheses, confidence, deviations, and reviewer decision. Do not use a mechanism-hypothesis label as if it were observed agreement. |

Use JSON `null` for an unobserved or unknown value, with a reason field; use
`false` only for observed absence. Keep `clearnet_control.performed=false`
with `verdict=null` and `tor_specific=null` when no control ran. A scanner
preflight failure has no target record and makes scanner-to-browser agreement
`INCONCLUSIVE`, even if both browsers have outcomes. An interactive boundary
has its own field and never licenses the claim that solving it would succeed.
Group repeats by `endpoint_group_id` in any summary: count cases and unique
endpoints separately and describe within-endpoint variation instead of using
repeated rows as independent sites.

### Synthetic recording walk-throughs — examples, not observations

The outcomes below are deliberately invented to test the rules. `Control`
means the automated clearnet control, not the ordinary browser.

| Example | Scanner / control | Tor Browser / ordinary browser | Required interpretation |
|---|---|---|---|
| Normal task | `PASS`, `tor_attempts=1`; `performed=false`, control verdict and `tor_specific` null | `NORMAL` / `NORMAL`, link completed | Task-level strong agreement; automated differential treatment `NOT_PERFORMED`; no Tor Browser disadvantage. |
| 202 semantics | `CHALLENGE`, `tor_attempts=3` from configured 202; control `CHALLENGE`, `tor_specific=false` | `NORMAL` / `NORMAL` on intelligible status task; no interstitial | Prospective `SEMANTIC_DISAGREEMENT`: the scanner reports its actual status-based rule, while browsers encounter no barrier. Neither automated nor browser Tor disadvantage is observed; do not call this browser friction. |
| Browser-passable refusal | `FAIL`, `tor_attempts=3`; control `FAIL`, `tor_specific=false` | `NORMAL` / `NORMAL` after the approved task | `SCANNER_PESSIMISTIC` for Tor Browser; the rule distinguishes client behavior, not Tor versus direct scanner traffic. Its mechanism remains a hypothesis unless independent configuration evidence supports it. |
| Differential treatment | `FAIL`, `tor_attempts=3`; control `PASS`, `tor_specific=true` | `BLOCKED` / `NORMAL` with the same task and no prohibited interaction | Automated Tor disadvantage and observed Tor Browser disadvantage are separate findings; the configured rule supports the reference expectation but does not prove every Tor exit behaves alike. |
| Inconclusive | No target JSONL because scanner preflight failed; control not performed, nullable target fields remain null | `INCONCLUSIVE` / `NORMAL` after an origin instability note | No scanner agreement or differential-treatment claim; retain the attempted case and deviation without replacement. |

The following timing examples exercise `TACP-0.4`; they are invented, not new
observations or revisions to the completed pilot:

| Example | Recording and interpretation |
|---|---|
| Content appears at 5 seconds and stays unchanged | Confirm stability at 8 seconds and advance to the next permitted step; no need to wait until 30. |
| Content appears at 7 seconds and is stable at 10 | Record both times. The delay is 7 seconds, so confirmation alone does not produce `FRICTION`; another impediment still can. |
| Content first appears at 29 seconds | Stop that action's observation at 30. Record the appearance and wait-limit expiry; stability remains unobserved, with a null stable time and reason. Do not extend to 32 seconds or infer blocking from expiry alone. |
| A permitted reload is still loading at 30 seconds | Record expiry without claiming a stable result. Do not reload again; classify only the available evidence. |
| A required step has a 25-second delay in Tor Browser and a 12-second delay in the ordinary browser; both tasks then complete | Both are `FRICTION`; compare as `SAME_TASK_OUTCOME`. Delays are per step and exclude stability confirmation, not total task durations. Retain both times without claiming equal speed or ranking within the category. |

If an interactive challenge appears, a further synthetic variant records
`interaction_boundary=PROHIBITED` and stops the case without solving it. The
observed task may be classified `BLOCKED` under the permitted-action rule;
the overall case comparison is `INCONCLUSIVE` if another instrument is
missing. If a browser record is missing, the separate browser-to-browser
comparison is `UNDETERMINED`. A missing scanner alone does not invalidate a
comparison between two completed browser records. The observed browser
`technical_failure_observed` remains `false` or null according to direct
evidence; success after interaction is unknown.

## Review and disposition record

| Decision | Current state |
|---|---|
| Owner review and date | Original packet approved 2026-09-25 UTC; prospective timing and comparison revision approved 2026-11-07 |
| Protocol identity and timing rules | `TACP-0.4`: advance after observed three-second stability; hard 30-second action limits with expiry recorded separately; ten-second delay excludes confirmation time; 15-minute paired window unchanged |
| Condition dispositions | One future-preflight candidate; four construction/permission conditions, with deferral allowed; approved as preparation dispositions |
| Collection shape and resource budget | At most seven analytic cases and zero remote requests during preparation; approved planning ceiling, not live traffic authority |
| Interpretation and synthetic walk-through | Original categories retained; matching conclusive browser categories give `SAME_TASK_OUTCOME`, with times and impediments retained separately. Timing examples added for the 2026-11-07 revision. |
| Unresolved readiness | Endpoint construction or deployment as applicable, operator permission, independent configuration checks, current catalog review, host/environment, private storage and retention, preflight budget if any, explicit live authority |

Owner approval completes the methodological review of this preparation
packet. Any material amendment needs a dated review and a new prospective
protocol revision. Approval of this packet does **not** authorize
construction, operator outreach, live measurement, publication, or reuse of
issue #33's private data.

The [protocol revision history](VALIDATION-REFERENCE-PROTOCOL.md#revision-history)
records the adopted changes. The
[original `TACP-0.3` packet](https://github.com/josephlhall/check_tor/blob/ec80623c2ec737ee2aecfc70eae99ca8e02bf602/VALIDATION-REFERENCE-PACKET.md)
remains available with its historical approval and rules.
