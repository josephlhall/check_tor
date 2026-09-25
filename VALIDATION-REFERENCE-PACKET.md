# Task-Based Reference Experiment Preparation Packet

> **Issue:** [#39](https://github.com/josephlhall/check_tor/issues/39)
>
> **Protocol:** [`TACP-0.3`](VALIDATION-REFERENCE-PROTOCOL.md)
>
> **Status:** APPROVED PREPARATION PACKET — no live authority
>
> **Owner approval:** Communicated 2026-09-25 UTC for the protocol identity,
> timing, condition dispositions, planning budget, and interpretation rules
>
> **Scanner baseline reviewed:** `567faea7ab4e65ebdc8d3176169e98d5ab4ff8d5`

This packet prepares reference observations; it is not a collection manifest
and contains no approved live endpoint list. The completed
[`TACP-0.2` pilot](VALIDATION-PILOT-RESULTS.md) remains historical evidence.
Its 26 purposively selected cases included no browser `FRICTION` or
`SEVERELY_DEGRADED` outcome. All three `CHALLENGE` cases used synthetic HTTP
202 responses, and the single observed Tor Browser disadvantage coincided
with scanner `PASS`. Those facts motivate these conditions but do not predict
their results. The scanner code and JSONL schema remain unchanged.

## Reference-condition specifications

The expectations below come from a documented service purpose or a proposed
controlled configuration, **never** from a desired scanner verdict. A
configuration that has not been built or reviewed is a specification, not
verified evidence. `Future preflight` means eligible for a later readiness
review, not ready for traffic. A controlled endpoint may remain deferred if
construction, permission, or an independent expectation basis is unavailable.

| ID and condition | Hypothesis and expected instruments | Independent basis and public task | Disposition and limits |
|---|---|---|---|
| `REF-NORMAL`: ordinary content with working navigation | A documented simple page and its first-party link should complete in both browsers; scanner may return `PASS`, but no verdict is guaranteed. | Existing [`HTTPBIN-LINKS-2`](REFERENCE-ENDPOINTS.md#httpbin-links-2) catalog record and documented public test-service purpose. Load `/links/2`, identify its simple content, follow the first displayed first-party link. | **Future preflight.** New approval and current verification are required. This is simple controlled content, not an ordinary-site prevalence sample. Content, redirects, and service availability may change. |
| `REF-202`: intelligible HTTP 202 status without challenge | A fixed 202 should exercise the scanner's `CHALLENGE` branch while browsers can complete a status-information task without a challenge. This is a proposed semantic disagreement, not a prediction of access friction. | [RFC 9110 §15.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.3) defines 202; controlled route configuration must independently specify 202 and a human-readable accepted/pending explanation. Task: read that explanation; navigation not applicable. | **Requires construction and operator authorization.** The pilot's httpbin `/status/202` is documented to return 202 but produced an empty browser task; it cannot establish this condition's intelligible page. Keep the configured status and task versioned. No challenge mechanism is inferred from 202. |
| `REF-CHALLENGE`: authorized challenge protecting meaningful content | A managed challenge may pass automatically, produce friction, or reach a prohibited interaction boundary. The scanner may classify challenge-like responses, but current JSONL alone cannot prove the live header or browser result. | Minimum infrastructure: operator-authorized HTTPS page with low-sensitivity static content and a documented, path-scoped managed challenge rule; task is reaching that content and one harmless first-party navigation if authorized. Rule/configuration review is the independent expectation basis. [Cloudflare's challenge-response documentation](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/) describes an explicit header, but this packet does not collect that header. | **Requires construction and operator permission.** No such endpoint is approved. Dynamic challenge selection is a confounder; interactive solving is prohibited. [Deterministic Turnstile test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) would test their own flow, not establish managed challenge behavior. |
| `REF-CLIENT`: documented client-dependent refusal that a browser can pass | A fixed rule should refuse the unchanged scanner request on both Tor and direct paths while permitting the predeclared browser task. A scanner `FAIL` plus browser success would be a pessimistic task comparison without automated Tor disadvantage. | Minimum operator-controlled static page with a versioned deterministic rule based on a documented difference in the actual unmodified client request profiles; task is content plus one safe link. Configuration, request-profile review, and an independent rule check establish the expectation before observation. | **Requires construction and permission; defer if a stable discriminator cannot be justified.** The scanner already sends browser-like headers; a guessed `User-Agent` rule is inadequate. Browser/client version drift and exit variation must be recorded. |
| `REF-TOR-DIFF`: documented Tor-versus-clearnet difference | A configured rule may refuse a Tor-classified request and permit a direct request. Compare scanner Tor/control fields and both browser tasks separately; a difference in one comparison does not establish the other. | Minimum operator-controlled static page and a versioned, reviewable rule plus current classification source and rule snapshot. Same harmless public task for both browsers. The configuration, rather than a scanner result, is the expectation basis. | **Requires construction and permission; defer if current classification cannot be reviewed.** Scanner and Tor Browser need not share an exit; exit membership and other edge conditions change. No same-exit experiment is planned. |

For each future case, complete the existing
[catalog schema](REFERENCE-ENDPOINTS.md#catalog-schema): lifecycle, visibility,
control, authorization, publication sensitivity, expectation basis, expected
instrument behavior, stability, statefulness, interaction limit, verification
method/date, owner/contact, and retirement trigger. These condition IDs are
planning labels; only `HTTPBIN-LINKS-2` is an existing eligible catalog entry.
No new endpoint receives a `verified` lifecycle merely by appearing here.

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
stops scanner retries; `CERT` and `WARN` also stop under current code. Each
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
| Protocol and approval | `TACP-0.3` revision, review date, reviewer, accepted timing and interpretation rules, unresolved conditions |
| Case selection | Approved catalog entry IDs, exact URLs kept private when required, independent expectation evidence and date, public task/navigation, authorization, association/publication review, lower entry limit, final slot/order/repeats |
| Instrument and host | Scanner commit and exact options, JSONL schema, OS and tool versions, Tor/Tor Browser and ordinary-browser versions, security level, time sync, observer mode, fresh-state controls |
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
The table below defines the analytical projection, not a replacement for
[`TACP-0.2` fields](VALIDATION-PROTOCOL.md#observation-record).

| Layer | Fields and rule |
|---|---|
| Predeclared case | `case_id`, `condition_id`, `catalog_entry_id`, `endpoint_group_id`, `protocol_id`, expectation source/version/date, approved task, planned order, repeat link, approval/authorization, limits |
| Direct scanner | Target JSONL record or explicit `NO_TARGET_RECORD` reason; preserve exact `verdict`, `tor_attempts`, `tor_attempt_limit`, `clearnet_control` object, nullable `tor_specific`, `body_limited`, schema version, timestamps, and raw-artifact reference outside Git. `detail` is contextual prose, not a parser input. |
| Browser facts | Separate Tor/ordinary task records: start/end, first meaningful and stable seconds, permitted reload trigger, navigation result, meaningful content, visible challenge and automatic completion, `interaction_boundary`, `technical_failure_observed`, observer exposure, uncertainty, and independent rubric outcome. |
| Automated comparison | `AUTOMATED_TOR_WORSE`, `SAME_OR_NOT_WORSE`, or `UNDETERMINED`, based only on a performed, conclusive scanner clearnet control and the preserved `tor_specific` value; record `NOT_PERFORMED` distinctly when absent. |
| Browser comparison | `TOR_BROWSER_WORSE`, `SAME_TASK_OUTCOME`, `ORDINARY_BROWSER_WORSE`, or `UNDETERMINED`, based on the two frozen-task outcomes and their specific friction/degradation evidence. |
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

If an interactive challenge appears, a further synthetic variant records
`interaction_boundary=PROHIBITED` and stops the case without solving it. The
observed task may be classified `BLOCKED` under the permitted-action rule;
the paired comparison is `INCONCLUSIVE` if another instrument is missing. Its
`technical_failure_observed` remains `false` or null according to direct
evidence; success after interaction is unknown.

## Review and disposition record

| Decision | Current state |
|---|---|
| Owner review and date | Approved in this session, 2026-09-25 UTC |
| Protocol identity and timing rules | `TACP-0.3` approved for preparation; 30-second initial/reload/navigation limits, 10-second delay threshold, 3-second stability rule, 15-minute paired window |
| Condition dispositions | One future-preflight candidate; four construction/permission conditions, with deferral allowed; approved as preparation dispositions |
| Collection shape and resource budget | At most seven analytic cases and zero remote requests during preparation; approved planning ceiling, not live traffic authority |
| Interpretation and synthetic walk-through | Approved, including prospective `SEMANTIC_DISAGREEMENT` and separate automated/browser comparisons |
| Unresolved readiness | Endpoint construction or permission, independent configuration checks, current catalog review, host/environment, private storage and retention, preflight budget if any, explicit live authority |

Owner approval completes the methodological review of this preparation
packet. Any material amendment needs a dated review and a new prospective
protocol revision. Approval of this packet does **not** authorize
construction, operator outreach, live measurement, publication, or reuse of
issue #33's private data.
