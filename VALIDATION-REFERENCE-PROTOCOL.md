# Prospective Tor Access Reference Protocol

> **Protocol ID:** `TACP-0.3`
>
> **Status:** APPROVED FOR PREPARATION — no live authority
>
> **Basis:** [Issue #39](https://github.com/josephlhall/check_tor/issues/39)
> and the completed [pilot](VALIDATION-PILOT-RESULTS.md)
>
> **Owner approval:** Communicated 2026-09-25 UTC for the prospective protocol
> and its linked preparation packet; live environment and data handling remain
> future readiness decisions

This prospective protocol specifies how a later, separately authorized study
could compare scanner observations with task-based browser access at reference
conditions. It does not revise observations collected under
[`TACP-0.2`](VALIDATION-PROTOCOL.md), which remains the frozen authority for
issue #33. The [reference preparation packet](VALIDATION-REFERENCE-PACKET.md)
specifies candidate conditions, a bounded manifest template, and the decisions
still needed. Neither document authorizes endpoint construction, preflight
requests, live scanning, browser visits, or operator contact.

The [stewardship policy](ETHICS-AND-DATA-STEWARDSHIP.md) governs every later
study and can halt a case. A future manifest must resolve its operational
requirements and receive explicit live authority before any requests.

## Question and limits

For a predeclared public task, what did the fixed `curl`-over-Tor scanner
observe, what could a person complete in Tor Browser and an ordinary browser,
and where do those observations disagree? Five reference conditions target
normal access, HTTP 202 semantics, challenge friction, client-dependent
refusal, and Tor-versus-clearnet difference. They are purposive conditions, not
a sample from which to estimate prevalence or scanner accuracy.

The scanner and Tor Browser may use different exits. A paired automated
clearnet control is a comparison between `curl` requests, not between browsers.
Neither browser outcome proves the cause of a scanner verdict. A configured
reference mechanism supports the expectation for a condition; an observed
outcome still requires a contemporaneous record.

## Instruments and evidence

Use the unchanged `check_tor` JSONL target record as the scanner result. It
contains `verdict`, `tor_attempts`, `tor_attempt_limit`,
`clearnet_control.enabled`, `.performed`, and nullable `.verdict`, nullable
`tor_specific`, and `body_limited`. Preserve the exact JSON values and
schema version. A failed scanner preflight has **no target record**. Do not
convert it to `TIMEOUT`, a missing control to `false`, or `detail` prose to a
structured response header.

The current JSONL has no HTTP status, response headers, per-attempt verdicts,
or browser outcome. A reference condition's expected status or challenge
mechanism comes from independently reviewed operator documentation or
controlled configuration, recorded with version and review date. Browser
observation supplies the task outcome. This protocol proposes no extra header
capture or network request. If a future analysis needs proof that a particular
live response carried a header such as `cf-mitigated: challenge`, it must first
approve a bounded acquisition method and restricted storage in a revised
manifest; absent that evidence, the header remains unobserved.

## Freeze the case before observation

Each eligible case needs a catalog record with an independent expectation
basis, authorization and publication review, a single start URL, an exact
public task and approved first-party navigation or `not applicable`, and the
lower of its own and the global traffic limit. Freeze the scanner commit and
settings, browser versions and security level, environment, order, case IDs,
repeat schedule, and stop rules in a later manifest. Do not select cases by a
scanner result or replace an unavailable condition after seeing outcomes.

Use a fresh Tor Browser identity and a fresh private ordinary-browser window
for each case. No diagnostic ordinary browser over Tor, selected exit, circuit
manipulation, login, form submission, CAPTCHA solving, warning bypass, or
challenge workaround is part of this protocol.

## Approved browser task and timing rules

All times are elapsed seconds from an immediately recorded action start on
the observation host; use UTC timestamps for starts and ends. The owner
accepted the numerical limits below on 2026-09-25 as operational study rules,
not established user-experience thresholds. They bound exposure and make
`FRICTION` reproducible within a 15-minute paired window. Any later change
requires a reviewed protocol revision before collection, never after a case
outcome is seen.

1. Directly load the approved URL. At **30 seconds**, classify a stable result
   or invoke the one allowed reload only if the page is still loading, stalled,
   or shows a clearly transient incomplete-load error. A stable refusal,
   warning, interaction boundary, or completed task is not a reload trigger.
2. After a permitted reload, wait at most **30 further seconds**. Record its
   trigger and result. Do not reload a second time, change identity or URL, or
   adjust browser settings.
3. If the task requires one approved first-party navigation, start it only
   after meaningful starting content appears. Allow at most **30 seconds** for
   the destination. Do not substitute another link if it is missing or fails.
4. A result is stable when the task-relevant content, refusal, warning, or
   boundary is visible and unchanged for **3 seconds**, or when its wait limit
   expires. Record time to first meaningful content and time to stable task
   outcome separately. A visible interstitial or delay of **10 seconds or
   more** in either required step is a study-defined user-visible impediment;
   record the actual seconds and what was visible. The threshold alone does not
   establish why the delay occurred.
5. Start the paired **15-minute** clock with the first primary instrument.
   At the limit, do not begin another instrument or add attempts to rescue
   comparability. Close the case with the observations already made and mark
   the comparison `INCONCLUSIVE` if any required instrument is missing. Record
   the timing deviation if a safely finishing action extends past the window.

Meaningful content is the predeclared information or function needed for that
case, not a generic browser error, challenge interstitial, empty response, or
branding. A status-reference task may define an intelligible status page as
meaningful content and navigation as not applicable. For ordinary content,
success requires both the page and its approved first-party navigation. Frozen
case instructions must name what a reviewer can recognize without copying page
text into the record.

## Browser classification

Apply the same rubric independently to Tor Browser and the ordinary browser:

| Outcome | Decision rule |
|---|---|
| `NORMAL` | The complete public task succeeds without a visible interstitial, reload, or study-defined delay. |
| `FRICTION` | The complete task succeeds after a visible interstitial, permitted reload, or study-defined delay. |
| `SEVERELY_DEGRADED` | Some meaningful content appears, but the required task remains incomplete or impractical at its frozen limit. |
| `BLOCKED` | No meaningful task content can be reached within the permitted actions, including when an unperformed prohibited interaction is the boundary. |
| `INCONCLUSIVE` | Missing observation, ambiguous content, unrelated origin or environment failure, protocol deviation, or instability prevents a fair task classification. |

Record `interaction_boundary` separately as `NONE`, `PASSIVE`,
`PROHIBITED`, or `UNKNOWN`, with a minimal factual type. A passive challenge
may finish automatically; record whether it did. A CAPTCHA, human-verification
action, login, consent disclosure, or access-control workaround is
`PROHIBITED`: stop that browser task without interacting. A resulting `BLOCKED`
means blocked **under this task and permitted-action rule**. It is not evidence
that the interaction would fail, that the site technically failed, or that its
operator intended to exclude Tor users. Record a distinct
`technical_failure_observed` value of `true`, `false`, or null and its evidence;
do not infer it from `BLOCKED`.

The stewardship policy requires stopping the **case** at a prohibited
interaction boundary. Record the boundary and any completed instrument facts,
then run no remaining instruments. If the case is incomplete, its paired
comparison is `INCONCLUSIVE` even when the observed browser task can be
classified `BLOCKED` under the permitted-action rule.

## Order, recording, and interpretation

Preassign `S-T-O` (scanner, Tor Browser, ordinary browser) or `T-S-O` (Tor
Browser, scanner, ordinary browser) and balance the two orders across included
cases where possible. Keep the ordinary browser last for consistency. The
browser observer should not receive the scanner verdict before entering and
locking each browser's factual task record. When one person necessarily sees
the scanner-first result, record `observer_exposed_to_scanner_result=true`
and the exposure time; still enter browser facts and outcomes before any
agreement or mechanism interpretation. Do not rewrite those fields after the
scanner comparison. Record any breach of this sequence as a deviation.

Keep four comparisons separate: scanner verdict versus Tor Browser task;
scanner Tor versus automated clearnet when a control was performed; Tor
Browser versus ordinary-browser task; and the hypothesis explaining any
disagreement. `tor_specific` is an automated inference only. A browser
disadvantage requires an observed worse Tor Browser task outcome under the
same frozen task; it does not follow from `tor_specific=true`. Mechanism
labels remain hypotheses unless the approved independent evidence actually
isolates them. Repeat visits to one endpoint are related observations, not
independent sites or a prevalence denominator. The packet provides the
recording and synthetic analysis examples.

For this prospective study, use `SEMANTIC_DISAGREEMENT` when a scanner label
correctly reflects a documented HTTP status but implies a challenge or
barrier that the completed browser task did not encounter. This is an analysis
category, not a changed scanner verdict or a retroactive `TACP-0.2` category.
Reserve `SCANNER_PESSIMISTIC` for a scanner refusal or severe failure when Tor
Browser completes the task. Record the actual observation and evidence before
choosing either label.

## Stop and change control

Apply every halt rule in the stewardship policy. An unavailable condition is
recorded as unavailable with a reason; continue only to preassigned eligible
slots. Do not screen for a replacement, chase a verdict, or extend the budget.
Unexpected content, permissions, protocol, or storage uncertainty stops the
affected case pending human review. A changed timing, endpoint, task,
instrument, field, or interpretation rule requires a new prospective revision
and review before use. The completed `TACP-0.2` pilot and its results are never
recoded under `TACP-0.3`.
