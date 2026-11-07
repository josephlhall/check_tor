# Prospective Tor Access Reference Protocol

`TACP-0.4` defines how a future study would compare what the scanner observes
with what a person can do in Tor Browser and in an ordinary browser. The
scanner starts at one approved URL. In each browser, a person starts at that
same URL and tries to complete the approved public task. Keeping the results
separate lets the reviewer see where the scanner verdict and browser outcomes
agree or diverge.

> **Protocol ID:** `TACP-0.4`
>
> **Status:** APPROVED FOR PREPARATION — no live authority
>
> **Basis:** [Issue #39](https://github.com/josephlhall/check_tor/issues/39)
> and the completed [pilot](VALIDATION-PILOT-RESULTS.md)
>
> **Owner approval:** Original preparation approved 2026-09-25 UTC; revision
> `TACP-0.4` approved 2026-11-07 for early advancement, deadline recording,
> delay measurement, and comparison by browser outcome category. Live
> environment and data handling remain future readiness decisions.

The owner approved the method for preparation. A future manifest must satisfy
the [stewardship policy](ETHICS-AND-DATA-STEWARDSHIP.md) and receive explicit
authority before any live requests. Endpoint construction and operator contact
also require separate approval. The
[reference preparation packet](VALIDATION-REFERENCE-PACKET.md) specifies the
candidate conditions, traffic limits, and decisions still needed. The
[completed issue #33 pilot](VALIDATION-PILOT-RESULTS.md) remains governed by
[`TACP-0.2`](VALIDATION-PROTOCOL.md).

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

Use the schema version 1 `check_tor` target record (`--format jsonl`) as the
scanner result, as approved for this preparation. The later detailed
[`--format jsonl-v2` mode](DETAILED-OUTPUT.md) has a separate contract and is not
part of this approved instrument specification. The v1 target record contains
`verdict`, `tor_attempts`, `tor_attempt_limit`,
`clearnet_control.enabled`, `.performed`, and nullable `.verdict`, nullable
`tor_specific`, and `body_limited`. Preserve the exact JSON values and
schema version. A failed scanner preflight has **no target record**. Do not
convert it to `TIMEOUT`, a missing control to `false`, or `detail` prose to a
structured response header.

JSONL v1 has no HTTP status, response headers, per-attempt verdicts,
or browser outcome. A reference condition's expected status or challenge
mechanism comes from independently reviewed operator documentation or
controlled configuration, recorded with version and review date. Browser
observation supplies the task outcome. This protocol proposes no extra header
capture or network request. If a future analysis needs proof that a particular
live response carried a header such as `cf-mitigated: challenge`, it must first
approve a bounded acquisition method and restricted storage in a revised
manifest; absent that evidence, the header remains unobserved.

## Freeze the case before observation

Before choosing a case, document what the endpoint is intended to do, using
evidence such as the operator's documentation or a reviewed configuration.
This gives the reviewer an expectation independent of the scanner verdict
being tested.

The case's catalog record must include that evidence, the authorization and
publication review, one start URL, the exact public task, and the approved
first-party navigation or `not applicable`. Use the lower of the case and
global traffic limits. In the future manifest, freeze the scanner commit and
settings, browser versions and security level, environment, order, case IDs,
repeat schedule, and stop rules. Do not select cases by a scanner result or
replace an unavailable condition after seeing outcomes.

Use a fresh Tor Browser identity and a fresh private ordinary-browser window
for each case. No diagnostic ordinary browser over Tor, selected exit, circuit
manipulation, login, form submission, CAPTCHA solving, warning bypass, or
challenge workaround is part of this protocol.

## Approved browser task and timing rules

All times are elapsed seconds from an immediately recorded action start on
the observation host; use UTC timestamps for starts and ends. The owner
accepted the numerical limits on 2026-09-25 and the operational rules below on
2026-11-07. These are study rules, not established user-experience thresholds.
They bound exposure and make observations reproducible within a 15-minute
paired window. Changes require a reviewed prospective revision before
collection, never after a case outcome is seen.

1. Directly load the approved URL. As soon as the task-relevant content,
   refusal, warning, or boundary has remained visible and unchanged for
   **3 seconds**, record that stable result and advance to the next permitted
   step. Do not wait until 30 seconds when stability is already established.
   A prohibited interaction stops the entire case immediately under the
   stewardship policy; do not wait three seconds at that boundary.
2. The initial load has a hard limit of **30 seconds**. At the limit, record
   what is visible and that the wait limit was reached. Invoke the one allowed
   reload only if the page is still loading, stalled, or shows a clearly
   transient incomplete-load error. A stable refusal, warning, interaction
   boundary, or completed task is not a reload trigger.
3. After a permitted reload, allow at most **30 further seconds** from that
   action's start, advancing earlier if the result is stable. Record the
   reload trigger and result. Do not reload again, change identity or URL, or
   adjust browser settings.
4. If the task requires one approved first-party navigation, start it after
   meaningful starting content has met the three-second stability rule. Allow
   at most **30 seconds** from the navigation action, advancing earlier if its
   result is stable. Do not substitute another link if it is missing or fails.
5. A deadline ends the action's observation window; it does **not** establish
   that the page is stable. Do not extend a window to finish the stability
   check. If content first appears at second 29, record that appearance and
   stop at second 30, without claiming three seconds of stability. Record the
   affected action and deadline expiry in the structured note, with null and a
   reason for that action's unobserved stable time. A permitted reload may
   subsequently reach stability; retain that later observation. The browser-level
   `time_to_stable_outcome_seconds` is null only when no stable final task
   outcome was observed. Apply the rubric to the evidence actually observed;
   expiry alone does not prove a block or technical failure.
6. Record time to first meaningful content separately from time to stable
   outcome. For the **10-second delay threshold**, use the time to the
   task-relevant content appearing on the initial load or reload, or to the
   approved navigation completing, measured from that action's start. Exclude
   the additional three-second stability confirmation. Content appearing at
   second 7 and confirmed stable at second 10 does not count as a ten-second
   delay. A visible interstitial, a permitted reload, or a delay of **10 seconds
   or more** in a required step still makes successful task completion
   `FRICTION`. Record the actual times and impediments; the threshold does not
   establish their cause.
7. Start the paired **15-minute** clock with the first primary instrument.
   At that limit, do not begin another instrument or add attempts to rescue
   comparability. Close the case with the observations already made and mark
   the overall case comparison `INCONCLUSIVE` if any required instrument is
   missing. Preserve the independent browser outcomes; their comparison follows
   the separate category rules below. Record
   the timing deviation if a safely finishing action extends past the window;
   this does not extend a browser action's 30-second limit.

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

Record `interaction_boundary` separately as `NONE`, `PASSIVE`, `PROHIBITED`,
or `UNKNOWN`, with a brief description of what appeared. If a passive challenge
appears, record whether it completes automatically. If you encounter a CAPTCHA,
human-verification action, login, consent disclosure, or access-control
workaround, record `PROHIBITED` and stop the entire case under the stewardship
policy. Leave the interaction untouched. Record the boundary and any completed
observations, and run no remaining instruments.

If a required instrument is missing, mark the overall case comparison
`INCONCLUSIVE` even if the observed browser task qualifies as `BLOCKED`.
A missing browser also makes the browser-to-browser comparison `UNDETERMINED`;
a missing scanner alone does not erase two completed browser observations.
That browser outcome describes what was possible under the task's permitted
actions. It leaves open whether completing the interaction would succeed,
whether the site technically failed, and whether the operator intended to
exclude Tor users.
Record a distinct `technical_failure_observed` value of `true`, `false`, or
null and the evidence for it.

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

Compare the browsers by their independently recorded outcome categories.
When either observation is missing or `INCONCLUSIVE`, use `UNDETERMINED` for
the browser comparison. Otherwise, matching categories mean
`SAME_TASK_OUTCOME`, including when both browsers are `FRICTION`. For different
categories, use the order `NORMAL`, `FRICTION`, `SEVERELY_DEGRADED`, `BLOCKED`
from less to more impaired to identify the worse browser outcome.

Keep the measured times and specific impediments even when the categories
match. For example, a required step with a 25-second delay in Tor Browser and a
12-second delay in the ordinary browser makes both successfully completed
tasks `FRICTION`. Those delays exclude stability confirmation; they are not
total task durations summed across steps. The outcome categories match. This does not mean they were equally fast or easy. Do not
rank a delay, challenge, or reload within a category without a separately
approved comparison rule defined before collection.

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
recoded under a later protocol revision.


## Revision history

| Revision | Approval | Scope |
|---|---|---|
| [`TACP-0.3`](https://github.com/josephlhall/check_tor/blob/ec80623c2ec737ee2aecfc70eae99ca8e02bf602/VALIDATION-REFERENCE-PROTOCOL.md) | 2026-09-25 UTC | Original reference preparation: timing limits, browser rubric, evidence boundaries, and interpretation rules. |
| `TACP-0.4` | 2026-11-07 | Advance after observed stability; keep hard per-action limits and record expiry separately; exclude stability confirmation from the delay threshold; compare browsers by outcome category while retaining times and impediments. |

The linked `TACP-0.3` text preserves the earlier approved method. This revision
changes only future observations. The completed `TACP-0.1` dry run and
`TACP-0.2` pilot retain their original methods and results. Scanner behavior,
JSONL v1, case allocation, traffic ceilings, and separate live-authorization
requirements are unchanged.
