# Tor Access Comparison Protocol: Five-Case Dry Run

> **Status:** ACCEPTED<br>
> **Evidence protocol:** `TACP-0.1`<br>
> **Frozen protocol:** `TACP-0.2`<br>
> **Scanner commit:** `fc13260f87c01e56db376858d90d837abcda1eaa`<br>
> **Human reviewer and observer:** Joseph Lorenzo Hall<br>
> **Observation date:** 2026-08-30<br>
> **Freeze accepted:** Joseph Lorenzo Hall, 2026-08-30

This note records procedural evidence from the issue #32 dry run. It does not
publish raw observation rows, scanner output, screenshots, browser notes,
observed IP addresses, or private storage paths. It does not estimate scanner
accuracy or the prevalence of any behavior.

## Scope

The dry run used five deliberately public cases from purpose-built client-test
services:

- a simple successful HTTP page with one approved first-party navigation;
- deliberate HTTP 403 and HTTP 429 responses; and
- expired and self-signed TLS certificate boundaries.

Three cases used scanner → Tor Browser → ordinary browser order. Two used Tor
Browser → scanner → ordinary browser order. The optional ordinary-browser-over-
Tor diagnostic remained disabled.

The scanner code and JSONL schema were unchanged during collection. Tor
Browser used its `Standard` security level and a New Identity before every
case. Firefox used a dedicated unsigned-in profile and a fresh private window
for each case. No warning was bypassed, no login or form interaction occurred,
and no browser reload was used.

## Procedural evidence

All five cases completed the three primary observations in their assigned
order. Every paired window was under five minutes, comfortably within the
15-minute limit. One scanner invocation was used per case, and all browser
tasks reached a stable outcome without a protocol-defined retry.

The selected cases exercised the rubric's normal-content path, deliberate HTTP
refusal/status paths, and TLS certificate refusal paths. Scanner and browser
labels could be compared without treating the tools as the same instrument.
The conditional scanner clearnet result and nullable `tor_specific` value were
preserved exactly rather than inferred from prose.

Five minimized private structured objects passed checks for required keys,
nested browser keys, frozen order, paired-window duration, disabled diagnostic
use, owner-only permissions, and exact preservation of scanner verdict,
attempt, clearnet-control, `tor_specific`, and body-limit values.

## What the dry run exposed

The first case did not capture exact browser action timestamps. The available
coordinator bounds established order and paired-window compliance, but not the
precise browser start and end. Later cases used explicit timestamped handoffs.

The original observation form repeated shared browser fields such as
`meaningful_content_reached`. That is ambiguous in a flat JSON object. The
private dry-run objects used separate `tor_browser` and `ordinary_browser`
objects, making the two values unambiguous.

`time_to_meaningful_content_seconds` cannot represent the useful timing of a
stable refusal or certificate boundary because meaningful content is never
reached. Approximate stable-outcome timing therefore had to remain in concise
notes during the dry run.

Screenshots were unnecessary. A small number were captured outside the study
root during two case cycles even though screenshots were disabled by default.
They contained only deliberately public test-endpoint or browser-interface
material, were not copied into study storage, and were deleted. Subsequent
observations used structured verbal reports only.

Closing the final Firefox window did not terminate the dedicated Firefox
process. The verified task-specific process was stopped gracefully before its
profile was deleted. Future closeout should verify process termination rather
than infer it from window state.

The self-signed-certificate Tor Browser observation took substantially longer
to reach its stable warning than the corresponding ordinary-browser
observation. The cause is unknown. A proposed New Identity repeat was declined
because it would have changed the condition and exceeded the frozen
interaction budget. The delay is preserved as uncertainty, not attributed to
an exit or client mechanism.

## Single post-run revision

`TACP-0.2` is the one evidence-driven revision permitted after the dry run. It:

1. defines separate `tor_browser` and `ordinary_browser` objects for JSON;
2. adds `time_to_stable_outcome_seconds` while retaining
   `time_to_meaningful_content_seconds`; and
3. requires action-time start and end capture, with null plus a visible
   deviation when exact capture fails.

These changes address the collection defects directly. They do not recode or
retroactively alter the `TACP-0.1` dry-run records.

## Data disposition

Raw scanner JSONL, stderr, one-case target files, and the dedicated Firefox
profile remained outside Git in owner-only storage during collection. After
the five structured objects passed their row audit, those raw artifacts were
permanently deleted. The temporary scanner Tor service was stopped. The empty
raw directory remains owner-only; the five minimized structured objects remain
private under the approved retention schedule.

No raw measurement artifact, screenshot, browser session data, target IP, or
private observation row was added to the repository.

## Residual limitations

- Five purpose-built cases test procedure, not accuracy or generalizability.
- Scanner and Tor Browser observations did not share a proven exit.
- Separate scanner attempts do not prove distinct exits.
- Artificial HTTP status endpoints do not establish organic rate limiting or
  operator policy.
- Certificate-boundary cases do not test behavior after a warning bypass.
- The unexplained Tor Browser delay supports no causal claim.
- `TACP-0.2` is frozen as the methodological basis for issue #33, but live
  issue #33 collection remains separately unauthorized.

## Human freeze decision

Joseph Lorenzo Hall accepted this sanitized note and the single `TACP-0.2`
revision on 2026-08-30. The protocol is `FROZEN FOR ISSUE #33`. This decision
does not authorize the issue #33 pilot or any additional live collection.
