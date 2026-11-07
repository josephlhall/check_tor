# Tor Access Comparison Pilot: Calibration Results

In 12 of 14 cases where `check_tor` returned `PASS`, both browsers finished the
public task. In one other `PASS` case, Tor Browser reached no meaningful
content while ordinary Firefox finished the task. All three `CHALLENGE`
results came from purpose-built HTTP 202 responses, and neither browser
displayed a challenge.

These are reviewed counts from 26 deliberately selected cases at 14 approved
endpoints, some visited more than once. The pilot shows how scanner verdicts
and browser outcomes lined up in these cases. Broader claims about scanner
accuracy, how common Tor blocking is, or an operator's intent or policy would
require other evidence.

> **Status:** HUMAN REVIEWED — REPOSITORY BASELINE PARITY VERIFIED
>
> **Issue:** [#33](https://github.com/josephlhall/check_tor/issues/33)
>
> **Protocol:** `TACP-0.2`
>
> **Pilot manifest:** [VALIDATION-PILOT-MANIFEST.md](VALIDATION-PILOT-MANIFEST.md)
>
> **Human reviewer and observer:** Joseph Lorenzo Hall
>
> **Collection date:** 2026-09-07
>
> **Review date:** 2026-09-07
>
> **Scanner baseline:** `c11c0211dc5b6e98a78cdcc38ed95d2ce5e562a6`

## Study design

The pilot completed 26 low-volume cases under the frozen
[Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md). The design favored
cases that could exercise verdicts a random sample might rarely produce. Of
the 14 approved catalog entries, four appeared once, eight appeared twice, and
two appeared three times.

Each case paired the scanner with a human observation in Tor Browser and a
fresh private window in ordinary Firefox. Thirteen cases used scanner-first
order and thirteen used Tor-Browser-first order. All 26 attempted cases remain
included; one scanner invocation failed its Tor-network preflight before the
case endpoint request and therefore has no scanner target observation.

The primary browser rubric was:

- `NORMAL`: meaningful content and the approved public navigation completed;
- `FRICTION`: the task completed after a bounded user-visible impediment;
- `SEVERELY_DEGRADED`: some content loaded, but the task remained materially
  impaired;
- `BLOCKED`: meaningful content could not be reached under the frozen task; and
- `INCONCLUSIVE`: the evidence could not support a fair classification.

## Verdict and access matrices

The first table shows the browser outcomes for each observed scanner verdict.

| Scanner observation | Tor `NORMAL` | Tor `BLOCKED` | Tor `INCONCLUSIVE` | Ordinary `NORMAL` | Ordinary `BLOCKED` | Ordinary `INCONCLUSIVE` |
|---|---:|---:|---:|---:|---:|---:|
| `PASS` | 12 | 1 | 1 | 13 | 0 | 1 |
| `CHALLENGE` | 0 | 0 | 3 | 0 | 0 | 3 |
| `FAIL` | 0 | 2 | 0 | 0 | 2 | 0 |
| `RATELIMIT` | 0 | 2 | 0 | 0 | 2 | 0 |
| `CERT` | 0 | 4 | 0 | 0 | 4 | 0 |
| No target observation | 0 | 1 | 0 | 0 | 1 | 0 |
| **Total** | **12** | **10** | **4** | **13** | **9** | **4** |

The two browsers produced the following paired outcomes:

| Tor Browser outcome | Ordinary-browser outcome | Cases |
|---|---|---:|
| `NORMAL` | `NORMAL` | 12 |
| `BLOCKED` | `BLOCKED` | 9 |
| `BLOCKED` | `NORMAL` | 1 |
| `INCONCLUSIVE` | `INCONCLUSIVE` | 4 |

The agreement table compares the scanner verdict with the Tor Browser task outcome.

| Agreement category | Cases |
|---|---:|
| `STRONG_AGREEMENT` | 20 |
| `ACCEPTABLE_SEMANTIC_AGREEMENT` | 0 |
| `SCANNER_OPTIMISTIC` | 1 |
| `SCANNER_PESSIMISTIC` | 0 |
| `INCONCLUSIVE` | 5 |

Four cases were inconclusive in both browsers. In a fifth case, both browsers
were classified `BLOCKED`, but the scanner's Tor preflight failed before
contacting the endpoint. That case had no scanner verdict to compare, so it
also counted as inconclusive for agreement.

The study deliberately overrepresented controlled failure cases. Repeat visits
to the same endpoint are related observations, so they cannot count as
independent sites. These counts describe agreement within the pilot and cannot
support a general scanner accuracy rate.

## Interpretation by verdict

### `PASS`

In 12 of the 14 `PASS` cases, both browsers completed the public task normally.
One `PASS` case was inconclusive because the required browser navigation was
not performed. In the remaining case, ordinary Firefox completed the task but
Tor Browser reached no meaningful content; this is the pilot's one
`SCANNER_OPTIMISTIC` result.

The reviewer considered a difference between the clients the leading
hypothesis. Different Tor exits were also plausible. The pilot used neither a
fixed shared exit nor a diagnostic request, so it could not isolate the cause
of the disagreement.

### `CHALLENGE`

The scanner classified the purpose-built HTTP 202 response as challenge-like.
Both browsers showed a stable, empty page with no visible status, challenge,
or meaningful content. The browser task relied on visible evidence, so all
three comparisons were `INCONCLUSIVE`. These cases show how an HTTP response
can trigger the scanner label without showing a person a challenge. They leave
open how often a Tor Browser user can get through a visible challenge.

### `FAIL`, `RATELIMIT`, and `CERT`

All eight cases in these three strata ended in `BLOCKED` outcomes in both
browsers: two `FAIL`, two `RATELIMIT`, and four `CERT`. These were deliberately
selected, repeated reference conditions. They demonstrate strong practical
agreement for those controlled cases, not how consistently the verdicts predict
behavior on ordinary sites.

One `CERT` case also illustrates that agreement on the practical result does
not prove agreement on the mechanism: the scanner and ordinary browser reached
certificate-failure semantics, while Tor Browser presented a connection
timeout. Exit-path and time-dependent explanations remain hypotheses.

For all seven `CHALLENGE`, `FAIL`, and `RATELIMIT` cases, the scanner's automated
clearnet control returned the same verdict and `tor_specific` was `false`.
Because these were purpose-built generic HTTP responses, this confirms the
control's behavior in those cases rather than establishing anything about
organic Tor-specific treatment.

### Unobserved outcomes

The pilot observed no scanner `DROP` or `TIMEOUT` verdict, no browser `FRICTION`
or `SEVERELY_DEGRADED` outcome, no acceptable-semantic agreement, and no
scanner-pessimistic case. The approved endpoint packet could not safely induce
the missing transport conditions, and collection was not expanded through
broad screening merely to fill those cells.

## Deviations and uncertainty

Five cases retained visible protocol deviations:

- two lost exact scanner timing while preserving the usable observation;
- one scanner invocation failed before its target request;
- one post-observation browser inspection may have added a request; and
- one case omitted the required public navigation in both browsers.

Two of those cases remain strongly classifiable on practical outcome and three
are inconclusive. No case was silently repaired, rerun, excluded, or assigned a
reconstructed timestamp after the outcome was known.

The balanced order split showed ten strong agreements in each order arm. The
remaining outcomes were three inconclusive cases in scanner-first order and one
optimistic plus two inconclusive cases in Tor-Browser-first order. The sample is
too small, stratified, and repeated to estimate an order effect.

## Implications for the scanner

The scanner verdict describes an automated response. The browser outcome
describes whether a person could complete the public task. Even when both
instruments indicate blockage, as in the controlled failure cases, the reason
for the blockage can differ. Keep that distinction when describing verdicts
in the README. The pilot did not reveal a deterministic classifier defect and
does not support changing scanner code to fit this small sample.

## Limits and follow-up

This was one day's work by one human reviewer on one host, with a small accepted
browser patch-version change between batches. Scanner and Tor Browser sessions
normally used different exits. The design does not isolate client, exit, time,
or origin effects, and it does not support claims about untested sites, edge
providers, regions, security levels, or future behavior.

The most useful follow-up work would be:

1. decide whether the lone optimistic pattern merits a separately governed
   client-versus-exit diagnostic study;
2. add a future reference task or instrument that can expose challenge-like
   HTTP semantics without relying only on visible page content;
3. seek safe, preapproved coverage of scanner pessimism, user-visible challenge
   friction, `FRICTION`, `SEVERELY_DEGRADED`, `DROP`, and `TIMEOUT`; and
4. add dates, reviewers, or environments only after defining how those sources
   of variation will be interpreted.

## Data disposition

Raw scanner and browser artifacts were deleted after their structured rows
passed audit. The private structured observations remain owner-only, outside
Git, and excluded from backup under the approved retention rule. They must be
deleted or receive a formally documented extension within 90 days after the
issue #33 review closes.

No scanner code, verdict rule, schema, or default changed during this pilot.
