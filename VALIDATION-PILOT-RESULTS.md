# Tor Access Comparison Pilot: Calibration Results

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

This note reports reviewed aggregate evidence from a bounded comparison of
`check_tor`, Tor Browser, and an ordinary browser. It does not publish private
rows, scanner JSONL, targets, screenshots, session data, observed IP addresses,
or private storage paths.

The results calibrate what the scanner's verdicts meant in these deliberately
selected cases. They are not an accuracy score, a prevalence estimate, or a
claim about any operator's intent or policy.

## Study design

The pilot completed 26 low-volume cases under the frozen
[Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md). The sample was
deliberately stratified to exercise scanner verdicts that a random sample might
rarely produce. It contained 14 unique approved catalog entries: four appeared
once, eight appeared twice, and two appeared three times. Repeated cases are
therefore not independent sites.

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

These are raw counts within the selected pilot strata.

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

Agreement was classified against Tor Browser's practical outcome:

| Agreement category | Cases |
|---|---:|
| `STRONG_AGREEMENT` | 20 |
| `ACCEPTABLE_SEMANTIC_AGREEMENT` | 0 |
| `SCANNER_OPTIMISTIC` | 1 |
| `SCANNER_PESSIMISTIC` | 0 |
| `INCONCLUSIVE` | 5 |

These counts must not be converted into a general scanner “accuracy” rate. The
case selection intentionally overrepresented controlled failure conditions,
and several catalog entries were repeated.

## Interpretation by verdict

### `PASS`

In 12 of the 14 `PASS` cases, both browsers completed the public task normally.
One `PASS` case was inconclusive because the required browser navigation was
not performed. In the remaining case, ordinary Firefox completed the task but
Tor Browser reached no meaningful content; this is the pilot's one
`SCANNER_OPTIMISTIC` result.

That disagreement shows why `PASS` cannot guarantee Tor Browser access. A
client-dependent explanation leads the private interpretation, while different
Tor exits remain a competing explanation. The pilot did not use a fixed shared
exit or an authorized diagnostic request, so it does not establish either
mechanism.

### `CHALLENGE`

All three `CHALLENGE` observations came from a purpose-built HTTP success
response that the scanner classifies as challenge-like. Both browsers displayed
a stable empty page without a visible status, challenge, or meaningful content,
so every comparison remained `INCONCLUSIVE` under the visual rubric.

This result identifies a measurement-boundary problem, not observed challenge
friction: an automated HTTP client can classify response semantics that the
frozen browser task cannot see. The pilot therefore does not answer how often a
user-visible challenge is passable in Tor Browser.

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

## What the pilot supports

- `PASS` was usually accompanied by normal Tor Browser access in this sample,
  but it did not guarantee browser task completion.
- Controlled `FAIL`, `RATELIMIT`, and `CERT` conditions aligned with practical
  blockage in both browsers in every observed case.
- `CHALLENGE` can describe scanner-visible HTTP semantics without implying that
  a human saw an interactive challenge.
- Agreement on blockage does not establish why the blockage occurred.
- The scanner and browser instruments answer related but non-equivalent
  questions; the existing README distinction remains necessary.

The pilot did not reveal a deterministic classifier defect and does not support
changing scanner code merely to fit this small sample.

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
