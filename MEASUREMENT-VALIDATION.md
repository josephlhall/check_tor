# Validating the `check_tor` Measurement Model

> **Status:** Research roadmap; issue #32 completed the protocol freeze and
> five-case dry run. Issue #33 completed a deliberately stratified 26-case
> pilot, private analysis, human-reviewed public calibration note, and final
> repository baseline-parity proof. The closed
> protocol work is tracked in
> [issue #32](https://github.com/josephlhall/check_tor/issues/32), and the
> completed pilot and follow-up are tracked in
> [issue #33](https://github.com/josephlhall/check_tor/issues/33).
> The governed protocol packet and sanitized dry-run evidence are in
> [VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md),
> [ETHICS-AND-DATA-STEWARDSHIP.md](ETHICS-AND-DATA-STEWARDSHIP.md), and
> [REFERENCE-ENDPOINTS.md](REFERENCE-ENDPOINTS.md), with procedural evidence in
> [VALIDATION-DRY-RUN.md](VALIDATION-DRY-RUN.md), with the pilot design in
> [VALIDATION-PILOT-MANIFEST.md](VALIDATION-PILOT-MANIFEST.md) and aggregate
> findings in [VALIDATION-PILOT-RESULTS.md](VALIDATION-PILOT-RESULTS.md).
> `TACP-0.2` remains frozen; the completed pilot does not authorize other live
> measurement.
> **Purpose:** Define what `check_tor` can legitimately claim, compare its verdicts with practical access in Tor Browser, and improve interpretation before adding more product features.
> **Scope:** Methodology and calibration, not a promise of validated accuracy.

## Why this work matters

`check_tor` is now well tested as software: it has deterministic offline core and integration suites, structured JSONL output, cross-platform CI, and explicit handling of operational target data. The next important question is not whether the code follows its rules. It is whether the rules measure the real-world phenomenon we care about.

The scanner observes sites through `curl` over Tor. When a block-like result persists across its configured Tor attempts, it compares that result with a non-Tor `curl` control. A human Tor Browser user is a different measurement instrument. Tor Browser has browser-specific TLS and HTTP fingerprints, JavaScript, cookies, session state, challenge-solving behavior, and rendering logic that `curl` does not reproduce.

The goal of this work is therefore **not to prove that `check_tor` is right**. It is to determine:

- what the scanner directly measures;
- what each verdict predicts about practical access in Tor Browser;
- where the scanner is systematically optimistic or pessimistic;
- which disagreements come from Tor exit reputation, client fingerprinting, browser behavior, or changing conditions;
- how the tool and its documentation should describe those limits.

## The central measurement question

Several related questions can easily be conflated:

1. **Does the server accept HTTP traffic from Tor exits?**
2. **Does the site treat automated Tor traffic worse than comparable automated non-Tor traffic?**
3. **Can a human using Tor Browser reach and use the site?**
4. **Is a Tor user materially disadvantaged compared with an ordinary browser user?**

The current scanner is strongest at question 2. Public-interest uses often care most about questions 3 and 4.

The validation study should measure the gap between them rather than assuming they are equivalent.

## What this project is not

This work is not intended to:

- estimate how much of the Internet blocks Tor;
- assess or rank organizations or applicants;
- use live or historical operational candidate lists;
- reproduce every behavior of every browser, WAF, CDN, or edge network;
- bypass access controls, CAPTCHAs, or anti-abuse systems;
- turn `check_tor` into a browser-automation framework;
- add a feature or configuration knob for every observed edge case;
- declare a verdict “accurate” merely because two automated clients agree.

The initial study should use deliberately selected public sites and controlled test endpoints. Operational target data must remain outside the repository.

## Measurement principles

### 1. Validate claims, not just labels

A verdict can be valid even when it does not exactly match the browser outcome, provided its wording accurately describes what the scanner observed.

For example, if repeated automated Tor requests receive HTTP 403 responses but Tor Browser succeeds after an interactive challenge, the scanner did observe repeated refusal of non-browser Tor traffic. The problem would be describing that result as proof that a human Tor Browser user is completely blocked.

A successful validation effort may therefore change verdict language or documentation without changing classification code.

### 2. Treat browser access as graded, not binary

A human experience should initially be classified using a small rubric:

- **Normal:** the public task succeeds without meaningful intervention.
- **Friction:** the public task succeeds after a short delay, retry, browser challenge, or similar step.
- **Severely degraded:** some content loads, but meaningful use is impaired or unreliable.
- **Blocked:** no meaningful public content can be reached after the defined attempts.
- **Inconclusive:** the result cannot be interpreted fairly because of login requirements, a broken origin, geographic behavior, inconsistent conditions, or another confounder.

The study should define a successful public task before data collection. For the first pilot, a conservative definition could be:

> The primary public page reaches meaningful content, required first-party resources load, and one ordinary public navigation action succeeds without entering credentials or submitting personal data.

### 3. Compare Tor and non-Tor browser experience

Tor Browser alone is not enough. A difficult experience may affect every visitor rather than Tor users specifically.

Each case should pair:

- the existing `check_tor` scan;
- a manual observation in Tor Browser;
- a manual observation in an ordinary browser over a non-Tor connection.

This mirrors the scanner’s clearnet-control logic and allows the study to ask whether the Tor user is treated materially worse.

### 4. Keep observations close together in time

WAF decisions, origin health, rate limits, challenges, and Tor exit reputation can change quickly. Scanner and browser observations should occur within a defined time window, ideally minutes rather than hours.

The study should record exact UTC times and treat large time gaps as a limitation.

### 5. Do not let the test itself create the outcome

Repeated scanner requests may trigger rate limits or alter WAF state before a browser test. Browser challenges and cookies may also change subsequent behavior.

The pilot should explicitly investigate order effects by alternating or randomizing whether the scanner or browser observation happens first. Tests should remain low-volume and non-invasive.

### 6. Separate ecological comparison from same-exit experiments

A normal Tor Browser session and a `check_tor` scan will often use different Tor exits. That is appropriate for the initial ecological question: “Does the scanner describe the practical access available to a Tor Browser user around the same time?”

For selected disagreements, a later targeted experiment may attempt a same-exit comparison to distinguish:

- exit-IP reputation;
- browser/client fingerprinting;
- JavaScript or cookie behavior;
- session state;
- protocol negotiation.

Same-exit testing is a second-stage diagnostic technique, not a prerequisite for the first pilot.

### 7. Freeze the protocol before interpreting results

Before collecting the main pilot sample, write down:

- the scanner version or Git commit;
- scanner settings;
- Tor, `curl`, Tor Browser, and ordinary-browser versions;
- browser security level;
- the human-experience rubric;
- the number of attempts and circuits;
- the observation time window;
- inclusion and exclusion rules;
- the fields to record.

Any deviations should be logged rather than silently normalized after seeing results.

## Initial hypotheses by verdict

These are hypotheses to test, not established conclusions.

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

## Agreement and disagreement categories

The study should not reduce every comparison to “correct” or “incorrect.” A more useful classification is:

- **Strong agreement:** scanner and browser indicate the same practical outcome.
- **Acceptable semantic agreement:** the labels differ, but the scanner correctly identifies the relevant friction or impairment.
- **Scanner pessimistic:** the scanner suggests a block or severe failure while Tor Browser completes the task.
- **Scanner optimistic:** the scanner passes while Tor Browser is blocked or materially degraded.
- **Exit-dependent disagreement:** results change mainly with Tor exit identity or reputation.
- **Client-dependent disagreement:** browser capabilities, fingerprint, JavaScript, cookies, or session state explain the difference.
- **Time-dependent disagreement:** changing conditions make the paired observations incomparable.
- **Inconclusive:** evidence is insufficient to attribute the difference.

The most important cases are scanner optimism, because they risk overlooking harm to Tor users, and scanner pessimism, because they risk overstating a site-wide block.

## Proposed validation program

### Phase 0: Completed measurement contract and dry run

Issue #32 completed this phase on 2026-08-30. Its authoritative measurement
contract and per-case procedure are in
[VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md); the governance policy,
endpoint catalog, and sanitized procedural evidence are linked from the status
note above. The pre-dry-run rationale below is retained as planning history,
not as an alternative live procedure.

The work began by drafting a concise statement of what `check_tor` claims:

A plausible starting point is:

> `check_tor` measures how a site responds to automated HTTP requests over Tor. For persistent block-like results, it compares that response with an automated non-Tor request and identifies cases where the Tor client is treated worse. Its verdicts approximate, but do not reproduce, a human Tor Browser user’s experience.

Completed preparation:

- Review every verdict description in the README.
- Separate direct observations from inferences.
- Identify wording that implies more about human browser access than the scanner observes.
- Record the exact tool version and default settings to be validated.
- Decide whether the study evaluates the current defaults or a fixed explicit
  configuration. The scanner defaults to `localhost:9050`, three Tor attempts,
  first/retry/clearnet timeouts of 60/30/20 seconds, and an enabled clearnet
  control. The corresponding command-line settings may be frozen explicitly;
  the HTTP request profile and 1 MiB response inspection cap remain fixed.

**Completed output:** a governed measurement contract and frozen per-case
protocol (`TACP-0.2`).

### Phase 1: Completed stratified manual pilot (issue #33)

Issue #33 completed 26 manually observed cases on 2026-09-07 under its
human-approved [pilot manifest](VALIDATION-PILOT-MANIFEST.md), separate live
authority, and `TACP-0.2`. The aggregate evidence and interpretation limits are
in [VALIDATION-PILOT-RESULTS.md](VALIDATION-PILOT-RESULTS.md). No browser
automation or scanner change entered the pilot.

The accepted design selected roughly 20–30 public cases, deliberately
stratified rather than random. It sought outcomes likely to expose disagreement:

- several `PASS` cases;
- several `CHALLENGE` cases;
- several `FAIL` cases;
- representative `RATE LIMIT`, `DROP`, and `TIMEOUT` cases;
- cases with a conclusive clearnet comparison;
- cases with known or suspected Cloudflare, Akamai, Imperva/Incapsula, Sucuri, custom WAF, and no obvious WAF.

A random Internet sample would probably yield many ordinary passes and teach little about calibration. The pilot is an instrument study, not a prevalence estimate.

For each case, the frozen procedure required the reviewer to:

1. Record the case and environment metadata.
2. Run `check_tor` using the frozen configuration and JSONL output.
3. Observe the site manually in Tor Browser using the defined rubric.
4. Observe the site manually in an ordinary browser.
5. Repeat across the planned number of Tor identities or sessions.
6. Classify agreement or disagreement.
7. Write a short causal hypothesis for any disagreement.
8. Mark uncertainty explicitly.

**Completed output:** an aggregate calibration table and reviewed disagreement
interpretations in [VALIDATION-PILOT-RESULTS.md](VALIDATION-PILOT-RESULTS.md).

### Phase 2: Build controlled reference cases

Real sites provide ecological realism but rarely reveal the mechanism with certainty. Controlled endpoints can test whether the scanner recognizes conditions intentionally created by the operator.

Potential controlled behaviors include:

- ordinary success over Tor and non-Tor;
- deliberate HTTP 401/403 for Tor exits;
- deliberate HTTP 429 rate limiting;
- a known browser challenge;
- connection reset or empty reply;
- delayed response or tarpit behavior;
- invalid or expired TLS configuration;
- behavior that differs by Tor exit IP;
- behavior that differs by client fingerprint or browser capability.

Controlled endpoints should be low-risk, clearly documented, and operated with permission. They should not become a general-purpose anti-Tor or evasion testbed.

**Output:** a small reference corpus with known expected mechanisms.

### Phase 3: Expand only after the pilot teaches us how

The pilot should answer whether the rubric is workable and which disagreements matter. Only then should the sample expand.

Possible later dimensions:

- more cases within each scanner verdict;
- multiple dates to measure temporal stability;
- multiple Tor Browser security levels;
- multiple exit countries or regions;
- same-exit comparisons for selected disagreements;
- additional edge/WAF providers;
- a second human reviewer for a subset of cases;
- repeatability measurements across operators and machines.

Do not choose a large sample size before the pilot reveals the variance and disagreement structure.

### Phase 4: Calibrate the product and documentation

The primary outputs may be interpretive rather than algorithmic:

- an evidence-based interpretation guide for each verdict;
- documented sources of false positives and false negatives;
- revised README language;
- a stable `METHODOLOGY.md`;
- examples of common disagreement patterns;
- code changes only where evidence shows a correctable classification problem;
- regression tests for any deterministic bug uncovered by the study.

The tool should not be modified merely to maximize agreement with a small sample.

## Proposed observation record

The frozen observation record in
[VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md) is authoritative for any
approved collection. The following flat sketch predates the completed dry run
and is retained as planning history; do not use it in place of the protocol's
separate browser records and required fields.

Suggested fields:

```text
case_id
observation_date_utc
site_category
edge_or_waf_provider_if_known

check_tor_commit
check_tor_configuration
tor_version
curl_version
operating_system
scanner_start_utc
scanner_end_utc
scanner_verdict
scanner_detail
tor_attempts
clearnet_control_verdict
tor_specific
body_limited

tor_browser_version
tor_browser_security_level
tor_browser_observation_order
tor_browser_attempt_count
tor_browser_outcome
challenge_present
challenge_completed
time_to_meaningful_content
key_public_navigation_succeeded
tor_browser_notes

ordinary_browser_name_and_version
ordinary_browser_outcome
ordinary_browser_notes

agreement_category
likely_disagreement_mechanism
confidence
protocol_deviation
reviewer
```

Use `./check_tor.zsh --format jsonl` for the scanner record rather than parsing human-readable output.

## Data handling and repository boundaries

This study must not recreate the target-list problem it is meant to help solve.
The governed safeguards and operational approval rules are in
[ETHICS-AND-DATA-STEWARDSHIP.md](ETHICS-AND-DATA-STEWARDSHIP.md); the procedure
is in [VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md). The completed issue #32
authorization did not extend beyond its five cases. `TACP-0.2` is frozen for
issue #33, but live collection still requires separate authorization. This
section remains planning context rather than collection authority.

- Do not use non-public operational or historical target lists.
- Use public validation cases selected specifically for the study or controlled endpoints.
- Keep raw JSONL, screenshots, browsing notes, and any sensitive target lists outside this repository.
- Do not commit cookies, challenge tokens, IP addresses, authentication material, or personal information.
- Commit only the protocol, sanitized aggregate findings, and deliberately public case descriptions.
- Use anonymous case IDs if a public domain’s inclusion could itself create an unwanted association.
- Keep request volume low and avoid logging in, submitting forms, solving CAPTCHAs through third-party services, or attempting to circumvent access controls.

The private study-data root and retention schedule must be approved before
collection. Raw measurement artifacts must remain outside this repository;
adding an in-tree study directory to `.gitignore` is not an acceptable
substitute.

## Current execution sequence

### Completed steps 1–4: prepare and dry-run the procedure

Issue #32 completed the bounded preparation and dry run on 2026-08-30. The
frozen protocol, governance policy, endpoint catalog, and dry-run note are the
durable outputs; their current status is summarized at the top of this file.
The original sequence is retained below to explain the completed work.

#### Step 1: Freeze the instrument

- Record the release, commit SHA, default settings, and supported override settings.
- Run the complete offline test suite and CI.
- Avoid unrelated scanner changes during the pilot.

#### Step 2: Draft the measurement contract

Write one page answering:

- What does `check_tor` directly observe?
- What does it infer?
- What does it not reproduce about Tor Browser?
- What claim is appropriate for each verdict?
- What would count as scanner optimism or pessimism?

Review this against the README before collecting data.

#### Step 3: Create the human-observation rubric and form

- Turn the proposed fields above into a simple Markdown or spreadsheet form.
- Define “normal,” “friction,” “severely degraded,” “blocked,” and “inconclusive.”
- Define the minimum public navigation task.
- Fix the browser versions and Tor Browser security level.
- Decide the number of Tor identities or attempts.
- Decide the maximum time per case.

#### Step 4: Run a five-case dry run

Completed on 2026-08-30 under `TACP-0.1`. See the sanitized
[dry-run procedural record](VALIDATION-DRY-RUN.md). The resulting single
revision, `TACP-0.2`, was accepted and frozen for issue #33 on 2026-08-30.

The five deliberately public cases represented different verdicts. Their purpose
was not to draw conclusions, but to find procedural problems:

- Is the rubric understandable?
- Can observations be completed consistently?
- Does scanner-first testing alter browser behavior?
- Is the time window practical?
- Are important fields missing?
- Are screenshots or raw logs actually necessary?
- Can the process be repeated without creating excessive traffic?

The protocol was revised once after the dry run and then frozen for issue #33.

### Completed step 5: Run the 20–30 case manual pilot

The human-approved issue #33 manifest supplied the experiment-level sampling,
endpoint, environment, and batch decisions that the frozen protocol does not
fix. Collection stopped after 26 includable cases when the frozen stratum
targets were satisfied.

- The sample was stratified.
- Scanner/browser order was preassigned and balanced.
- Paired observations remained within the frozen window.
- Uncertainty and protocol deviations remained visible.
- Disagreements were reviewed without changing the scanner mid-pilot.

### Completed step 6: Review disagreements before writing code

Group disagreements by likely mechanism:

- exit reputation;
- browser challenge solving;
- TLS or HTTP fingerprint;
- JavaScript or cookie state;
- protocol behavior;
- timing or origin instability;
- classification bug;
- documentation overclaim.

The private review found one medium-confidence scanner-optimistic case, no
scanner-pessimistic case, and five inconclusive comparisons. It retained
client-dependent and exit-dependent explanations as competing hypotheses and
found no basis for a scanner code change from this pilot alone.

The review considered separately whether each pattern calls for:

- no change;
- clearer documentation;
- a verdict wording change;
- a classifier change;
- a new regression test;
- a targeted same-exit experiment.

### Completed step 7: Prepare and review the calibration note

The final [pilot calibration results](VALIDATION-PILOT-RESULTS.md) are the first
evidence-based deliverable rather than a new feature release. Human review and
repository proof completed on 2026-09-07. The note states:

- what sample was studied;
- what protocol was used;
- how often each verdict corresponded to each human-experience category;
- the main disagreement mechanisms;
- what conclusions each verdict does and does not support;
- what changed in the tool or documentation as a result;
- the limits of the study.

## Questions the pilot should answer

At minimum:

1. Does `PASS` strongly predict successful Tor Browser access?
2. When `CHALLENGE` is reported, how often is the challenge visible and solvable in Tor Browser?
3. How often does `FAIL` mean complete human blocking versus browser-resolvable friction?
4. Are `DROP` and `TIMEOUT` more or less predictive of browser failure than HTTP refusal?
5. How often are apparent blocks exit-specific rather than site-wide?
6. How often does the clearnet comparison correctly distinguish Tor-specific treatment from generic automation hostility?
7. What are the most common scanner-pessimistic cases?
8. Are there any scanner-optimistic cases?
9. Which disagreements can be explained without changing the classifier?
10. Which verdict descriptions should be narrowed or clarified?

The [pilot calibration results](VALIDATION-PILOT-RESULTS.md) answer these
questions where the selected evidence permits and mark `CHALLENGE`, `DROP`,
`TIMEOUT`, scanner pessimism, and causal mechanism questions as unresolved where
the pilot cannot support an answer.

## What success looks like

Success is not a perfect agreement percentage.

The work succeeds if it produces:

- a defensible statement of what `check_tor` measures;
- a repeatable manual access-comparison protocol;
- an interpretation guide grounded in observation;
- known disagreement patterns;
- explicit limits on what each verdict permits a user to conclude;
- targeted fixes only where evidence warrants them;
- a clear basis for deciding whether a larger study is worth doing.

The desired endpoint is a tool whose results are useful because their meaning and limits are understood—not because the tool has accumulated more switches.

## Model-assisted interpretation

This section is a **planned extension** to the current protocol, not an established result.
A fast implementation-oriented model can serve as a hypothesis and consistency
aid for interpretation work, while all claims remain grounded in collected
observations.

Use it where it adds value in six places:

- Decision-surface drafting:
  Convert verdict-level evidence to human-experience labels using explicit fields the scanner already outputs
  (`verdict`, circuit outcomes, `body_limited`, clearnet comparison fields), then manually review each mapping.

- Disagreement atlas curation:
  Normalize each mismatch into a repeated tuple:
  `scanner verdict`, `browser outcomes`, `likely mechanism`, `alternative mechanism`, `next probe`.

- Pilot site-selection planning:
  Propose candidate cases that increase disagreement coverage (not just PASS-heavy cases),
  including exit-sensitive, challenge-heavy, and automation-hostile-but-not-Tor-specific examples.

- Edge-case probe design:
  Suggest targeted scenarios with explicit hypotheses and falsification criteria
  (e.g., challenge-only behavior, exit-reputation sensitivity, slow-with-friction degradation).

- Contract-language guardrails:
  Draft three-way wording for each interpretation: what is directly observed, what is inferred,
  and what is not measured by this protocol.

- Per-case evidence templates:
  Create a stable note structure for scan fields, browser outcomes, disagreement class, confidence,
  and follow-up action, reducing reviewer variance in Step 6.

Suggested workflow:

1. Generate one model-assisted pass after each 5–10 paired observations.
2. Keep only high-confidence hypotheses as candidate follow-up tasks.
3. Re-check every candidate against raw data, the frozen protocol, and this document’s success criteria.
4. Add only protocol or documentation changes where evidence and review support them.

Model output should never replace raw observation. Human review remains the sole final authority for protocol decisions.
