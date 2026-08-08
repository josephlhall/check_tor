# Validating the `check_tor` Measurement Model

> **Status:** Working research plan
> **Purpose:** Define what `check_tor` can legitimately claim, test how its verdicts correspond to real Tor Browser experience, and improve interpretation before adding more product features.
> **Scope:** Methodology and calibration, not a promise of validated accuracy.

## Why this work matters

`check_tor` is now well tested as software: it has deterministic offline core and integration suites, structured JSONL output, cross-platform CI, and explicit handling of operational target data. The next important question is not whether the code follows its rules. It is whether the rules measure the real-world phenomenon we care about.

The scanner observes sites through `curl` over Tor. When a block-like result persists across its configured Tor attempts, it compares that result with a non-Tor `curl` control. A human Tor Browser user is a different measurement instrument. Tor Browser has browser-specific TLS and HTTP fingerprints, JavaScript, cookies, session state, challenge-solving behavior, and rendering logic that `curl` does not reproduce.

The goal of this work is therefore **not to prove that `check_tor` is right**. It is to determine:

- what the scanner directly measures;
- what each verdict predicts about actual user experience;
- where the scanner is systematically optimistic or pessimistic;
- which disagreements come from Tor exit reputation, client fingerprinting, browser behavior, or changing conditions;
- how the tool and its documentation should describe those limits.

## The central measurement question

Several related questions can easily be conflated:

1. **Does the server accept HTTP traffic from Tor exits?**
2. **Does the site treat automated Tor traffic worse than comparable automated non-Tor traffic?**
3. **Can a human using Tor Browser reach and use the site?**
4. **Is a Tor user materially disadvantaged compared with an ordinary browser user?**

The current scanner is strongest at question 2. Project Galileo and other public-interest uses often care most about questions 3 and 4.

The validation study should measure the gap between them rather than assuming they are equivalent.

## What this project is not

This work is not intended to:

- estimate how much of the Internet blocks Tor;
- assess or rank Project Galileo applicants;
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

### 2. Treat usability as graded, not binary

A human experience should initially be classified using a small rubric:

- **Normal:** public content loads and can be used without meaningful intervention.
- **Friction:** the site becomes usable after a short delay, retry, browser challenge, or similar step.
- **Severely degraded:** some content loads, but meaningful use is impaired or unreliable.
- **Blocked:** no usable public content can be reached after the defined attempts.
- **Inconclusive:** the result cannot be interpreted fairly because of login requirements, a broken origin, geographic behavior, inconsistent conditions, or another confounder.

The study should define “usable” before data collection. For the first pilot, a conservative definition could be:

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

A normal Tor Browser session and a `check_tor` scan will often use different Tor exits. That is appropriate for the initial ecological question: “What does a real user experience around the same time?”

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
| `PASS` | A successful automated response over Tor after redirects, possibly after an earlier exit-specific problem | Strong predictor that Tor Browser reaches usable content |
| `CHALLENGE` | The edge returned a recognizable challenge or challenge-like response | Predictor of user friction; browser may solve or pass the challenge |
| `RATELIMIT` (`RATE LIMIT` in text output) | HTTP 429 over Tor | Predictor of unreliable or severely degraded access, especially on shared exits |
| `FAIL` | Repeated HTTP 401/403 responses across the configured Tor attempts | Strong evidence that automated Tor requests are refused; may overstate complete human blocking |
| `DROP` | Connection reset, empty reply, or truncated transfer | Predictor of serious impairment; browser behavior may still differ |
| `TIMEOUT` | No timely usable response | Predictor of degradation, but sensitive to patience, protocol, origin health, and exit conditions |
| `CERT` (`CERT ERROR` in text output) | TLS certificate validation prevented an HTTP exchange | Likely user-visible security failure, though browsers may present different interstitial behavior |
| `SOCKS` (`SOCKS ERROR` in text output) | The Tor exit could not complete the connection | Often exit-specific or network-specific rather than evidence of site policy |
| `WARN` (`WARNING` in text output) | The result fell outside a confident classification | Should remain inconclusive unless manual review establishes a recurring pattern |

## Agreement and disagreement categories

The study should not reduce every comparison to “correct” or “incorrect.” A more useful classification is:

- **Strong agreement:** scanner and browser indicate the same practical outcome.
- **Acceptable semantic agreement:** the labels differ, but the scanner correctly identifies the relevant friction or impairment.
- **Scanner pessimistic:** the scanner suggests a block or severe failure while Tor Browser is usable.
- **Scanner optimistic:** the scanner passes while Tor Browser is blocked or materially degraded.
- **Exit-dependent disagreement:** results change mainly with Tor exit identity or reputation.
- **Client-dependent disagreement:** browser capabilities, fingerprint, JavaScript, cookies, or session state explain the difference.
- **Time-dependent disagreement:** changing conditions make the paired observations incomparable.
- **Inconclusive:** evidence is insufficient to attribute the difference.

The most important cases are scanner optimism, because they risk overlooking harm to Tor users, and scanner pessimism, because they risk overstating a site-wide block.

## Proposed validation program

### Phase 0: Define the measurement contract

Before running a study, draft a concise statement of what `check_tor` currently claims.

A plausible starting point is:

> `check_tor` measures how a site responds to automated HTTP requests over Tor. For persistent block-like results, it compares that response with an automated non-Tor request and identifies cases where the Tor client is treated worse. Its verdicts approximate, but do not reproduce, a human Tor Browser user’s experience.

Tasks:

- Review every verdict description in the README.
- Separate direct observations from inferences.
- Identify wording that implies more about human usability than the scanner observes.
- Record the exact tool version and default settings to be validated.
- Decide whether the study evaluates the current defaults or a fixed explicit
  configuration. The scanner defaults to `localhost:9050`, three Tor attempts,
  first/retry/clearnet timeouts of 60/30/20 seconds, and an enabled clearnet
  control. The corresponding command-line settings may be frozen explicitly;
  the HTTP request profile and 1 MiB response inspection cap remain fixed.

**Output:** a one-page measurement contract and a frozen pilot protocol.

### Phase 1: Run a small manual pilot

Start manually, not with browser automation.

Select roughly 20–30 public cases, deliberately stratified rather than random. Oversample the outcomes most likely to expose disagreement:

- several `PASS` cases;
- several `CHALLENGE` cases;
- several `FAIL` cases;
- representative `RATE LIMIT`, `DROP`, and `TIMEOUT` cases;
- cases with a conclusive clearnet comparison;
- cases with known or suspected Cloudflare, Akamai, Imperva/Incapsula, Sucuri, custom WAF, and no obvious WAF.

A random Internet sample would probably yield many ordinary passes and teach little about calibration. The pilot is an instrument study, not a prevalence estimate.

For each case:

1. Record the case and environment metadata.
2. Run `check_tor` using the frozen configuration and JSONL output.
3. Observe the site manually in Tor Browser using the defined rubric.
4. Observe the site manually in an ordinary browser.
5. Repeat across the planned number of Tor identities or sessions.
6. Classify agreement or disagreement.
7. Write a short causal hypothesis for any disagreement.
8. Mark uncertainty explicitly.

**Output:** a small calibration table and a set of disagreement case notes.

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

The pilot should answer whether the rubric is usable and which disagreements matter. Only then should the sample expand.

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

The raw study record should be structured enough to compare cases but simple enough for manual use.

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

- Do not use live or historical Galileo candidate lists.
- Use public validation cases selected specifically for the study or controlled endpoints.
- Keep raw JSONL, screenshots, browsing notes, and any sensitive target lists outside this repository.
- Do not commit cookies, challenge tokens, IP addresses, authentication material, or personal information.
- Commit only the protocol, sanitized aggregate findings, and deliberately public case descriptions.
- Use anonymous case IDs if a public domain’s inclusion could itself create an unwanted association.
- Keep request volume low and avoid logging in, submitting forms, solving CAPTCHAs through third-party services, or attempting to circumvent access controls.

A possible local layout is:

```text
~/check_tor-validation/
├── protocol/
├── raw-jsonl/
├── browser-notes/
├── screenshots/
└── analysis/
```

That directory should remain outside the Git repository. If any local study-output directory is created inside the checkout for convenience, add it to `.gitignore` before collecting data.

## First steps after the bounded implementation work

The first milestone should be deliberately small.

### Step 1: Freeze the instrument

- Record the release, commit SHA, default settings, and supported override settings.
- Run the complete offline test suite and CI.
- Avoid unrelated scanner changes during the pilot.

### Step 2: Draft the measurement contract

Write one page answering:

- What does `check_tor` directly observe?
- What does it infer?
- What does it not reproduce about Tor Browser?
- What claim is appropriate for each verdict?
- What would count as scanner optimism or pessimism?

Review this against the README before collecting data.

### Step 3: Create the human-observation rubric and form

- Turn the proposed fields above into a simple Markdown or spreadsheet form.
- Define “normal,” “friction,” “severely degraded,” “blocked,” and “inconclusive.”
- Define the minimum public navigation task.
- Fix the browser versions and Tor Browser security level.
- Decide the number of Tor identities or attempts.
- Decide the maximum time per case.

### Step 4: Run a five-case dry run

Choose five deliberately public cases representing different verdicts. The purpose is not to draw conclusions. It is to find procedural problems:

- Is the rubric understandable?
- Can observations be completed consistently?
- Does scanner-first testing alter browser behavior?
- Is the time window practical?
- Are important fields missing?
- Are screenshots or raw logs actually necessary?
- Can the process be repeated without creating excessive traffic?

Revise the protocol once after the dry run, then freeze it for the pilot.

### Step 5: Run the 20–30 case manual pilot

- Use a stratified sample.
- Alternate or randomize scanner/browser order.
- Keep paired observations close in time.
- Record uncertainty and protocol deviations.
- Investigate disagreements, but do not change the scanner mid-pilot.

### Step 6: Review disagreements before writing code

Group disagreements by likely mechanism:

- exit reputation;
- browser challenge solving;
- TLS or HTTP fingerprint;
- JavaScript or cookie state;
- protocol behavior;
- timing or origin instability;
- classification bug;
- documentation overclaim.

Decide separately whether each pattern calls for:

- no change;
- clearer documentation;
- a verdict wording change;
- a classifier change;
- a new regression test;
- a targeted same-exit experiment.

### Step 7: Publish a calibration note

The first useful deliverable should be a short evidence-based note, not a new feature release. It should state:

- what sample was studied;
- what protocol was used;
- how often each verdict corresponded to each human-experience category;
- the main disagreement mechanisms;
- what conclusions each verdict does and does not support;
- what changed in the tool or documentation as a result;
- the limits of the study.

## Questions the pilot should answer

At minimum:

1. Does `PASS` strongly predict usable Tor Browser access?
2. When `CHALLENGE` is reported, how often is the challenge visible and solvable in Tor Browser?
3. How often does `FAIL` mean complete human blocking versus browser-resolvable friction?
4. Are `DROP` and `TIMEOUT` more or less predictive of browser failure than HTTP refusal?
5. How often are apparent blocks exit-specific rather than site-wide?
6. How often does the clearnet comparison correctly distinguish Tor-specific treatment from generic automation hostility?
7. What are the most common scanner-pessimistic cases?
8. Are there any scanner-optimistic cases?
9. Which disagreements can be explained without changing the classifier?
10. Which verdict descriptions should be narrowed or clarified?

## What success looks like

Success is not a perfect agreement percentage.

The work succeeds if it produces:

- a defensible statement of what `check_tor` measures;
- a repeatable manual validation protocol;
- an interpretation guide grounded in observation;
- known disagreement patterns;
- explicit limits on what each verdict permits a user to conclude;
- targeted fixes only where evidence warrants them;
- a clear basis for deciding whether a larger study is worth doing.

The desired endpoint is a tool whose results are useful because their meaning and limits are understood—not because the tool has accumulated more switches.
