# Tor Access Comparison Protocol

> **Status:** FROZEN FOR ISSUE #33
>
> **Protocol ID:** TACP-0.2
>
> **Dry-run approval:** Joseph Lorenzo Hall, 2026-08-30 (`TACP-0.1`)
>
> **Intended use:** Methodological basis for the completed issue #33 pilot;
> every future live use still requires its own human-approved manifest and
> explicit authority
>
> **Scanner baseline:**
> `fc13260f87c01e56db376858d90d837abcda1eaa`
>
> **Human approval:** Joseph Lorenzo Hall, 2026-08-30
>
> **Operational fields:** Resolved at preflight on 2026-08-30

This document is the normative manual protocol for comparing `check_tor`
observations with browser access outcomes. Revision `TACP-0.1` governed the
completed issue #32 dry run. The human reviewer accepted this single
evidence-driven revision as `FROZEN FOR ISSUE #33` on 2026-08-30. Issue #33
later completed collection under its separately approved manifest and live
authority; the protocol freeze alone never authorized that traffic.

The ethical and data-handling rules in
[ETHICS-AND-DATA-STEWARDSHIP.md](ETHICS-AND-DATA-STEWARDSHIP.md) can stop or
restrict any step in this protocol. Current scanner code and the documented
JSONL schema remain authoritative for what the scanner does. If those sources
conflict with this protocol, stop and record the mismatch; do not reinterpret
an observation after seeing the result.

## Purpose and study boundary

The project studies whether an automated `curl`-over-Tor scanner describes the
practical access available to a human Tor Browser user.

In plain language, this protocol compares what `check_tor` reports with what a
person can reach using Tor Browser. More technically, the five-case dry run
tests whether a small paired-instrument procedure can compare automated Tor
traffic, Tor Browser task outcomes, and ordinary-browser controls without
confusing those instruments or collecting unnecessary sensitive material.

The five-case dry run tests the **procedure**, not scanner accuracy. It may show
that a field, timing rule, rubric, order assignment, or safeguard needs revision.
It cannot establish:

- accuracy, sensitivity, specificity, or error rates;
- prevalence of Tor blocking or friction;
- a site's intent or site-wide policy;
- performance across Tor users, exits, countries, dates, or security levels;
- that the scanner and Tor Browser used the same exit;
- that separate scanner circuits used distinct exits; or
- that a verdict predicts human browser access beyond the five deliberately
  chosen cases.

The later stratified pilot in issue #33 is outside this completed five-case
dry-run evidence. Its per-case protocol prerequisite is complete: this
document completed the dry run, received its one evidence-driven revision, and
was explicitly marked `FROZEN FOR ISSUE #33`. Before any pilot collection, the human
reviewer must approve an experiment-level pilot manifest and grant separate
explicit live authority. That manifest must freeze the approved endpoints,
sample allocation or stopping rule, current environment, order schedule, batch
plan, storage boundary, and remote-observation mode without silently revising
this per-case procedure.

## Measurement contract

### Direct scanner observations

`check_tor` directly observes how its fixed `curl` request profile behaves over
a local Tor SOCKS proxy. It records `curl` and HTTP outcomes, follows redirects,
inspects a bounded response body, and classifies the result. For a persistent
block-like Tor result it normally makes a conditional automated clearnet
`curl` request.

The JSONL target record is the authoritative scanner observation. It includes:

- `schema_version`, `type`, and `target`;
- `verdict` and human-readable `detail`;
- `tor_attempts` and `tor_attempt_limit`;
- `clearnet_control.enabled`, `performed`, and nullable `verdict`;
- nullable `tor_specific`; and
- `body_limited`.

Analysis must use the structured fields. `detail` may preserve useful context,
but it is not a stable parsing interface.

### Scanner inferences

When the clearnet control is conclusive, the scanner compares verdict severity
and may set `tor_specific` to `true` or `false`. This is an inference about the
paired automated requests. It does not establish a site's broader policy, a
human browser outcome, a shared exit, or a causal mechanism.

Recognized WAF or edge signatures suggest response infrastructure or mechanism.
They do not identify who selected a policy or why.

### Human observations and hypotheses

The Tor Browser and ordinary-browser observations record whether a defined
public task succeeded under the frozen environment. Agreement categories and
causal explanations are reviewed interpretations, not scanner output.

A scanner-to-browser relationship remains a hypothesis until supported by a
larger approved study. The dry run may reveal procedural disagreements but
must not publish them as calibrated error rates.

### Claims this protocol does not support

No instrument in this study, alone or in combination, establishes:

- operator intent or anti-Tor policy;
- behavior for every path, user, session, exit, or client;
- population prevalence;
- same-exit comparison;
- unique exit use across scanner attempts;
- safety of ordinary browsers configured to use Tor; or
- permission to bypass a challenge, authentication boundary, or access control.

## Instruments

| ID | Instrument | Role | What it contributes | Principal limitation |
|---|---|---|---|---|
| I1 | `check_tor` / `curl` over Tor | Primary automated observation | Structured automated Tor outcome | Not Tor Browser; first `PASS` ends retries; circuits do not prove unique exits |
| I2 | Scanner automated clearnet `curl` control | Conditional automated control | Whether the paired automated Tor result was more severe | Runs only for persistent block-like outcomes and is not an ordinary browser |
| I3 | Tor Browser | Primary human observation | Graded browser-access outcome under a frozen Tor Browser environment | Normally uses a different exit from I1 and may vary by session or time |
| I4 | Ordinary browser over clearnet | Primary human control | Whether difficulty also affects an ordinary non-Tor browser | Different client, network path, and fingerprint from I1–I3 |
| I5 | Ordinary browser over Tor SOCKS | Diagnostic only; disabled by default | May help distinguish browser capability from Tor Browser-specific behavior | Not Tor Browser and lacks its privacy protections; carries leak and fingerprinting risk |

I5 is disabled for all five dry-run cases. Any later proposal to use it requires
a named case, a falsifiable causal question, a disposable profile, and specific
safeguards approved before collection. It would run only after I1–I4 so it
could not alter the primary observations.

## Dry-run design

### Sample purpose and size

The dry run has exactly five cases. Each case must be deliberately public or
explicitly authorized and approved through
[REFERENCE-ENDPOINTS.md](REFERENCE-ENDPOINTS.md) and the stewardship review.

The cases should exercise different procedural demands where safely possible,
but they are not a representative or random sample. Inability to obtain a rare
verdict safely is recorded rather than solved through broad pre-screening or
additional traffic.

### Preassigned order

The order is assigned before collection:

| Case | Catalog entry | Primary order |
|---|---|---|
| DR-01 | `HTTPBIN-LINKS-2` | I1 scanner → I3 Tor Browser → I4 ordinary browser |
| DR-02 | `HTTPBIN-STATUS-403` | I3 Tor Browser → I1 scanner → I4 ordinary browser |
| DR-03 | `HTTPBIN-STATUS-429` | I1 scanner → I3 Tor Browser → I4 ordinary browser |
| DR-04 | `TLS-EXPIRED-BADSSL` | I3 Tor Browser → I1 scanner → I4 ordinary browser |
| DR-05 | `TLS-SELF-SIGNED-BADSSL` | I1 scanner → I3 Tor Browser → I4 ordinary browser |

This completed dry-run assignment balanced scanner-first and Tor-Browser-first
cases while keeping the ordinary-browser control last. Future assignments must
likewise be fixed before outcomes are known. Any departure during collection is
a protocol deviation.

### Paired-observation window

The target window is 15 minutes from the start of the first primary instrument
to the end of the last. Do not rush or omit fields to stay within the window.
If the window is exceeded, finish only if stewardship rules still permit it and
record the duration and reason as a deviation. An over-window case may still
teach whether the procedure is practical, but it is not a tightly paired
observation.

Record all timestamps in UTC using an unambiguous ISO 8601 form such as
`2026-08-28T16:30:00Z`.

## Frozen environment record

This table preserves the reviewed `TACP-0.2` baseline used to complete issue
#32. It is not an issue #33 pilot manifest and does not authorize live work.
Before any separately authorized pilot collection, the human reviewer must
reverify the current environment and approve the experiment-level manifest
described above. Any change that materially alters the per-case method requires
a new protocol revision; otherwise, record the verified current value in the
approved pilot material rather than treating this historical baseline as a
fresh measurement.

| Field | Frozen value |
|---|---|
| Protocol name | Tor Access Comparison Protocol (TACP) |
| Protocol ID | `TACP-0.2` |
| Scanner repository | `josephlhall/check_tor` |
| Scanner commit | `fc13260f87c01e56db376858d90d837abcda1eaa`; reverify before any separately authorized issue #33 collection |
| JSONL schema | `1` |
| Scanner proxy | `localhost:9050` |
| Tor attempt limit | `3` |
| First/retry/clearnet timeouts | `60` / `30` / `20` seconds |
| Automated clearnet control | Enabled |
| HTTP request profile | Fixed by scanner commit |
| Response inspection limit | Fixed by scanner commit; currently 1 MiB |
| Operating system and version | macOS 26.6.2 (build 25G83) |
| `zsh` version | 5.9 (`arm64-apple-darwin25.0`) |
| `curl` version | Apple `/usr/bin/curl` 8.7.1, reporting `x86_64-apple-darwin25.0` in the current Codex environment |
| Tor version and distribution | Homebrew Tor 0.4.9.11 at `/opt/homebrew/opt/tor` |
| Tor Browser version | 15.0.20, installed from the Homebrew cask in `/Applications/Tor Browser.app` |
| Tor Browser security level | `Standard`, visually verified by the owner on 2026-08-30 |
| Tor Browser extensions/configuration | Newly installed stock build; only bundled NoScript and system theme active; verified 2026-08-30 |
| Ordinary browser and version | Firefox 154.0.1 |
| Ordinary-browser profile rule | Dedicated owner-only profile at `/Users/josephhall/Library/Application Support/check_tor/issue-32/raw/firefox-profile`; no sign-in or added extensions; fresh private window for each case; verified 2026-08-30 |
| Local time synchronization check | macOS `timed` service running; owner visually confirmed automatic time enabled on 2026-08-30 |
| Private study-data root | `/Users/josephhall/Library/Application Support/check_tor/issue-32`, owner-only (`0700`), with `structured/` and `raw/` |
| Backup treatment | Time Machine reports the study root as excluded; verified 2026-08-29 |
| Restricted raw-artifact retention | Delete after row audit and no later than 30 days after collection; approved 2026-08-29 |
| Structured-observation retention | Delete or formally extend within 90 days after issue #33 review closes; approved 2026-08-29 |

### Scanner invocation

Use an external one-case target file and restricted JSONL destination. The
task-specific environment variables below must resolve outside this repository:

```zsh
./check_tor.zsh \
  --format jsonl \
  --proxy localhost:9050 \
  --circuits 3 \
  --timeout-first 60 \
  --timeout-retry 30 \
  --timeout-clearnet 20 \
  "$CHECK_TOR_CASE_TARGET_FILE" > "$CHECK_TOR_CASE_JSONL_FILE"
```

Before running, record the exact scanner commit and confirm the working tree
does not change scanner code. Do not use `--no-clearnet`.

One scanner invocation is permitted per case. A first-attempt `PASS` produces
one Tor observation; `--circuits 3` is a maximum, not a request for three
independent observations. SOCKS authentication requests circuit isolation, but
neither separate circuits nor separate invocations prove distinct exits.

The scanner's Tor preflight is part of the interaction budget. The operator
must not record or publish the displayed or observed exit IP.

## Human observation procedure

### Preparation

Before every case:

1. Confirm the case is approved, has not opted out, and remains within its
   catalog interaction limit.
2. Confirm the order assignment and start the 15-minute window only when ready.
3. Confirm no browser is signed in and no personal identifiers will be entered.
4. In Tor Browser, use **New Identity** before the case. This closes prior tabs,
   clears browser state, and requests new circuits; it still does not establish
   an exit shared with the scanner or unique across cases.
5. Open a fresh private window in the approved ordinary browser.
6. Record exact versions, security level, start conditions, and any deviation.

Do not use “New Tor Circuit for this Site” during the primary observation. It
changes the circuit without clearing private state and would constitute a
separate diagnostic condition.

### Fixed public task

For each primary browser:

1. Navigate directly to the approved public URL.
2. Wait for the page to reach a stable outcome without bypassing browser or
   site security warnings.
3. Identify whether meaningful first-party public content is available.
4. If the case declares a navigation, follow the one pre-approved first-party
   link without credentials, personal information, form submission, purchase,
   download, or other state-changing action. For a mechanism-only endpoint,
   record navigation as not applicable.
5. Record outcome, timing, challenge behavior, navigation result, and
   uncertainty.

Passive or automatically completed browser challenges may be observed.
CAPTCHAs, “prove you are human” tasks requiring interaction, login prompts,
consent flows that disclose data, or access-control workarounds must not be
completed. Record the boundary encountered and stop that task.

### Proposed retry rule

Each primary browser permits at most one ordinary reload when the initial page
does not reach a stable outcome because of a transient stall or incomplete
load. Record the trigger, timestamp, and result. Do not use a new identity, a
new circuit command, altered security settings, or a different URL as the
retry. A second retry is prohibited; classify the observation with appropriate
uncertainty.

The owner approved this retry rule on 2026-08-29.

### Case close

After the three primary observations:

1. record the paired-window end time and any deviation before interpretation;
2. close the ordinary browser's private window and do not preserve its state;
3. confirm the JSONL file is in the approved restricted location and no raw
   output was written inside the repository;
4. complete required structured fields and identify uncertainty without
   collecting new evidence; and
5. do not perform I5; it is disabled for all five dry-run cases.

## Browser access outcome rubric

The rubric applies to the fixed public task, not to every site capability.

| Outcome | Definition |
|---|---|
| `NORMAL` | Meaningful public content and the approved navigation load without meaningful intervention or impairment |
| `FRICTION` | The task succeeds after a short passive challenge, approved single reload, or similarly bounded delay that a user would notice |
| `SEVERELY_DEGRADED` | Some meaningful content loads, but the approved task is materially incomplete, unreliable, or impractical |
| `BLOCKED` | No meaningful public content can be reached within the frozen task and attempt rule |
| `INCONCLUSIVE` | Authentication, origin failure, instability, protocol deviation, ambiguous content, or another confounder prevents a fair classification |

The public task succeeds when the primary page reaches meaningful content,
required first-party resources for that content load, and the single approved
public navigation succeeds without credentials or personal-data submission.
Do not infer whole-site access from this task.

## Observation record

The approved private structured record must have one row or object per case.
Free-form prose is supplementary and should be minimized.

For JSON, place the Tor Browser fields in a `tor_browser` object and the
ordinary-browser fields in an `ordinary_browser` object. This avoids duplicate
keys such as `meaningful_content_reached` while preserving the field names
below. A tabular form may instead prefix those shared fields with the
instrument name.

The recorder captures each instrument start immediately before releasing the
observer or scanner action and captures its end immediately after the stable
outcome is reported. If action-time capture fails, use null rather than a
reconstructed timestamp and record the available coordinator bounds as a
deviation. Do not infer timestamps from screenshots or file metadata.

### Case and governance fields

```text
case_id
catalog_entry_id
endpoint_visibility
authorization_basis
publication_sensitivity
case_inclusion_reason
site_category
edge_or_waf_provider_if_known
edge_or_waf_evidence
approved_start_url
approved_navigation_description
endpoint_association_review
protocol_id
protocol_approval_date_utc
human_reviewer
observation_date_utc
planned_order
actual_order
paired_window_start_utc
paired_window_end_utc
protocol_deviation
deviation_effect
```

### Environment fields

```text
check_tor_commit
check_tor_configuration
jsonl_schema_version
operating_system
zsh_version
curl_version
tor_version
tor_browser_version
tor_browser_security_level
ordinary_browser_name_and_version
time_sync_check
```

### Scanner fields

```text
scanner_start_utc
scanner_end_utc
scanner_jsonl_record_location
scanner_target
scanner_verdict
scanner_detail
tor_attempts
tor_attempt_limit
clearnet_control_enabled
clearnet_control_performed
clearnet_control_verdict
tor_specific
body_limited
```

Copy structured JSON values without recoding them. Preserve null distinctly
from `false`. Do not derive `tor_specific` from prose.

### Tor Browser fields

```text
tor_browser_start_utc
tor_browser_end_utc
tor_browser_new_identity_confirmed
tor_browser_attempt_count
tor_browser_reload_used
tor_browser_outcome
meaningful_content_reached
challenge_present
challenge_completed_automatically
challenge_interaction_required
approved_navigation_succeeded
time_to_stable_outcome_seconds
time_to_meaningful_content_seconds
tor_browser_uncertainty
tor_browser_structured_note
```

### Ordinary-browser fields

```text
ordinary_browser_start_utc
ordinary_browser_end_utc
ordinary_browser_private_window_confirmed
ordinary_browser_attempt_count
ordinary_browser_reload_used
ordinary_browser_outcome
meaningful_content_reached
challenge_present
challenge_completed_automatically
challenge_interaction_required
approved_navigation_succeeded
time_to_stable_outcome_seconds
time_to_meaningful_content_seconds
ordinary_browser_uncertainty
ordinary_browser_structured_note
```

### Interpretation fields

```text
agreement_category
likely_disagreement_mechanism
alternative_disagreement_mechanism
confidence
evidence_for_interpretation
diagnostic_client_authorized
diagnostic_question
diagnostic_result
```

Interpretation occurs after the three primary observations are recorded. Keep
direct evidence separate from likely and alternative mechanisms.

### Value conventions

- Every required field is present even when its value is null.
- Use `true`, `false`, and null distinctly. Null means not observed, not
  applicable, or unknown; the accompanying field or note must make the reason
  clear.
- Use the exact outcome, agreement, and confidence tokens defined here rather
  than free-text synonyms.
- Record timestamps in UTC and durations as numeric seconds. Record
  `time_to_stable_outcome_seconds` for every stable browser outcome; record
  `time_to_meaningful_content_seconds` only when meaningful content is reached.
- Preserve scanner enum spelling exactly as emitted in JSONL.
- Keep structured notes factual, concise, and limited to the approved public
  task. Do not paste raw page text.
- Store artifact references only in the approved private record. Do not copy
  local paths or private endpoint identifiers into public material.
- Do not add an exit-IP field. If an IP is encountered accidentally, follow the
  stewardship rule for restricted artifacts.

## Agreement categories

| Category | Meaning |
|---|---|
| `STRONG_AGREEMENT` | Scanner and Tor Browser indicate the same practical outcome |
| `ACCEPTABLE_SEMANTIC_AGREEMENT` | Labels differ, but the scanner correctly identifies relevant friction or impairment |
| `SCANNER_PESSIMISTIC` | Scanner suggests severe failure while Tor Browser completes the task |
| `SCANNER_OPTIMISTIC` | Scanner passes while Tor Browser is blocked or materially degraded |
| `EXIT_DEPENDENT_HYPOTHESIS` | Variation appears consistent with exit identity or reputation, but is not directly established |
| `CLIENT_DEPENDENT_HYPOTHESIS` | Client capability, fingerprint, JavaScript, cookies, or session state is the leading explanation |
| `TIME_DEPENDENT_HYPOTHESIS` | Changing conditions make the observations poorly comparable |
| `INCONCLUSIVE` | Evidence does not support a fair agreement or mechanism classification |

Mechanism categories ending in `_HYPOTHESIS` must not be published as causal
findings without direct evidence. Confidence is `LOW`, `MEDIUM`, or `HIGH` and
must include a short evidence statement.

## Inclusion, exclusion, and halt rules

A case may start only if:

- its endpoint record and authorization basis are approved;
- its public task and first-party navigation are predeclared;
- every operational blocker in this protocol and the stewardship plan is
  resolved;
- the environment is frozen and the order is assigned; and
- the interaction budget can be honored.

Exclude or halt a case if it requires authentication, personal data, form
submission, purchase, download, CAPTCHA completion, access-control bypass, or
another prohibited interaction. Also halt for an operator request, abuse
signal, suspected operational harm, unexpected sensitive data, exposed
vulnerability, or any stewardship trigger.

Do not silently substitute a new endpoint. Record the exclusion and obtain
human approval for any replacement before observing it.

## Deviations

A deviation record must state:

- what differed from the approved protocol;
- when and why it happened;
- whether it affected safety, comparability, or interpretation;
- whether the case was completed, halted, or excluded; and
- the human review decision.

Safety-impacting deviations halt collection. Analytical deviations never get
“fixed” by editing timestamps, dropping inconvenient observations, adding
unplanned retries, or changing a category after seeing other cases.

## Dry-run evidence gate

The dry run succeeds procedurally only if the human reviewer can determine:

- whether every required field was understandable and collectable;
- whether order and timing rules were practical;
- whether the browser task produced reproducible classifications;
- whether the interaction budget was proportionate;
- whether screenshots, raw notes, or other artifacts were unnecessary;
- whether uncertainty and deviations were visible rather than normalized;
- whether the data boundary was followed; and
- what single revision, if any, is justified before issue #33.

The dry run must not report an accuracy percentage or prevalence estimate.

## Change control and freeze

### Revision history

| Protocol ID | State | Date | Change summary |
|---|---|---|---|
| `TACP-0.1` | Approved and used for the five-case issue #32 dry run | 2026-08-30 | Initial governed procedure and observation schema |
| `TACP-0.2` | Frozen and used for issue #33; live authority came from its separate manifest and gates | 2026-08-30 | One post-run revision: nested browser records, stable-outcome timing, and explicit action-time timestamp capture |

The lifecycle is:

1. `DRAFT — NOT AUTHORIZED FOR LIVE USE` while expert review and operational
   decisions remain open.
2. `APPROVED FOR FIVE-CASE DRY RUN` only after the human reviewer approves the
   text, endpoints, environment, storage, access, retention, deletion, contact,
   incident path, interaction limits, and diagnostic-client decision.
3. At most one evidence-driven protocol revision after all five cases or an
   approved early halt.
4. `FROZEN FOR ISSUE #33` only after the human reviewer accepts that revision
   and the sanitized dry-run note.

Every status transition records protocol ID, UTC date, reviewer, scanner
commit, and a concise change summary. Any later material change requires a new
protocol revision and must not be applied retroactively to collected cases.

## Sources

- [`check_tor` measurement roadmap](MEASUREMENT-VALIDATION.md)
- [Five-case dry-run procedural record](VALIDATION-DRY-RUN.md)
- [Issue #33 pilot manifest](VALIDATION-PILOT-MANIFEST.md)
- [Issue #33 pilot calibration results](VALIDATION-PILOT-RESULTS.md)
- [Ethics and data stewardship](ETHICS-AND-DATA-STEWARDSHIP.md)
- [Reference endpoint catalog](REFERENCE-ENDPOINTS.md)
- [Tor Project: using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [Tor Project: security levels](https://support.torproject.org/tor-browser/features/security-levels/)
- [Tor Project: managing identities](https://support.torproject.org/tor-browser/features/managing-identities/)
