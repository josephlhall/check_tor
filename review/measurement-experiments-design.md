# Measurement experiments implementation proposal

This records the proposal submitted for pre-implementation review on November
15, 2026. Subsequent decisions and validation are in
[the implementation record](implementation-state.md). The reviewed base is check_tor v1.9.2,
commit 7e5995381e186dafe4decae3bb3d1243d5418891.

## Intended outcome

A researcher can run a small offline experiment, inspect observations and their
limits, preserve a reproducible record, and understand how to apply the same
record-reading techniques to an authorized Tor/direct measurement. Public
instructions must be self-contained and use public or synthetic examples.

## Configurable Tor verification timeout

Add --timeout-preflight SECONDS to text, JSONL v1 and JSONL v2. Accept integers
1 through 3600, default 20, using existing numeric validation conventions.
This is the deadline of each verification request. Existing retry eligibility,
15/30-second backoff, verification endpoint, 1 MiB cap and redirect policy keep
their current semantics. Document how the timeout and retries affect the maximum
startup allowance, with global pacing and process overhead accounted separately.

Wire parsing, dynamically scoped shell configuration, Python arguments, bridge
settings and actual curl invocation together. Record timeout_preflight in v2
settings and the effective preflight_timeout in request_profile. Each attempt's
requested_timeout and timeout diagnostic must agree with the actual request.
Preserve the exact existing sourced-shell parse_args reply tuple shape, which
is asserted by integration tests. Use a separate named parse result for the new
setting with main owning its dynamic scope, or demonstrate another compatible
route. Review how that result resets between invocations and on errors. A timeout-only selection must preserve existing routing
semantics. Reject invalid arguments before input or network work. Private
bridge environment values must be validated and set explicitly by the coordinator.

Regression proof covers default and explicit values in all formats, equals and
separate forms, invalid bounds and syntax, repeated sourced calls, actual fake
curl arguments, settings/records, retry attempts, and timeout diagnostics.
Historical results retain their original settings. Matching a historical timeout
alone does not establish comparability with an older scanner revision.

## Offline experiment entry point

Add a small standard-library Python CLI under reference-lab with list and run
commands. Cases initially cover normal navigation, readable HTTP 202, a stall
during TLS, a stall after TLS, and synthetic startup verification failure.
The HTTPS cases require the existing optional nginx/OpenSSL tools. Each command
checks its own prerequisites and reports actionable errors.

The runner starts only loopback fixtures on ephemeral ports, uses disposable
certificates trusted by its own clients, and cleans owned processes and scratch
on normal completion, error and interruption. It accepts known case IDs rather
than arbitrary URLs. Real local observations use the existing scanner probe and
classifier. The startup-failure case uses a fail-closed fake curl and the normal
scanner CLI, verifies the selected executable, and admits only synthetic inputs.
Existing tests contain the fixture mechanisms. Extract only the needed shared
fixture code when doing so preserves existing assertions and cleanup behavior.
Avoid making a user command instantiate unittest test cases as its runtime API.

Each run produces a concise terminal explanation. Optional --output-dir creates
an exclusive private directory outside a Git checkout and refuses overwrite.
Retained files include a versioned manifest, observations, and separate case
specification/answer material. Local probe observations have an explicitly
labelled lab format; full mocked CLI records retain native JSONL v2. Do not
fabricate native lifecycle records around a direct probe. Configuration truth,
observed evidence and interpretation must be identifiable. Neutral case IDs in
model-visible material reduce answer leakage, with the limits of blinding
explained. Actual outcomes are collected fresh, never substituted from answers.

The initial tutorial runs normal and 202, explains HTTP status versus scanner
label and human task completion, then uses the two timeout cases to show which
observations support distinguishing causes. The startup example demonstrates
that a failed verification leaves target accessibility unobserved. Provide a
single command for each case, expected output shape, cleanup behavior, and one
small variation that users can run locally.

## Saved-run manifest and inspector

Provide a minimal synthetic manifest template and a standard-library offline
inspector for a single native JSONL v2 execution. This reads existing artifacts
without launching the scanner. An accompanying capture example preserves the
process exit status, stdout, stderr, source identity, target-file digest/order,
requested command/settings, effective settings and a minimal runtime inventory.
Use exclusive output paths and restrictive permissions. Preserve original records.
Avoid environment dumps and unnecessary target or raw-header duplication.

The inspector reports observed attempts by route and phase, pair completeness,
policy omissions, terminal state and evidence problems. It joins IDs and checks
lifecycle consistency, duplicate identities, pair references, terminal counts,
settings consistency where required and supplied process status. Truncated JSON,
missing terminal records, unsupported schema or contradictions must never become
an unqualified successful-run report. Complete negative observations remain data.
Exit 3 is an expected policy outcome only with matching valid terminal evidence.
If process status was not supplied, explicitly report that it is unavailable.

Accept older v2 records whose additive optional fields are absent and ignore
unknown additive fields. Do not invent missing settings from today's defaults.
Keep the original per-run identity and all missingness. Cross-run recovery and
statistical estimation remain explicit study analysis decisions. The inspector
must state its validated invariants and limits rather than claim comprehensive
schema certification. Synthetic fixtures cover successful, policy-stopped,
interrupted, preflight-failed, truncated and contradictory runs, including older
v2 shapes. Prefer a bounded reader with clear resource-error reporting.

## Public documentation and context

Audit all tracked public prose, help text and proposed artifacts for unexplained
internal project/study names, private links, hostnames, paths or dependencies.
Describe already-public findings using their scientific purpose, setting changes,
aggregate observations and limitations. In the README timeout rationale, explain
the earlier comparison of Tor/direct retrieval and the simultaneous changes to
timeout, redirect and body limits without requiring knowledge of another project.
Preserve the inability to isolate the timeout effect. Do not add private study
records to establish public context. Keep frozen methods and dated evidence
historically accurate, using clearly dated notes for subsequent behavior.

Link the experiment guide prominently from Measurement validation and Testing.
Provide a compact map of regression checks, controlled local experiments and
live browser comparison procedures with commands, prerequisites, artifacts and
limits. Update the detailed-output contract and current measurement notes for
the configurable timeout. Add a short repository-specific instruction to give
public readers sufficient context and use reviewed public or synthetic examples
when discussing downstream research. Check new material for the same boundary.

## Execution and acceptance

Implement in a task worktree after this review, in focused stages: timeout and
regressions, reusable local cases plus tutorial, manifest/inspector, and full
public-context pass. Reuse repository dependencies and conventions. Run the
existing offline suites, relevant new regression checks, all optional lab tests,
Apple Python compatibility where available, documentation commands/link checks,
and diff checks. Verify process cleanup and exclusive output behavior. Proposed
lab/helper coverage should run in a dedicated optional-lab CI job installing
nginx, while preserving routine scanner dependency requirements. Review whether
CI scope should be path-filtered without weakening required checks.

Acceptance requires a fresh reader to reproduce the tutorial locally, obtain
honest evidence, inspect good and deliberately incomplete sample runs, select
and verify the preflight timeout in every output mode, and follow public prose
without access to another repository. Report any unverified behavior.

## Reviewer request and scoring

Review this design before implementation. Evaluate correctness, backward
compatibility, measurement validity, public-context boundaries and proportional
scope. Identify concrete failure scenarios and missing acceptance criteria.
Judge whether the proposed inspector and fixture reuse are too broad and propose
a smaller complete implementation when justified. Consider whether any proposed
requirement adds needless ceremony. Assess each concern by severity, evidence,
trigger, consequence, and smallest correction. Separate source-established facts
from design risks. Give a final proceed/revise verdict and at most 8 prioritized
findings, within roughly 1200 words. Do not execute tools, access external data,
or infer private-study details. Source excerpts follow in the review packet.


## Source evidence included in the review

The packet used public source excerpts from the reviewed base. The full submitted
packet is archived with the raw review response outside Git, identified by the
hash in the implementation record.

| Source | Included lines at the reviewed base |
| --- | --- |
| `check_tor.zsh` | 20–49, 145–175, 407–554, 611–645, 790–855 |
| `check_tor_probe.zsh` | 1–96 |
| `check_tor_measure.py` | 100–150, 634–730, 778–826, 1240–1275, 1540–1560 |
| `DETAILED-OUTPUT.md` | 187–265, 342–417 |
| `reference-lab/test_lab.py` | 31–189 |
| `reference-lab/routes.conf` and `nginx.conf` | Complete files |
| `reference-lab/OPERATIONS.md` | 30–80 |
| `tests/test_tls.py` | 23–71, 223–345 |
| `tests/test_measurement.py` | 149–175, 222–274, 281–295 |
| `tests/check_tor_integration_test.zsh` | 174–194 |
| `.github/workflows/offline-tests.yml` | Complete file |
