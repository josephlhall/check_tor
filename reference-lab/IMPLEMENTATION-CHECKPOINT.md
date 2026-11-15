# Offline reference conditions implementation record

**Offline construction is complete, tested, and independently reviewed.** On November 15, 2026 the owner authorized committing, local macOS CI before push, PR/merge after required checks pass, and updating and closing [#44](https://github.com/josephlhall/check_tor/issues/44), [#45](https://github.com/josephlhall/check_tor/issues/45), and [#46](https://github.com/josephlhall/check_tor/issues/46). The shipping PR and issue closure records hold the final commit and CI outcomes. This record does not authorize deployment, DNS changes, live qualification, or study traffic.

## Delivered scope

The implementation builds on `971ceb8d5ef80c686f475611a2bed6b8a9819d81` (`v1.9.1`). Two focused implementation workers prepared the related conditions and the challenge recipe; a separate Astra reviewer examined the design and integrated result. The primary integrated and verified the work.

| Issue | Offline deliverable | Future qualification boundary |
|---|---|---|
| #44 | Exact navigation-header rule, fixed reading-room task and synthetic request fixtures | Both task steps in the actual unmodified browser profiles must be qualified; candidate versions alone establish no browser outcome. |
| #45 | Validated frozen exit-snapshot compiler, real-peer membership rule and synthetic fixtures | Acquire and review current source data, qualify source-address handling and enforce the frozen deadline. IPv6 remains unavailable for this source. |
| #46 | Disabled exact-host/two-path managed-challenge rule, meaningful origin task and operator action card | Check the actual provider account/plan and zone, then separately authorize deployment and live qualification. A configured rule does not establish an observed challenge. |

Maintain source, deterministic tests, and rebuild/teardown recipes. Public hosting is temporary and only justified by a separately approved batch; there is no ongoing hosting commitment. Scanner behavior, JSONL, the study protocol, and historical study result files are unchanged. Both completed HTTP 202 scanner comparisons remain inconclusive; the published [#42 report](https://github.com/josephlhall/check_tor/issues/42) remains authoritative.

## Verification evidence

The implementation-stage checks completed on November 14, 2026:

- The complete README Testing block passed: 67 core checks, 165 CLI integration checks, and all 114 Python scanner tests. All 114 Python tests also passed on Apple's system Python.
- All 18 integrated reference-lab tests passed on both default and Apple Python with nginx 1.31.8. They cover the original normal/202 fixtures, header/address conditions, snapshot compiler, and challenge rule/origin. Requests were loopback-only; no Tor startup, exit-list acquisition or public target request ran.
- Local Markdown file targets resolved and `git diff --check` passed.
- nginx was installed with explicit owner permission for local fixtures. No persistent service was started. Docker was unavailable, so the optional lab tests used native nginx.

The existing macOS VM recipe and hosted checks cover the scanner suites. Optional nginx suites are validated separately on the host; they are not claimed as part of the VM recipe. Shipping requires local macOS VM CI on the committed head before push and successful required hosted checks. Final outcomes belong in the shipping PR handoff rather than being predicted here.

## Independent review and correction

Astra's design review required case-sensitive parsed `navigate`, qualification of both navigation steps, observation-time-based freshness, explicit unsupported-family handling, and no inference of a real challenge from configuration alone.

The integrated review found one material defect: the initial compiler expected hexadecimal SHA-256 while CollecTor's index uses Base64. The corrected compiler strictly decodes canonical Base64 to 32 bytes and compares digest bytes. Tests cover the actual encoding, malformed encoding/length/padding, and valid-but-wrong digests. All 10 affected condition tests passed on both Python installations after correction. Astra inspected the correction and accepted the offline scope with no remaining material findings.

The later optional [Gemini review](GEMINI-REVIEW.md) had one incomplete High attempt and one completed Medium attempt. Its concerns were independently verified; no material code defect remained. One clarification of intentional rejection behavior was adopted in the operator recipe. Gemini's conditional verdict is not represented as approval.

## Activation and retirement

The [November 15 qualification record](QUALIFICATION.md) describes the
subsequent temporary deployment and the Tor exit-list cutoff guard.

Offline completion satisfies the construction scope of #44–46; all catalog entries remain candidates. Before selecting one for a future batch, separately approve exact browser compatibility, source freshness/coverage, provider and zone behavior, hostname/certificate choices, costs, traffic limits, private custody, and retirement dates. The address snapshot deadline is operator-enforced; nginx does not automatically expire or refresh it. If these requirements cannot be met, defer that condition.

The proposed challenge hostname and provider resources are not created by this work. Close ingress and retire temporary resources at the approved end of any future deployment. Existing #41/#42 authority cannot be reused for new traffic.

## Handoff

- **Scope:** reusable optional conditions, shared loopback fixtures, challenge and teardown recipes, and current documentation links. No scanner/schema change, deployment or live study.
- **Validation:** implementation-stage scanner and lab suites, Apple Python compatibility, local document/whitespace checks and independent review passed as detailed above. Shipping CI outcomes are recorded in the PR.
- **Risk:** synthetic rules do not establish actual browser behavior, universal Tor membership, or a particular provider challenge. Those remain explicit future qualification gates.
