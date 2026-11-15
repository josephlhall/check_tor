# Independent Gemini review of reference conditions #44–46

Two owner-approved reviews on November 14, 2026 examined the same bounded implementation packet. The packet covered the optional nginx conditions, snapshot compiler, managed-challenge recipe, tests, and operator documentation. It excluded credentials, raw study data, unrelated files, and prior review conclusions.

Packet SHA-256: `e58effee9ad03f20c1e5fb9aa1ea4cd1a499c9d93296f226199d04e7aaf90f8c`.

The review asked for concrete correctness or operational defects within the offline construction scope. Deployment, exact browser/provider qualification, and live measurement were explicitly future gates. The unchanged scanner and historical study outcomes were outside the change.

## Results

| Profile | Result | Input tokens | Thinking tokens | Answer tokens | Seconds | Estimated USD |
|---|---|---:|---:|---:|---:|---:|
| Argon High | Incomplete; generation cap exhausted | 27,980 | 32,765 | 3 | 259.195 | 0.3836 |
| Argon Medium | Completed; findings independently checked | 27,980 | 0 | 3,261 | 41.797 | 0.0886 |

Both attempts used a 32,768-token combined thinking/answer allowance. Charges are historical usage estimates, not current pricing guidance. Zero reported thinking tokens is provider accounting, not evidence of zero internal reasoning. Raw requests, responses, receipts, and approval records remain local and are not published here.

High returned no usable review. Its incomplete result is not acceptance or evidence that defects are absent. Medium raised four concerns and conditionally withheld acceptance on three. That conditional verdict is preserved; it is not presented as Gemini approval.

## Independent verification of Medium's findings

1. **Separate configuration and runtime directories:** not reproduced. nginx 1.31.8 passed configuration validation with separate directories; normal, client and Tor-difference routes returned their expected 200/403 statuses. Relative includes resolved correctly in the tested arrangement.
2. **Empty source and newest-observation selection:** not a current defect. Header-only synthetic input raised the intended controlled unavailable error; short-circuit evaluation avoids an empty `max`. Any observation satisfying the three-hour newest-observation requirement also survives the less restrictive 24-hour selection gate, so the maxima agree for a nonempty selected set.
3. **Missing implementation checkpoint:** the file existed locally and was deliberately excluded from the review packet to avoid sharing prior reviewer conclusions. It is included in this change, and its local links resolve.
4. **Off-route and unsupported-method responses:** intentional behavior exposed no protected task content. Synthetic POST, unknown-route and body-bearing requests returned 405/404/400. The operator recipe now states that rejection order explicitly. Adding a provider-wide block would expand the reviewed scope without fixing a demonstrated defect.

No material code defect survived these checks. The review produced one operator-documentation clarification and an independently reproduced deployment-layout check. Offline acceptance rests on verified behavior, the passing test suites, and the separate Astra review recorded in the [implementation checkpoint](IMPLEMENTATION-CHECKPOINT.md).

## Calibration follow-up

The capped High attempt motivated two separately approved calibration experiments. All 18 experiment requests completed; the nominal clean control in the first experiment was compromised and was not used to declare a winner. The second experiment compared all three models at Medium and High on two new matched tasks, with an independently verified clean control.

The [published calibration report](https://github.com/josephlhall/dotfiles/blob/main/docs/gemini-review-calibration.md) records the sanitized measurements, frozen predictions, limitations, and provisional Argon Medium recommendation with generous token headroom. The guidance shipped in [Dotfiles PR #309](https://github.com/josephlhall/dotfiles/pull/309). Those experiments do not alter this review's original disposition, authorize deployment, or change either inconclusive HTTP 202 scanner comparison.
