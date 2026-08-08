# Repository instructions

## Shipping convention

When the user says "ship it," merge the ready pull request after its required
checks pass, fast-forward the local `main` branch from `origin/main`, and delete
the merged feature branch both locally and on the remote.

Treat `targets.txt`, everything under `scans/`, and `*.private.txt` as sensitive
operational data, not test fixtures. Unless a task explicitly concerns that
data, do not inspect, modify, use in tests, expose in output, or force-add it.
Never commit it. Use `targets-EXAMPLE.txt` or temporary files for testing.

Keep raw measurement-validation artifacts—including JSONL, screenshots,
browser notes, cookies, session data, and observed IP addresses—outside the
repository. Only protocols, sanitized aggregate findings, and deliberately
public case descriptions may be committed. When scanner changes materially
affect the measurement model or protocol, keep `MEASUREMENT-VALIDATION.md`
accurate and distinguish hypotheses and planned methods from established
findings.
