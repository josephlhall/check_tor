# Repository instructions

These repository instructions supplement the global Codex working agreements
in `~/.codex/AGENTS.md`. Keep general workflow there and only `check_tor`-specific
rules here.

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
