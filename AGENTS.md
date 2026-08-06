# Repository instructions

Treat `targets.txt`, everything under `scans/`, and `*.private.txt` as sensitive
operational data, not test fixtures. Unless a task explicitly concerns that
data, do not inspect, modify, use in tests, expose in output, or force-add it.
Never commit it. Use `targets-EXAMPLE.txt` or temporary files for testing.
