# Repository instructions

## Shipping convention

When the user says "ship it," merge the ready pull request after its required
checks pass, fast-forward the local `main` branch from `origin/main`, and delete
the merged feature branch both locally and on the remote.

Treat `targets.txt`, everything under `scans/`, and `*.private.txt` as sensitive
operational data, not test fixtures. Unless a task explicitly concerns that
data, do not inspect, modify, use in tests, expose in output, or force-add it.
Never commit it. Use `targets-EXAMPLE.txt` or temporary files for testing.
