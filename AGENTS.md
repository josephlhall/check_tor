# Repository instructions

Treat `targets.txt` and `scans/*.txt` as operational scan data, not test
fixtures. Do not modify them unless the task explicitly concerns scan targets
or archived results; use `targets-EXAMPLE.txt` or temporary files for testing.

**Never commit them.** They name organizations that believe they are at risk
and are seeking protection they do not yet have; publishing that list hands an
adversary a pre-filtered reconnaissance aid. Both paths are gitignored — do
not override that with `git add -f`, and check what is being staged before
running `git add -A`. See "Handling target lists" in README.md.
