# Tor Reachability Scanner

A `zsh` utility script for Project Galileo that automates testing a list of domains against a local Tor SOCKS proxy. It verifies whether sites are accessible over the Tor network, checking for WAF blocks, SSL/TLS certificate misconfigurations, and SOCKS connection failures—and diagnoses *who* is doing the blocking and whether the block is Tor-specific. By Joseph Lorenzo Hall, PhD (<https://josephhall.org/>)

## Prerequisites & Installation

This script requires `zsh`, `curl`, and a local `tor` proxy to run.

### For macOS
1. **Install dependencies via Homebrew:**
   ```zsh
   brew install tor
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your `~/.zshrc` for easy proxy management:
   ```zsh
   alias tor-on='brew services start tor'
   alias tor-off='brew services stop tor'
   alias tor-stat='brew services info tor'
   alias tor-reset='brew services restart tor'
   ```

### For Linux / ChromeOS (Debian/Ubuntu)
1. **Install dependencies via APT:**
   ```zsh
   sudo apt update && sudo apt install zsh tor curl -y
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your shell profile (e.g., `~/.zshrc`) to map to the system service:
   ```zsh
   alias tor-on='sudo service tor start'
   alias tor-off='sudo service tor stop'
   alias tor-stat='sudo service tor status'
   alias tor-reset='sudo service tor restart'
   ```

*Run `source ~/.zshrc` to apply any alias changes.*

## Setup

1. Place `check_tor.zsh` somewhere convenient, and copy `targets-EXAMPLE.txt` to create your own list. Keep real target lists **outside** this repository—see [Handling target lists](#handling-target-lists).
2. Make the script executable:
   ```zsh
   chmod +x check_tor.zsh
   ```

## Usage

1. **Start the Tor proxy:**
   Ensure your local proxy is running on `localhost:9050` before scanning the Internet.
   ```zsh
   tor-on
   ```

2. **Populate your target list:**
   Copy `targets-EXAMPLE.txt` and add the domains you want to test, one per line. The script will automatically format them to enforce `https://`. Blank lines and lines starting with `#` are ignored.
   ```zsh
   mkdir -p ~/tor-targets
   cp targets-EXAMPLE.txt ~/tor-targets/mylist.txt
   emacs ~/tor-targets/mylist.txt
   ```

3. **Run the scanner:**
   Pass your text file as an argument to the script.
   ```zsh
   ./check_tor.zsh ~/tor-targets/mylist.txt
   ```

   Exactly one readable target file is required. A file containing only blank
   lines and comments is rejected before the scanner contacts Tor. Run
   `./check_tor.zsh --help` to see the command contract without starting Tor.

4. **Stop the Tor proxy (when finished):**
   ```zsh
   tor-off
   ```

### Output, color, and exit status

Scan results and progress are written to stdout. Invocation, input, dependency,
and Tor preflight failures are written to stderr. This allows redirected output
to contain scan results without mixing in fatal diagnostics.

Color is enabled when stdout is an interactive terminal. Redirected output is
plain text. Set [`NO_COLOR`](https://no-color.org/) to any value to disable
color explicitly:

```zsh
NO_COLOR=1 ./check_tor.zsh ~/tor-targets/mylist.txt
```

Exit status `0` means the scan completed, even if it found blocked or degraded
targets. Exit status `1` means the command could not complete because invocation,
input, a required command, or the Tor preflight failed.

## Testing

All tests are deterministic and offline. They use synthetic `.example.test`
targets and temporary files; they never inspect `targets.txt`, `scans/`, or
`*.private.txt`. You do not need a running Tor proxy or Internet access.

The repository has two complementary suites:

* `tests/check_tor_test.zsh` exercises the decision logic directly, including
  curl and HTTP classification, WAF fingerprints, retry eligibility, severity,
  and Tor-versus-clearnet comparisons.
* `tests/check_tor_integration_test.zsh` invokes `check_tor.zsh` as a user would.
  It places a controlled fake `curl` first in `PATH` to test argument failures,
  source-safe loading, target parsing and normalization, circuit retries,
  clearnet controls, output summaries, curl arguments, and temporary-file
  cleanup without reaching the network.

Run the complete local validation from the repository root:

```zsh
test -x check_tor.zsh
zsh -n check_tor.zsh check_tor_core.zsh tests/*.zsh
zsh tests/check_tor_test.zsh
zsh tests/check_tor_integration_test.zsh
git diff --check
```

A successful run reports `All 64 offline checks passed.` and
`All 56 offline integration checks passed.` The **Offline tests** GitHub Actions
workflow runs the same syntax and test commands on Ubuntu and macOS for every
pull request and push to `main`; it can also be started manually.

## Handling target lists

**Do not commit real target lists.** A list of domains being checked for Tor reachability is a list of organizations that believe they are at risk and are seeking protection they do not yet have. Each domain is individually public, but the curated set is not—published, it is a pre-filtered reconnaissance aid that also implies which organizations are currently unprotected.

Three things in this repository exist to prevent that:

* `targets-EXAMPLE.txt` ships well-known public sites and deliberate TLS test endpoints, so the example list is safe to scan and to publish.
* `targets.txt`, `scans/`, and `*.private.txt` are gitignored, so a real list does not become a commit by accident.
* The script prints a warning if the target file you pass it is tracked by git.

The safest arrangement is to keep real lists entirely outside the repository:

```zsh
mkdir -p ~/tor-targets
cp targets-EXAMPLE.txt ~/tor-targets/mylist.txt
./check_tor.zsh ~/tor-targets/mylist.txt
```

If a real list has already been committed, deleting it in a new commit is **not** enough—it stays in history and is retrievable with one command. Rewriting history (`git filter-repo --invert-paths --path <file>`) and force-pushing is the minimum, and you should assume anything public for a meaningful period may already have been cloned, forked, or archived independently.

## How results are diagnosed

The script does more than fetch a status code:

* **Multiple circuits before declaring a block.** A block-ish result (FAIL, CHALLENGE, RATE LIMIT, DROP, TIMEOUT, SOCKS ERROR) is retried on up to 3 fresh Tor circuits (via SOCKS credential isolation—no ControlPort needed). A site that fails on all 3 has a site-wide policy; a site that passes on retry was just rejecting one exit node's IP reputation, and is reported as PASS with a note.
* **A clearnet control request, compared by severity.** A block that persists across every circuit is re-tested *without* Tor, and the two results are ranked by how badly each impedes a real user: served normally, passable with friction (a challenge a browser can solve), or impassable. A site is only reported as blocking Tor when Tor fares *strictly worse* than an ordinary client. This clears sites that are simply hostile to every scripted client, and it catches escalation—a site that challenges everyone but hard-blocks Tor is flagged as "escalated for Tor". If the control request itself fails uninformatively (broken origin, TLS error), the result is labelled inconclusive and kept in the summary for a manual look.
* **Blocker fingerprinting.** Response headers and bodies are inspected to name the blocker: Cloudflare error codes (1020 firewall rule, 1015 rate limit, 1006/1007/1008 IP ban—these ride inside an HTTP 403, not on the status line), `cf-mitigated: challenge` (managed challenge), Akamai, Sucuri, and Imperva/Incapsula signatures.
* **Summary.** The scan ends with per-verdict counts and a list of the domains where Tor was treated worse than an ordinary client.

## Output Legend

The script evaluates `curl` exit codes, HTTP status codes, and response contents to provide specific diagnostics:

* **[PASS]** (Green): Final status 200 after following redirects. The site is successfully serving Tor traffic. If earlier circuits were blocked, the result notes the block is exit-dependent rather than site-wide.
* **[CHALLENGE]** (Cyan): The request reached the host, but a WAF is interposing a challenge: a Cloudflare managed challenge (403 + `cf-mitigated`), a JS challenge / under-attack page (503), an async queue (202), or a 200 that actually landed on a `/cdn-cgi/` challenge page. Tor users with JavaScript enabled may still get through, with friction.
* **[RATE LIMIT]** (Yellow): Status 429. Not necessarily a deliberate Tor block, but exit IPs are shared by many users and burn through rate limits, so Tor users are effectively locked out.
* **[FAIL]** (Red): Status 403 or 401 on every circuit tried. The server is actively refusing the request, likely a WAF rule targeting Tor exit nodes; the specific blocker (e.g. "Cloudflare 1020: blocked by a firewall rule") is named when identifiable.
* **[DROP]** (Red): The connection failed while receiving data (curl exit 56—commonly a mid-request reset), closed with no reply (exit 52), or was truncated mid-transfer (exit 18)—the signature of a firewall silently killing Tor connections, arguably stronger block evidence than a 403.
* **[CERT ERROR]** (Purple): The destination server has an invalid, self-signed, or expired SSL/TLS certificate, terminating the secure connection before an HTTP status can be negotiated.
* **[SOCKS ERROR]** (Red): The Tor circuit was built, but the exit node could not complete the connection to the host server.
* **[TIMEOUT]** (Yellow): The connection hung. The detail distinguishes a stall *after* the TLS handshake (tarpitting) from never getting a response at all (silent drop or dead host).
* **[WARNING]** (Yellow): Anything else—unexpected status codes, redirect loops, unusual curl failures—printed with the raw codes for manual triage.

## License

This project is dedicated to the public domain under CC0 1.0 Universal. See the `LICENSE` file for details.
