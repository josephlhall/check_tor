# Run and understand a measurement experiment

The local examples let you compare a known server condition with the scanner's
observations. Start here to learn how an HTTP response, a scanner verdict and a
person's ability to complete a browser task relate to each other.

| What you want to do | Entry point | What it establishes |
| --- | --- | --- |
| Verify scanner behavior after a code change | [Offline tests](README.md#testing) | Regression assertions against synthetic and loopback fixtures |
| Explore controlled responses and retain observations | Local examples below | What the installed curl and scanner observe under the selected condition |
| Read an existing detailed scan | [Saved-run inspector](#inspect-a-saved-scanner-run) | Record consistency, observed outcomes and missing evidence |
| Compare scanner output with human access over Tor | [Browser comparison protocol](VALIDATION-REFERENCE-PROTOCOL.md) | Task observations under a prospectively chosen live method |

## Run your first local example

From the repository root, use Python 3.9 or newer, Zsh, curl and OpenSSL on
`PATH`. The normal and accepted examples also use nginx with its HTTP TLS
module. nginx is an optional lab dependency. Install it with your usual package
manager if needed, for example `brew install nginx` on macOS or
`sudo apt-get install nginx` on Debian/Ubuntu.

```sh
python3 reference-lab/experiments.py list
python3 reference-lab/experiments.py run normal
python3 reference-lab/experiments.py run accepted
```

The commands start temporary loopback fixtures and use the scanner's shared
probe and classifier. They need no Tor process or Internet connection. Their
certificate is trusted only by the local clients they start. Each command stops
its owned processes and removes scratch files when it finishes or is interrupted.
The ordinary scanner CLI performs Tor verification before target requests, so
use this lab command for the loopback examples.

For `normal`, look for HTTP 200 and `PASS`. The page contains opening hours and
a first-party link to visitor information. For `accepted`, look for HTTP 202
and `CHALLENGE`. The response body says the example request is accepted and
pending. The classifier maps 202 to `CHALLENGE`, even though this fixture serves
a readable page with no interactive challenge. These observations establish
what the automated probe received. Human task completion needs a browser
observation, as described in the [operator handoff](reference-lab/OPERATIONS.md).

## Compare failures with similar verdicts

```sh
python3 reference-lab/experiments.py run tls-handshake-stall
python3 reference-lab/experiments.py run tls-response-stall
python3 reference-lab/experiments.py run preflight-failure
```

Both stall cases should produce `TIMEOUT` with curl exit 28. In the first, the
server receives the start of a TLS handshake and withholds its response. In the
second, TLS completes and the server reads the HTTP request before withholding
the reply. Examine the diagnostic detail and the recorded fixture evidence to
see which stage was reached. The common verdict alone cannot distinguish the
configured causes.

Vary the local probe deadline while keeping the condition fixed.

```sh
python3 reference-lab/experiments.py run tls-response-stall --timeout 3
```

The local deadline accepts whole seconds from 1 through 60 and defaults to two
seconds. It applies to the local probe cases. Timing depends on the machine, so
compare the observed stage and outcome without treating wall-clock duration as
a calibrated latency measurement.

`preflight-failure` exercises the ordinary detailed scanner entry point with a
synthetic curl executable. It reports failed startup verification and zero
target requests. Target accessibility remains unobserved. The synthetic client
has no network implementation and refuses unexpected requests.

## Keep an experiment record

Choose a new output directory outside every Git checkout.

```sh
python3 reference-lab/experiments.py run accepted \
  --output-dir "$HOME/check-tor-accepted-example"
python3 reference-lab/experiments.py run preflight-failure \
  --output-dir "$HOME/check-tor-startup-example"
```

The command refuses an existing destination. `manifest.json` identifies the
configured case and provenance. `observations.jsonl` contains the actual recorded
evidence. Local probe records have their own lab format. The startup-failure
example retains native JSONL v2 from the scanner. Keep the formats distinct when
writing an analysis.

When preparing diagnostic exercises, show reviewers the observations and keep
the manifest's configured condition for scoring. The public case source and
scanner diagnostics can reveal the mechanism, so this separation alone does
not establish a blinded experiment. State what evidence each reviewer received
and allow “insufficient evidence” when the observations cannot support a claim.

## Inspect a saved scanner run

```sh
python3 check_tor_inspect.py /path/to/observations.jsonl --exit-status 0
python3 check_tor_inspect.py /path/to/observations.jsonl --exit-status 3 --format json
```

Use the process exit status actually saved with that execution. If it is
unavailable, omit `--exit-status`; the inspector reports the outcome as
unverified. To inspect the synthetic startup example, pass `provenance.scanner_exit_status` from its manifest. The local direct-probe lab format is outside this
inspector's native JSONL v2 input contract.

The inspector checks a single execution's identities, attempt and pair links,
counts and terminal consistency, and reports omissions and incomplete evidence.
Complete negative observations count as collected data. A matching scanner
status 3 can represent policy stopping after HTTP 429. Keep those observations
and inspect the omissions before deciding what a subsequent study run should do.
The [detailed output contract](DETAILED-OUTPUT.md#cautious-collection-and-completion)
defines these outcomes.

The inspector's own exit 0 means its consistency checks passed. The report can
still describe a failed or interrupted scanner run. Exit 1 means inconsistent,
incomplete, unreadable or over-budget evidence, and exit 2 means invalid
inspector arguments. A truncated record, missing terminal record or conflicting
process status cannot establish successful execution. Optional fields absent
from older v2 records remain unavailable. The inspector accepts at most 16 MiB per line, 128 MiB per file and 100,000
lines, and reports over-budget input explicitly. It tolerates additional
fields and reports its validation limits; it does not replay the scheduler or
certify a study's sampling, timing design, site intent or browser usability.

## Capture an authorized live measurement

Live measurements use Tor and contact the selected endpoints. Choose the
research question, target scope, traffic budget and analysis rule first, following
the [data-stewardship guidance](ETHICS-AND-DATA-STEWARDSHIP.md). Then follow the
[first-scan setup](README.md#run-your-first-scan). The following Zsh recipe plans
one Tor/direct pair per input occurrence with equal 30-second target deadlines.
Adapt the explicit settings prospectively to the approved study.

Choose a private output parent outside every Git checkout. The example uses
your home directory as that parent.

Copy the [manifest template](examples/measurement-manifest.json) into a fresh
private directory. Its null values mean “not recorded yet.” The recipe freezes
the exact input bytes and their order, saves the invocation and native records,
and preserves the process status even if the scanner exits nonzero. Run from
the repository root, replacing the input path with the authorized private list.

```zsh
(
  umask 077
  run_dir=$(mktemp -d "$HOME/check-tor-run.XXXXXXXX") || exit 1
  cp /path/to/authorized-targets.txt "$run_dir/input.txt" || exit 1
  cp examples/measurement-manifest.json "$run_dir/manifest.json" || exit 1
  scan_args=(--format jsonl-v2 --trials 1 --control always --control-scope trial
    --timeout-preflight 20 --preflight-retry none
    --timeout-first 30 --timeout-retry 30 --timeout-clearnet 30
    --order counterbalanced --seed 42 --workers 1 --start-gap 1
    --execution-policy paired-cautious --rate-limit-stop after-pair
    --max-redirects 10 --max-body-bytes 1MiB "$run_dir/input.txt")
  if python3 - "$run_dir" ./check_tor.zsh "${scan_args[@]}" <<'PY'
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text())
manifest["purpose"] = "Paired Tor/direct retrieval with the recorded settings"
manifest["input"]["sha256"] = hashlib.sha256((root / "input.txt").read_bytes()).hexdigest()
manifest["runtime"] = {"python": sys.version, "platform": platform.platform()}
try:
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5)
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == Path.cwd().resolve():
        revision = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
        sources = ["check_tor.zsh", "check_tor_core.zsh", "check_tor_probe.zsh",
                   "check_tor_measure.py", "check_tor_retry.py", "check_tor_onion.py"]
        changed = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *sources], timeout=5)
        manifest["source_checkout"] = {
            "revision": revision.stdout.strip() if revision.returncode == 0 else None,
            "scanner_sources_modified": bool(changed.returncode) if changed.returncode in (0, 1) else None,
        }
except (OSError, subprocess.TimeoutExpired):
    pass
for tool in ("zsh", "curl", "tor"):
    try:
        result = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.splitlines()
        version = lines[0] if result.returncode == 0 and lines else "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        version = "unavailable"
    manifest["runtime"][tool] = version
(root / "command.json").write_text(json.dumps(sys.argv[2:], indent=2) + "\n")
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
  then
    :
  else
    print -u2 -- "Preparation failed; retained $run_dir"
    exit 1
  fi
  if ./check_tor.zsh "${scan_args[@]}" > "$run_dir/observations.jsonl" 2> "$run_dir/stderr.txt"; then
    scan_status=0
  else
    scan_status=$?
  fi
  if python3 - "$run_dir" "$scan_status" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
path = root / "manifest.json"
manifest = json.loads(path.read_text())
manifest.update(exit_status=int(sys.argv[2]), state="finished")
path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
  then
    :
  else
    print -u2 -- "Finalization failed; retained $run_dir"
    exit 1
  fi
  if python3 check_tor_inspect.py "$run_dir/observations.jsonl" --exit-status "$scan_status"; then
    inspect_status=0
  else
    inspect_status=$?
  fi
  print -r -- "Retained run: $run_dir"
  exit "$inspect_status"
)
```

The native `run_start` contains the scanner source digest and effective settings.
The manifest points to that evidence and records the checkout revision and
scanner-source modification status when Git metadata is available. With an
archive checkout, add the release identifier to the manifest. Runtime version
strings describe the
installed tools; record any intentionally configured trust store or proxy
assumptions separately without credentials. If preparation or capture stops
before finalization, retain the directory and inspect the available evidence.
A manifest marked `finished` means the process returned, while the inspector
assesses the recorded outcome.

`--timeout-preflight` accepts 1–3600 seconds in every scanner output mode and
defaults to 20. It applies to each startup request. In JSONL v2 mode, `--preflight-retry transient` allows up to three such
requests after eligible transport failures, with 15/30-second backoff. The transport
and backoff allowance is therefore `3 × timeout + 45` seconds, with additional
pacing and process overhead possible. Freeze that policy as part of the method.
Selecting a previous timeout alone does not make a newer scanner comparable to
an older study. Keep primary, missing and later recovery observations distinct
when analyzing repeated collections.
