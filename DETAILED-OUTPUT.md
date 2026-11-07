# Detailed measurement output

`--format jsonl-v2` records individual automated requests and the lifecycle of
one scanner execution. It requires Python 3.9 or newer in addition to the
scanner's existing Zsh/curl dependencies; it uses only Python's standard
library. The coordinator invokes the existing Zsh probe and classifier. Text
output and `--format jsonl` retain their existing contracts and do not require
Python.

## Choosing a measurement policy

To keep today's failure-driven retries and conditional target control while
retaining each observation:

```zsh
./check_tor.zsh --format jsonl-v2 /path/outside/repo/targets.txt
```

To perform three sequential Tor/direct pairs for every input occurrence:

```zsh
./check_tor.zsh --format jsonl-v2 --trials 3 \
  --control always --control-scope trial \
  --order counterbalanced --seed 42 \
  --timeout-first 30 --timeout-retry 30 --timeout-clearnet 30 \
  --max-partner-gap 60 --workers 2 --start-gap 1 \
  /path/outside/repo/targets.txt
```

These are invocation examples, not authorization to contact any particular
site. Keep output outside the repository with restrictive permissions.

| Setting | Meaning |
| --- | --- |
| No `--trials` | Retry the existing block-like outcomes, stopping on PASS/CERT/WARN or at `--circuits`. |
| `--trials N` | Make exactly N Tor observations unless the run fails or is interrupted. Successes and CERT/WARN outcomes do not end the sequence. No additional failure retries are added. |
| `--control conditional` | Make a direct control only when the associated Tor result is block-like. This is the default. |
| `--control always` | Make the control even after a successful Tor result. |
| `--control never` / `--no-clearnet` | Make no direct controls. |
| `--control-scope target` | One control for the whole target bundle; conditional eligibility uses its final Tor observation. This is the default. |
| `--control-scope trial` | A control belongs to an individual fixed trial. Requires `--trials` and enabled controls. |
| `--order tor-first` | Tor precedes its control; this is the default and the only order for conditional controls. |
| `--order direct-first` | With always-controls, run direct first. For target-scoped controls this precedes the whole Tor sequence. |
| `--order counterbalanced --seed N` | Choose reproducible order independently of outcomes, circuit tags, and worker completion order. Requires always-controls. |
| `--max-partner-gap S` | Maximum start-to-start time for each-trial partners, in seconds; default 60. Observations exceeding it remain in the output with a late flag. |
| `--workers N` | At most N active target bundles, from 1 to 32; default 1. |
| `--start-gap S` | Global minimum interval between coordinator probe invocations, in seconds, from 0 to 3600; default 0. |
| `--run-id TEXT`, `--group-id TEXT` | Optional opaque caller labels. They do not replace the scanner's internal execution identity. |

Unsupported or contradictory combinations fail before reading the target file
or making a request. In particular, fixed trials cannot also specify a retry
count, conditional controls cannot precede the observation that determines
whether they are needed, and disabled controls cannot have a trial scope or
an alternative order. The new policy options require v2 output.

Counterbalanced order uses `(seed + target_occurrence - 1 + trial - 1) % 2`:
zero selects Tor first, one selects direct first. For a target-scoped control,
use trial 1 in that formula. The seed is an integer from 0 through 2147483647.
This alternates order reproducibly; it does not claim random assignment.

The first Tor observation uses `--timeout-first`; later Tor observations use
`--timeout-retry`, including later fixed trials. Controls use
`--timeout-clearnet`. Set all three equally when equal timeout budgets are
part of the intended comparison. The partner-gap setting flags elapsed time;
it does not interrupt a slow partner or add a replacement observation.

A once-per-target control is associated with the bundle. It is not presented
as a separate matched observation for each Tor request. Fixed observations
have no invented overall target verdict: consumers receive the native outcomes
and counts and can apply a separately defined analysis rule.

## Routing and request configuration

Legacy detailed runs preserve inherited routing behavior. Records distinguish
the requested route from a guarantee about effective routing. `--reproducible`
removes proxy environment overrides in child processes and explicitly sets
proxy bypass rules so direct observations bypass proxies and Tor observations
use the selected SOCKS endpoint. Explicit trial/control/order, worker, or pacing options enable this
mode automatically, even when they select a default value. TLS trust settings remain in force. `.curlrc` is disabled
in both legacy and reproducible modes, as in the existing scanner.

The request still uses curl's TLS/HTTP behavior and the scanner's established
headers, redirect limit, body cap, and classifier. Detailed mode disables curl URL
globbing, so braces and ranges in a supplied URL cannot expand one observation
into several transfers. SOCKS isolation credentials
request circuit isolation; they do not prove a different exit relay. Repeated
trials are not independent samples. Neither mode reproduces a browser session.

## Records and identity

Every line is one JSON object with `schema_version: 2` and a `type`. Consumers
must use keys rather than assuming input order or adjacent lines imply a pair.
The execution has an internal unique ID, and every retained input occurrence
has its own target and bundle identity. Duplicate URLs remain distinct work.
The original input field contains the retained, trimmed line, before HTTPS
normalization; blank lines and comments do not create targets.

Caller labels are limited to 1024 characters each and retained target URLs to
8192 characters. These bounds keep individual records manageable. IDs such as
`target-1` or `attempt-2` are unique within an execution; use `execution_id`
together with the local ID when joining files from several executions.

The lifecycle consists of `run_start`, `bundle_start`, `attempt_start`,
`attempt_end`, `pair_end` where applicable, `bundle_end`, and `run_end`.
Preflight is an attempt with a separate phase, not a target or trial. Its Tor
verification result is retained without its response body or exit IP.

Attempt records include the original input and normalized URL, requested
route and routing assurance, actual issue order, timeout, UTC timestamps,
monotonic elapsed duration, curl result, nullable HTTP status, final URL,
redirect count, body-cap state, native verdict, and completion state. Unavailable
facts remain null. A curl timeout is a completed observation of a transport
failure; a scanner setup failure or cancelled process is not a completed
negative site response. `local_error` identifies local processing failures;
transport facts already captured remain present, but the native verdict is
null and `complete` is false. For example, an uncapped curl write error retains
its curl status without being counted as a site verdict.

Each-trial always-controls have pairing keys from the start. Conditional
controls can only be paired after the Tor outcome establishes eligibility;
the pair record then names both attempt IDs explicitly. A missing control
remains missing. Pair records retain the observed start gap when both probes
started, even if one was later aborted. The late flag is null when a second
start was never observed; pair completion is a separate fact.

Run records contain allowlisted effective settings, configured bounds, source
identity, caller labels, actual issued/completed counts, and terminal state.
A source digest identifies the executable sources even when no release version
is available. Retry-mode counts at the start are bounds rather than a promise
that every possible request will occur. Preflight and target counts are separate.
Verdict counts describe observations by route, not independent sites or people.

The principal machine fields are:

| Record | Fields to use |
| --- | --- |
| Every record | `schema_version`, `type`, `execution_id`, nullable `run_id` and `group_id`. |
| `run_start` | `settings` (including `request_profile`), `scanner`, `clocks`, and `planned`. |
| Target-related records | `target_id`, `target_occurrence`, `bundle_id`, `original_input`, and `url`. |
| `attempt_start` / `attempt_end` | `attempt_id`, `phase`, `route`, `global_order`, `bundle_order`, `trial_id`, `pair_id`, `pairing_state`, `routing`, `requested_timeout`, `started_at`, and `adapter_started`. |
| `attempt_end` | `ended_at`, `duration_seconds`, `status`, `complete`, `verdict`, `detail`, `http_status`, `curl_exit`, `curl_error`, `final_url`, `redirect_count`, `body_limited`, `tor_verified`, and `local_error`. |
| `pair_end` | `attempt_ids` keyed by route, `observed_start_gap_seconds`, `late`, `state`, `missing_routes`, and `aborted_routes`. |
| `bundle_end` | `state`, `attempts_issued`, and `attempts_completed`. |
| `run_end` | `state`, `complete`, `exit_code`, `duration_seconds`, `counts` split into preflight/target issued/completed, `target_states`, `verdict_counts`, and nullable `error`. |

`adapter_started: false` identifies a local invocation that could not even
start its adapter; it does not increment the issued count. Issued counts are
successful top-level adapter launches, not proof of a network packet or HTTP
request reaching its destination. Completed counts require a valid completed
observation. An HTTP refusal or curl timeout can therefore be complete even
though access failed. `tor_verified` applies only to preflight; it is null on
target observations. A missing verdict-count key means zero occurrences.

Consumers may ignore additional optional fields within v2. Removing fields or
changing their types or meanings requires a new schema version. Do not parse
human `detail` strings to recover fields or use them as stable classifications.

UTC timestamps describe civil time and may move if the system clock changes.
Pacing, durations, and partner gaps use Python's monotonic clock. Monotonic
values are useful within one execution; they are not cross-machine timestamps.

## Concurrency and pacing

One coordinator owns stdout and all request launches. Each observation has
private response files and its own owned process group. Requests within a
bundle remain sequential; independent hostnames may overlap. Hostname matching
is case-insensitive, ignores a trailing dot and port, and supports IPv6 literals.
Repeated occurrences of the same normalized hostname wait until its previous
bundle finishes. They are not deduplicated.

The start gap applies across every route and worker, including the single Tor
preflight at the beginning of the run. A top-level probe start means the
coordinator's invocation of its probe adapter. It is not a guarantee about
when curl is scheduled by the OS, opens a socket, sends a packet, or follows a
redirect. Redirect hops are outside this rate guarantee. Workers share the
local Tor process and network capacity. Hostname serialization and global pacing
are not provider-level throttling: different names may reach the same service.

## Failure, interruption, and sensitive data

A successful terminal record means the requested schedule completed, regardless
of native site verdicts. Detailed mode exits 0 on completion, 1 on runtime or
input-file failure, 2 for invalid command-line arguments, and ordinarily 130
or 143 for handled SIGINT or SIGTERM respectively. Output failure can prevent
writing the terminal record even when cancellation was also requested. Interruptions and fatal setup/output failures stop
new scheduling. Owned child processes are terminated and reaped, complete
available observations are retained when output remains writable, and terminal
records identify partial and unexecuted work. The scanner cleans its private
temporary response files; it does not provide persistent resume or recovery.

A consumer that stops reading stdout for two seconds is treated as an output
failure; the scanner stops issuing rather than accumulating unbounded output.
This is an output deadline, not a network timeout. A failed write may leave a
partial final JSON line, and the scanner does not retain a recovery spool.

An abrupt crash can leave no terminal record or a truncated last line. Treat
that file as incomplete. Never infer completion from the last successful
attempt. If stdout has failed, a terminal record may be impossible to write;
the nonzero process status and missing terminal record remain significant.

URLs, caller labels, and result details are still sensitive operational data.
Do not put credentials in targets or labels. Detailed input rejects URL
userinfo before requests, and emitted URL diagnostics exclude userinfo.
The format does not retain bodies, cookies, response headers, environment
dumps, exit IPs, or circuit identities. Query strings and caller-supplied labels
are not a safe place to hide secrets. JSON escaping protects record syntax;
it is not anonymization.
