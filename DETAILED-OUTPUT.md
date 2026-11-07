# Detailed measurement output

Use `--format jsonl-v2` when you need a record of each request, control over
the order and timing of Tor and direct comparisons, or evidence about where
a run stopped. Detailed mode uses the same Zsh probe and classifier as
the ordinary scanner and adds a Python coordinator to schedule requests and
write JSON Lines. It requires Python 3.9 or newer and uses only the standard
library. Text and JSONL v1 work with Zsh and curl without Python.

Use the [first-scan instructions](README.md#run-your-first-scan) to start
Tor and check curl's certificate trust before running these examples. Keep
target files and output outside the repository with restrictive permissions.
Use endpoints appropriate for the collection you have authorized.

## Choosing a measurement policy

To record each observation while keeping the default failure-driven retries
and conditional comparison for the target, select the output format alone.

```zsh
./check_tor.zsh --format jsonl-v2 /path/outside/repo/targets.txt
```

For three Tor/direct pairs per input occurrence, specify fixed trials and
a control for each trial. This example alternates which route goes first,
uses equal request timeouts, and can overlap work on two distinct hostnames.

These scheduling options bypass ambient proxies for direct probes. Qualify
curl on that direct path with the same executable and CA settings; a check
through an environment proxy does not cover it. Use a subshell to remove the
proxy overrides just for the checker and this run:

```zsh
(
  unset http_proxy https_proxy all_proxy no_proxy
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
  ./scripts/check-curl-trust.zsh &&
    ./check_tor.zsh --format jsonl-v2 --trials 3 \
      --control always --control-scope trial \
      --order counterbalanced --seed 42 \
      --timeout-first 30 --timeout-retry 30 --timeout-clearnet 30 \
      --max-partner-gap 60 --workers 2 --start-gap 1 \
      /path/outside/repo/targets.txt
)
```

| Setting | Meaning |
| --- | --- |
| Omit `--trials` | Retry block-like verdicts until the result changes to `PASS`, `CERT`, or `WARN`, or the run reaches `--circuits`. |
| `--trials N` | Schedule 1–100 fixed Tor trials per input occurrence. Each verdict counts as one observation. A failure of the scan, interruption, or the cautious policy can end the sequence early. |
| `--control conditional` | Make a direct control only when the associated Tor result is block-like. This is the default. |
| `--max-redirects N` | Follow at most `0`–`100` redirects per Tor/direct target probe; default `10`. Available in every output mode. |
| `--control always` | Make the control even after a successful Tor result. |
| `--control never` / `--no-clearnet` | Make no direct controls. |
| `--control-scope target` | One control for the whole target bundle; conditional eligibility uses its final Tor observation. This is the default. |
| `--control-scope trial` | A control belongs to an individual fixed trial. Requires `--trials` and enabled controls. |
| `--order tor-first` | Tor precedes its control; this is the default and the only order for conditional controls. |
| `--order direct-first` | With always-controls, run direct first. For target-scoped controls this precedes the whole Tor sequence. |
| `--order counterbalanced --seed N` | Choose reproducible order independently of outcomes, circuit tags, and worker completion order. Requires always-controls. |
| `--max-partner-gap S` | Mark a pair late if the start times of its two probes are more than S seconds apart. Accepts positive seconds up to 3600, default 60. Requires trial-scoped controls when set explicitly. |
| `--execution-policy legacy\|paired-cautious` | Default `legacy`. `paired-cautious` prioritizes ready pair partners and stops an input hostname after explicit HTTP 429. |
| `--workers N` | At most N active target bundles, from 1 to 32; default 1. |
| `--start-gap S` | Global minimum interval between coordinator probe invocations, in seconds, from 0 to 3600; default 0. |
| `--run-id TEXT`, `--group-id TEXT` | Optional labels for your analysis. Join records by the scanner's generated execution ID. |

Fixed trials continue after `PASS`, `CERT`, and `WARN`. Block-like verdicts
count toward the chosen number of trials and do not add failure retries.

The scanner rejects incompatible options before it reads the target file or
makes a request. Choose either `--trials` or an explicit `--circuits`.
Use `--order tor-first` for conditional controls, since their eligibility
depends on the Tor result. A trial scope requires enabled controls, and
alternative orders require `--control always`. Scheduling options require
`--format jsonl-v2`.

Counterbalanced order uses `(seed + target_occurrence - 1 + trial - 1) % 2`:
zero selects Tor first, one selects direct first. For a target-scoped control,
use trial 1 in that formula. The seed is an integer from 0 through 2147483647.
This alternates order reproducibly; it does not claim random assignment.

The first Tor observation uses `--timeout-first`; later Tor observations use
`--timeout-retry`, including later fixed trials. Controls use
`--timeout-clearnet`. Set all three equally when equal timeout budgets are
part of the intended comparison. The partner-gap setting flags elapsed time;
it does not interrupt a slow partner or add a replacement observation.

A target bundle contains the requests for one input occurrence. A
target-scoped control belongs to the whole bundle. Use trial-scoped controls
to compare individual pairs. Fixed trials report individual outcomes and
counts. Choose a separate analysis rule if you need a single target verdict.

## Routing and request configuration

By default, detailed mode inherits the ordinary scanner's proxy settings
from the environment. In that case the record identifies the requested route
and marks its effective routing as unknown. Use `--reproducible` to remove
proxy environment overrides from child processes. The scanner then directs
Tor probes through the selected SOCKS endpoint and makes direct probes
without a proxy. Explicit trial, control, order, execution policy, worker,
or pacing options enable this behavior even if you specify a default value.
Both routing modes keep the configured TLS trust and suppress `.curlrc`.

Detailed mode uses curl's TLS and HTTP behavior, the scanner's fixed headers
and body cap, and the selected redirect limit. It disables curl URL globbing
so braces and ranges in one input stay part of a single URL. SOCKS usernames
request circuit isolation, but different circuits can share an exit. Treat
the measurements as repeated curl observations. A browser may get a
different response or do more with the same response.

## Records and identity

Every line is one JSON object with `schema_version: 2` and a `type`. Consumers
must use keys rather than assuming input order or adjacent lines imply a pair.
The execution has an internal unique ID, and every retained input occurrence
has its own target and bundle identity. Duplicate URLs remain distinct work.
The original input field contains the retained, trimmed line, before HTTPS
normalization; blank lines and comments do not create targets.

The scanner accepts up to 1024 characters for each caller label and up to
8192 characters for each retained input line before URL normalization. These bounds keep individual records manageable. IDs such as
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
The scanner hashes the executable source files to identify the version
that ran, even without a release tag. The digest includes comments, so a
comment-only edit also changes it.
Retry-mode counts at the start are bounds rather than a promise that every
possible request will occur. Preflight and target counts are separate.
Verdict counts describe observations by route, not independent sites or people.

The principal machine fields are:

| Record | Fields to use |
| --- | --- |
| Every record | `schema_version`, `type`, `execution_id`, nullable `run_id` and `group_id`. |
| `run_start` | `settings` (including `request_profile`), `scanner`, `clocks`, and `planned`. |
| Target-related records | `target_id`, `target_occurrence`, `bundle_id`, `original_input`, and `url`. |
| `attempt_start` / `attempt_end` | `attempt_id`, `phase`, `route`, `global_order`, `bundle_order`, `trial_id`, `pair_id`, `pairing_state`, `routing`, `requested_timeout`, `started_at`, and `adapter_started`. |
| `attempt_end` | `ended_at`, `duration_seconds`, `status`, `complete`, `verdict`, `detail`, `http_status`, `curl_exit`, `curl_error`, `final_url`, `redirect_count`, `body_limited`, `tor_verified`, and `local_error`; target observations may also include `stop_reason` and `redirect_evidence`. |
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
changing their types or meanings requires a new schema version. The explicitly
selected `paired-cautious` policy extends v2 with a new terminal state
`policy_stopped` and exit code `3`. This expands existing value domains, beyond
optional-field additions; strict readers must support these before opting in.
Existing values retain their meanings. Use structured fields for
classification and reserve human-readable `detail` for display.

UTC timestamps describe civil time and may move if the system clock changes.
Pacing, durations, and partner gaps use Python's monotonic clock. Monotonic
values are useful within one execution; they are not cross-machine timestamps.

## Redirect observations

`--max-redirects N` counts redirects **followed**, excluding the initial request.
For A → B → C, a budget of zero visits only A. A budget of one visits A and
B, leaving C unvisited. A terminal response reached after exactly N
redirects keeps its normal verdict. The default remains ten, and preflight follows no redirects
regardless of this setting. `run_start.settings.max_redirects` and
`settings.request_profile.redirect_limit` both report the effective choice.

Target `attempt_end` records add optional fields within schema v2:

| Field | Meaning |
| --- | --- |
| `stop_reason` | `redirect_limit` for native curl exit 47, `body_limit` when the inspection cap takes precedence, otherwise null. A stop is inconclusive about subsequent access. |
| `redirect_evidence.state` | `complete`, `unavailable`, `invalid`, `unsupported`, or `truncated` extraction. This describes evidence quality, not access or scanner completion. |
| `redirect_evidence.followed` | Ordered records with one-based `hop`, `http_status`, `response_url`, and resolved `destination` for each retained followed redirect. A prefix may be retained when later evidence is unusable. |
| `redirect_evidence.next_destination` | Resolved, sanitized destination left unvisited at curl's redirect limit, or null. No response was observed for this next hop; its URL may already have appeared in a cycle. |
| `redirect_evidence.next_destination_state` | `available`, `absent`, `invalid`, `unsupported`, `truncated`, `unavailable`, or `not_applicable` (no redirect-limit stop). |

Existing `final_url` and `http_status` describe the final **visited** response;
`redirect_count` remains curl's number of followed redirects, even when fewer
hops can be retained as evidence. Native curl status/error facts are preserved.
Reaching the limit is `WARN`, not proof of a loop, inaccessible destination, or
Tor blocking. It causes neither failure-driven retries nor conditional controls;
explicit fixed trials and always-controls retain their schedules.

The cutoff destination comes from curl's native `redirect_url`, including its
resolution of relative Location values. It can remain available even when hop
headers are unavailable. The collector reconstructs followed hops from complete
HTTP response blocks and curl's follow count, ignoring informational and proxy
CONNECT responses. It resolves relative Location values against the response
URL and checks the reconstructed terminal URL against curl's effective URL.
References with known curl/Python resolution differences (such as three leading
slashes, fragment-only references, empty query/fragment delimiters, explicit
schemes without an authority, or repeated path slashes) are unsupported for
reconstruction. The collector also treats unnormalized dot segments as
unsupported. It records why evidence is incomplete when facts conflict,
headers are missing, Location values are duplicate or folded, or URLs are
malformed or use unsupported schemes. Missing facts stay null. Check the
evidence state before interpreting an empty hop list.

`settings.redirect_evidence_bounds` records finite extraction/retention bounds:
at most 262144 private header bytes examined, 100 hop records, 8192 UTF-8 bytes
per URL value, and 65536 bytes of JSON-escaped evidence per attempt. When a bound
is exceeded, whole URL values or trailing hop records are omitted and evidence
is marked truncated; URLs are never shortened into apparently valid destinations.
These metadata bounds do not increase curl's follow budget or change its body,
timeout, or routing policies. Private response files are removed with their
request directory and are never exported.

Only allowlisted status and sanitized URL fields are retained; raw headers,
cookies, authorization material, and bodies are excluded. URL userinfo is
removed from every exported hop and next destination. Query strings and
fragments are retained for destination interpretation and may contain sensitive
values: detailed output remains operational data, not anonymized output. Invalid
metadata is represented by fixed state labels, never echoed in diagnostics.

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

## Cautious collection and completion

`--execution-policy paired-cautious` is an opt-in detailed-mode contract. It
implies reproducible routing, preserves selected pair order and control rules,
and records its effective value in `run_start.settings.execution_policy`.
`legacy` keeps the existing schedule. The policy does not automatically sleep,
retry, replace observations, resume, or combine outcomes from several runs.

At each eligible launch, the coordinator processes available completions and
prefers a ready second pair member over new-target or unpaired work. Pacing,
worker ceilings, sequential routes, and whole-bundle hostname serialization
still apply. A slow first member is not preempted; priority promises no maximum
partner gap. `observed_start_gap_seconds` and `late` remain start-to-start facts.

A completed explicit HTTP 429 on either route stops unlaunched work for the
normalized input hostname, including later input occurrences. Case, trailing
dots, and ports use the existing hostname matching. Redirects do not broaden
this to other hostnames or providers. HTTP 503, response body text, certificate
failures, and timeouts do not trigger the stop. Unrelated hostnames continue.
Missing or bad retry metadata cannot prevent a 429 stop.

A completed 429 remains a complete native observation. A suppressed partner is
missing, not aborted, and has no invented attempt ID. A shortened bundle stays
`partial`; a suppressed occurrence that never starts stays `not_started`.

The policy records bounded omission descriptions tied to the triggering
attempt. Known-required requests are distinguished from future controls/retry
opportunities whose eligibility was never determined. Planned request counts
remain upper bounds; subtracting issued requests does not count actual skipped
requests. Three always-controlled pairs stopped on their first Tor request
have one issued/completed request and five known-required omissions.

| Invocation outcome | `state` | `complete` | Exit code |
| --- | --- | --- | --- |
| Required observations and invocation finished | `complete` | `true` | `0` |
| Policy omitted work; remaining work finished normally | `policy_stopped` | `false` | `3` |
| Runtime, setup, output, or cleanup failure | `error` | `false` | `1` |
| Handled interruption without overriding fatal failure | `interrupted` | `false` | `130` / `143` |

The cautious policy adds independent `run_end.schedule_complete` and
`policy_truncated` booleans. Schedule coverage means all required observations
finished; controls established as unnecessary are not missing work. Policy
truncation means the policy actually omitted work. Failure/interruption takes
precedence in the terminal state while earlier omission evidence remains.
Cleanup can fail after all observations finish: `schedule_complete` can then
be true while `complete` is false. A last-request 429 that omits nothing permits
normal completion, with `policy_truncated: false`.

For a 700-domain run, a single hostname stop can therefore make the invocation
incomplete without invalidating the other 699 domains' observations. A later
invocation has a new identity and never revises this result. A later 200 does
not by itself complete even that new invocation; its requested schedule must
finish. Combining observations into a study is a caller decision.

A reader should accept exit `3` as a policy outcome only with a
valid matching terminal record, keep usable observations, and inspect omissions
before deciding whether to invoke the scanner again. Require exit `0` plus a
valid complete terminal record for full successful execution. An absent,
truncated, or contradictory terminal record is incomplete evidence, even if
an earlier attempt succeeded. Failures and signals retain their significance.

### Cautious policy machine fields

| Record | Additional fields |
| --- | --- |
| `hostname_stop` | Normalized `hostname`, `triggering_attempt_id`, `triggering_target_id`, `route`, `http_status`. Emitted even if nothing remains to omit. |
| `target_omission` | Target identity, stop reason/trigger fields, and compact `known_required` / `eligibility_undetermined` lists. |
| `pair_end` | `missing_reason` identifies the hostname stop when it withheld a partner. |
| `bundle_end` | Optional `omission` retains that target's stop and omission description. |
| `run_end` | `schedule_complete`, `policy_truncated`, `hostname_stops` count, `omission_counts`, and `schedule_accounting`. |

Each range descriptor contains `route`, inclusive `trial_range: [first, last]`,
`count`, and a structured `description`. In retry mode these ranges identify
potential attempt ordinals, not invented fixed-trial IDs. Once-per-target
controls use `scope: "target"` and `count: 1` instead of a trial range.
`omission_counts` has `known_required` and `eligibility_undetermined` totals.
`schedule_accounting` distinguishes `known_required_omitted`,
`eligibility_undetermined_omitted`, `known_required_unresolved`,
`eligibility_undetermined_unresolved`, and `known_unnecessary`. Unresolved
requirements can include launched observations that failed to complete; these
counts are not another count of issued requests. Native issued/completed counts
remain separate. Required versus undetermined is about eligibility, not whether
an eventual request would succeed.

### Retry-After evidence

Target/control `attempt_end.retry_after` describes only the final visited
response. It is additive in detailed output, independent of the selected
execution policy. Status 429/503 can have retry evidence; other statuses are
`not_applicable`. `state` is `usable`, `absent`, `invalid`, `unavailable`,
`truncated`, or `not_applicable`; `reason` explains syntax, duplicates, overflow,
missing/mismatched/incomplete response blocks, or the finite bound encountered.
No raw header values or other arbitrary headers are exported.

Usable evidence contains `form` (`delay_seconds` or `http_date`), `units:
"seconds"`, `wait_seconds`, `reference_time_utc`, `reference_basis`, and
`clock_uncertainty`. Delay-seconds are anchored at observation completion,
conservatively later than receipt. HTTP dates also contain `not_before_utc` and
`past_date`; the wait rounds a positive date difference upward to whole seconds.
A zero or past date produces zero by the stated clock. An unavailable comparison
clock produces no guessed wait. UTC wall clocks may move, and the local/server
clock offset is unknown; a caller must choose its fallback for unusable evidence
and its own allowance for clock uncertainty. A parsed wait never promises that
a later request will succeed.

The parser accepts HTTP's three date forms (IMF-fixdate and obsolete RFC850 and
asctime forms); RFC850 two-digit years use the completion-relative fifty-year
rule. Grammar, calendar/date range, duplicate fields, numeric range, and capture
bounds have distinct failure reasons. Maximum retained wait is 2147483647
seconds; excessive values are rejected rather than clamped. Extraction examines
at most 262144 private header bytes, 256 response blocks, 4096 lines, 256 bytes
per retry value, and 100 followed redirects; retained evidence is at most 2048
serialized bytes. URL comparison is bounded to 8192 UTF-8 bytes. The effective
bounds are recorded in `settings.retry_after_bounds`. Interim, CONNECT, earlier
redirect, and unvisited response metadata cannot supply the final retry value.
Header files remain private and are removed with the observation directory.

## Failure, interruption, and sensitive data

Use the terminal record and exit status together to assess completion. See
the [outcome table](#cautious-collection-and-completion) for the statuses a
started run can report. Invalid detailed-mode arguments exit with code `2`
before the schedule starts.

On interruption or fatal setup or output failure, the scanner stops
launching new work, terminates its child processes, and cleans its private
temporary response files. If it can still write output, it keeps available
observations and reports partial and unexecuted work in the terminal record.
To collect again, start a new invocation.

A consumer that stops reading stdout for two seconds is treated as an output
failure; the scanner stops issuing rather than accumulating unbounded output.
This is an output deadline, not a network timeout. A failed write may leave a
partial final JSON line, and the scanner does not retain a recovery spool.

A crash or failed write can leave a truncated line or prevent the scanner
from writing a terminal record. Treat the run as incomplete in either
case, even if the last complete attempt succeeded. Retain the nonzero
process status alongside any records you can still read.

Treat detailed records as sensitive. The scanner rejects credentials in
the userinfo part of an input URL and removes userinfo from emitted URL
diagnostics. The record format excludes raw bodies, cookies, headers,
environment dumps, exit IPs, and circuit identities. It can still expose
target URLs, query strings, caller labels, and result details. Keep
credentials out of targets and labels and store the records privately.
