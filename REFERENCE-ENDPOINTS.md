# Reference Endpoints for Tor Access Comparison

> **Status:** DRY RUN COMPLETED — CATALOG REMAINS GOVERNED<br>
> **Live observations:** Five issue #32 cases completed on 2026-08-30; private
> rows are not published in this catalog<br>
> **Dry-run selection:** Five documented public test cases approved by the
> owner on 2026-08-29 and completed under `TACP-0.1`<br>
> **Private targets:** Prohibited from this public file

This catalog defines how candidate and reference endpoints are described for
the manual access-comparison protocol. It is not a target list, a claim about
current site policy, or permission to measure an endpoint.

Every live case must also satisfy
[ETHICS-AND-DATA-STEWARDSHIP.md](ETHICS-AND-DATA-STEWARDSHIP.md) and be approved
under [VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md). Catalog expectations
never override current observation, operator contact, a lower interaction
limit, or a safety stop.

## Why the dimensions are separate

Terms such as “public,” “verified,” and “controlled” answer different
questions. Combining them into one status can hide an important limitation.
This catalog records them independently:

- **Lifecycle:** how ready the entry is for use.
- **Visibility:** whether naming the endpoint is permitted in public material.
- **Control:** whether the study operator controls the endpoint behavior.
- **Authorization basis:** why the planned interaction is permitted.
- **Publication sensitivity:** whether association with the study could create
  harm even if the endpoint itself is public.

A public third-party endpoint can be documented but unstable. An
operator-controlled endpoint can still be private. A documented mechanism can
be verified from operator material without having been observed live by this
project.

## Catalog schema

Each approved catalog entry must record:

| Field | Meaning |
|---|---|
| `entry_id` | Stable non-sensitive identifier |
| `endpoint` | URL or private reference; private values never enter this file |
| `lifecycle` | `desired`, `candidate`, `verified`, or `retired` |
| `visibility` | `public` or `private` |
| `control` | `third-party` or `operator-controlled` |
| `authorization_basis` | Purpose-built public test service, explicit operator authorization, or approved deliberately public ordinary content |
| `publication_sensitivity` | `low`, `review`, or `do-not-name` |
| `expected_mechanism` | Intended or hypothesized network/application behavior |
| `expectation_basis` | Operator documentation, controlled configuration, prior observation, or hypothesis |
| `expected_scanner_behavior` | Expected direct scanner observation, never a promised current verdict |
| `expected_tor_browser_behavior` | Expected human observation or `unknown` |
| `expected_ordinary_browser_behavior` | Expected human control or `unknown` |
| `stability` | Known stability limits and likely change mechanisms |
| `statefulness` | Whether prior requests, cookies, rate limits, or session state may change behavior |
| `interaction_limit` | Maximum permitted protocol interactions; lower than the global budget when needed |
| `verification_method` | How authorization and expected behavior were checked |
| `last_verified_utc` | Date of the verification above, not a promise of current behavior |
| `owner_or_contact` | Public operator/contact reference where appropriate |
| `retirement_trigger` | Condition that makes the entry ineligible |
| `notes` | Concise limitations without private operational detail |

### Lifecycle definitions

- `desired`: a behavior family needed for coverage; no eligible endpoint has
  been selected.
- `candidate`: a plausible endpoint exists, but one or more authorization,
  stability, verification, publication, or human-approval checks remain.
- `verified`: the endpoint's authorization basis and documented expected
  mechanism were checked recently enough for human review. This does not mean
  the project made a live measurement or that the outcome is guaranteed.
- `retired`: the endpoint must not be selected because authorization,
  stability, safety, relevance, or publication status changed.

## Completed five-case dry run

These cases use purpose-built public client-testing services. Documentation
review did not guarantee their observed behavior, and no endpoint request was
made while selecting them. The sanitized procedural record is in
[VALIDATION-DRY-RUN.md](VALIDATION-DRY-RUN.md).

| Case | Catalog entry | Approved browser task | Navigation |
|---|---|---|---|
| DR-01 | `HTTPBIN-LINKS-2` | Load the documented two-link page and identify its simple public content | Follow the first displayed first-party link |
| DR-02 | `HTTPBIN-STATUS-403` | Load the documented HTTP 403 response and record the stable browser outcome | Not applicable |
| DR-03 | `HTTPBIN-STATUS-429` | Load the documented HTTP 429 response and record the stable browser outcome | Not applicable |
| DR-04 | `TLS-EXPIRED-BADSSL` | Navigate directly and record the certificate-warning or refusal boundary | Not applicable; do not bypass the warning |
| DR-05 | `TLS-SELF-SIGNED-BADSSL` | Navigate directly and record the certificate-warning or refusal boundary | Not applicable; do not bypass the warning |

All five cases used the global interaction budget or the lower entry-specific
limit. I5 remained disabled. Preflight rechecked documentation, versions,
association, and opt-out status without making a measurement request.

## Public starter entries

The catalog eligibility and expected mechanisms below were verified against
public operator documentation on the dates recorded. Later live dry-run
observations are summarized separately in
[VALIDATION-DRY-RUN.md](VALIDATION-DRY-RUN.md); private outcomes are not copied
into this catalog.

### HTTPBIN-LINKS-2

| Field | Value |
|---|---|
| `entry_id` | `HTTPBIN-LINKS-2` |
| `endpoint` | `https://httpbin.org/links/2` |
| `lifecycle` | `verified` for documented purpose; approved as DR-01 on 2026-08-29; dry run completed 2026-08-30 |
| `visibility` | `public` |
| `control` | `third-party` |
| `authorization_basis` | Purpose-built public HTTP client-testing service |
| `publication_sensitivity` | `low`, subject to final human review |
| `expected_mechanism` | HTTP 200 HTML page containing two first-party links |
| `expectation_basis` | httpbin public endpoint documentation |
| `expected_scanner_behavior` | Expected `PASS` after redirects, if any; current observation controls |
| `expected_tor_browser_behavior` | Simple link page expected; exact rendering and availability remain unknown |
| `expected_ordinary_browser_behavior` | Simple link page expected; exact rendering and availability remain unknown |
| `stability` | Public test service; implementation and hosting may change |
| `statefulness` | Expected low for this GET endpoint |
| `interaction_limit` | One approved scanner invocation; one direct load and first displayed first-party link per primary browser; one protocol-defined reload at most |
| `verification_method` | Documentation review established catalog eligibility; live outcome retained privately under `TACP-0.1` |
| `last_verified_utc` | `2026-08-29` |
| `owner_or_contact` | https://github.com/postmanlabs/httpbin |
| `retirement_trigger` | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `notes` | Do not copy page content beyond the required structured outcome |

### HTTPBIN-STATUS-403

| Field | Value |
|---|---|
| `entry_id` | `HTTPBIN-STATUS-403` |
| `endpoint` | `https://httpbin.org/status/403` |
| `lifecycle` | `verified` for documented purpose; approved as DR-02 on 2026-08-29; dry run completed 2026-08-30 |
| `visibility` | `public` |
| `control` | `third-party` |
| `authorization_basis` | Purpose-built public HTTP client-testing service |
| `publication_sensitivity` | `low`, subject to final human review |
| `expected_mechanism` | Deliberate HTTP 403 response |
| `expectation_basis` | httpbin public endpoint documentation for `/status/:code` |
| `expected_scanner_behavior` | Expected `FAIL`; current observation controls |
| `expected_tor_browser_behavior` | Documented status response expected; exact browser presentation remains unknown |
| `expected_ordinary_browser_behavior` | Documented status response expected; exact browser presentation remains unknown |
| `stability` | Public test service; implementation and hosting may change |
| `statefulness` | Expected low for this GET endpoint |
| `interaction_limit` | One approved scanner invocation and one direct load per primary browser; no navigation; one protocol-defined reload at most |
| `verification_method` | Documentation review established catalog eligibility; live outcome retained privately under `TACP-0.1` |
| `last_verified_utc` | `2026-08-29` |
| `owner_or_contact` | https://github.com/postmanlabs/httpbin |
| `retirement_trigger` | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `notes` | Record the stable outcome; do not infer operator intent from the deliberate status response |

### HTTPBIN-STATUS-429

| Field | Value |
|---|---|
| `entry_id` | `HTTPBIN-STATUS-429` |
| `endpoint` | `https://httpbin.org/status/429` |
| `lifecycle` | `verified` for documented purpose; approved as DR-03 on 2026-08-29; dry run completed 2026-08-30 |
| `visibility` | `public` |
| `control` | `third-party` |
| `authorization_basis` | Purpose-built public HTTP client-testing service |
| `publication_sensitivity` | `low`, subject to final human review |
| `expected_mechanism` | Deliberate HTTP 429 response |
| `expectation_basis` | httpbin public endpoint documentation for `/status/:code` |
| `expected_scanner_behavior` | Expected `RATELIMIT`; current observation controls |
| `expected_tor_browser_behavior` | Documented status response expected; exact browser presentation remains unknown |
| `expected_ordinary_browser_behavior` | Documented status response expected; exact browser presentation remains unknown |
| `stability` | Public test service; implementation and hosting may change |
| `statefulness` | Expected low; this endpoint returns a requested status rather than inducing a rate limit |
| `interaction_limit` | One approved scanner invocation and one direct load per primary browser; no navigation; one protocol-defined reload at most |
| `verification_method` | Documentation review established catalog eligibility; live outcome retained privately under `TACP-0.1` |
| `last_verified_utc` | `2026-08-29` |
| `owner_or_contact` | https://github.com/postmanlabs/httpbin |
| `retirement_trigger` | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `notes` | The deliberate response exercises recording only; it is not evidence of organic rate limiting |

### TLS-EXPIRED-BADSSL

| Field | Value |
|---|---|
| `entry_id` | `TLS-EXPIRED-BADSSL` |
| `endpoint` | `https://expired.badssl.com/` |
| `lifecycle` | `verified` for documented purpose; approved as DR-04 on 2026-08-29; dry run completed 2026-08-30 |
| `visibility` | `public` |
| `control` | `third-party` |
| `authorization_basis` | Purpose-built public service for manual client testing |
| `publication_sensitivity` | `low`, subject to final human review |
| `expected_mechanism` | Expired TLS certificate |
| `expectation_basis` | badssl.com public site and project README |
| `expected_scanner_behavior` | TLS validation should prevent a usable HTTP classification; expected `CERT`, but current observation controls |
| `expected_tor_browser_behavior` | Certificate warning or refusal; exact interstitial and available actions depend on browser version and policy |
| `expected_ordinary_browser_behavior` | Certificate warning or refusal; exact behavior depends on browser version and policy |
| `stability` | Designed as a test endpoint, but the operator states functionality can change without notice |
| `statefulness` | Expected low; browser security state and prior exceptions can affect behavior |
| `interaction_limit` | One approved scanner invocation and the primary browser tasks; no warning bypass |
| `verification_method` | Documentation review established catalog eligibility; live outcome retained privately under `TACP-0.1` |
| `last_verified_utc` | `2026-08-28` |
| `owner_or_contact` | https://github.com/chromium/badssl.com |
| `retirement_trigger` | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `notes` | Browser warning bypass is outside the public task |

### TLS-SELF-SIGNED-BADSSL

| Field | Value |
|---|---|
| `entry_id` | `TLS-SELF-SIGNED-BADSSL` |
| `endpoint` | `https://self-signed.badssl.com/` |
| `lifecycle` | `verified` for documented purpose; approved as DR-05 on 2026-08-29; dry run completed 2026-08-30 |
| `visibility` | `public` |
| `control` | `third-party` |
| `authorization_basis` | Purpose-built public service for manual client testing |
| `publication_sensitivity` | `low`, subject to final human review |
| `expected_mechanism` | Self-signed TLS certificate |
| `expectation_basis` | badssl.com public site and project README |
| `expected_scanner_behavior` | TLS validation should prevent a usable HTTP classification; expected `CERT`, but current observation controls |
| `expected_tor_browser_behavior` | Certificate warning or refusal; exact interstitial and available actions depend on browser version and policy |
| `expected_ordinary_browser_behavior` | Certificate warning or refusal; exact behavior depends on browser version and policy |
| `stability` | Designed as a test endpoint, but the operator states functionality can change without notice |
| `statefulness` | Expected low; browser security state and prior exceptions can affect behavior |
| `interaction_limit` | One approved scanner invocation and the primary browser tasks; no warning bypass |
| `verification_method` | Documentation review established catalog eligibility; live outcome retained privately under `TACP-0.1` |
| `last_verified_utc` | `2026-08-28` |
| `owner_or_contact` | https://github.com/chromium/badssl.com |
| `retirement_trigger` | Operator withdrawal, changed documented purpose, unexpected content, or stewardship stop |
| `notes` | Browser warning bypass is outside the public task |

The badssl project describes itself as a manual client-testing service and
warns that functionality may change without notice. These entries therefore
provide documented mechanisms, not guaranteed observations.

## Desired test-case coverage

This is a coverage map, not an approved endpoint list. Each row identifies an
access or failure mode for which a controlled example could exercise the
observation record and scanner-to-browser comparison. The five-case dry run
does not need to cover every row.

The map keeps gaps visible without inventing targets or expanding the study to
find them. A `desired` row means that suitable coverage is wanted but no
eligible endpoint has been selected; it does not authorize discovery traffic.

| Behavior family | Lifecycle | Why useful | Safe endpoint requirement | Principal confounder |
|---|---|---|---|---|
| Ordinary HTTPS success | `desired` | Exercise the normal public task and observation form | Deliberately public ordinary content or controlled endpoint | Site content and dependencies change |
| Deterministic redirect chain | `desired` | Confirm final-target and navigation recording | Purpose-built or operator-authorized endpoint | Redirect target or browser policy changes |
| HTTP 401/403 refusal | `desired` | Exercise `FAIL` semantics without inferring intent | Operator-controlled or purpose-built endpoint | Authentication boundary and policy attribution |
| HTTP 429 rate limit | `desired` | Exercise `RATELIMIT` and state recording | Operator-controlled endpoint with explicit traffic limit | Testing may create the state being measured |
| Passive browser-solvable challenge | `desired` | Exercise `CHALLENGE` versus human friction | Explicitly authorized challenge designed for testing | Fingerprint, JavaScript, cookies, and time |
| Interactive CAPTCHA or access challenge | `desired`, observation boundary only | Confirm the protocol stops consistently | Public/authorized case; no solving | Human interaction is prohibited |
| Delayed response | `desired` | Exercise timeout and browser-access timing fields | Purpose-built endpoint with bounded delay | Local network and patience threshold |
| Connection reset or empty reply | `desired` | Exercise `DROP` transport symptoms | Purpose-built or operator-controlled endpoint | Exit, origin, and transient network conditions |
| Truncated transfer | `desired` | Exercise bounded transport failure classification | Purpose-built or operator-controlled endpoint | Client recovery behavior |
| Oversized response body | `desired` | Exercise `body_limited` and `WARN` interpretation | Purpose-built endpoint with documented size and low burden | Transfer burden and compression |
| Client-fingerprint-dependent response | `desired` | Test scanner/browser divergence hypotheses | Operator-controlled endpoint | Mechanism attribution without control |
| Tor-exit-dependent response | `desired` | Test ecological exit variation | Operator-controlled endpoint with explicit authorization | Scanner and Tor Browser exits differ |
| Stateful or cookie-dependent response | `desired` | Test session-rule completeness | Operator-controlled endpoint; no token retention | Prior state and privacy risk |
| SOCKS-path failure | `desired`, local/control preferred | Distinguish proxy-path diagnosis from site behavior | Local deterministic fixture, not a public target | Not a destination-site outcome |

## Ordinary public candidates

`targets-EXAMPLE.txt` contains well-known public sites that the repository has
already designated safe as examples. They are not automatically `verified`
catalog entries for this study. Before one can become an issue #33 pilot case,
the human reviewer must approve:

- the exact public task and navigation;
- the authorization basis and interaction limit;
- whether naming the site creates an unwanted association;
- the current stability and statefulness assessment;
- the verification date; and
- its role in the approved pilot allocation or stopping rule.

Do not record or publish a presumed verdict, WAF, Tor policy, or human outcome
for an ordinary public candidate before the contemporaneous protocol
observation.

## Private and operator-controlled entries

The schema supports `private` and `operator-controlled` values, but a private
entry and its endpoint belong only in the approved private structured store.
This public file may report only a sanitized behavior-family description when
the human reviewer determines that doing so is safe and useful.

Creating new controlled infrastructure is outside issue #32. A desired row may
remain unfilled rather than expanding scope.

## Case selection gate

The following gate governed the completed issue #32 dry run. Each selected
entry had:

- a completed catalog record and current verification date;
- an approved authorization basis and publication-sensitivity decision;
- a predeclared public task and navigation;
- an interaction limit compatible with the protocol;
- a planned order slot;
- a reason it improves procedural coverage; and
- a replacement rule that requires human approval rather than silent
  substitution.

The five selected cases are recorded above because they are deliberately public
and safe to name. For issue #33, do not treat their prior approval as an
approved pilot list: each candidate must appear in the human-approved pilot
manifest with current verification, an authorization and publication-sensitivity
decision, an interaction limit, and a preassigned order/batch slot. That
manifest and separate live authority remain required before collection.

## Sources

- [badssl.com dashboard](https://badssl.com/dashboard/)
- [badssl.com project README](https://github.com/chromium/badssl.com)
- [httpbin endpoint documentation](https://httpbin.org/legacy)
- [httpbin project](https://github.com/postmanlabs/httpbin)
- [Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md)
- [Ethics and data stewardship](ETHICS-AND-DATA-STEWARDSHIP.md)
- [`targets-EXAMPLE.txt`](targets-EXAMPLE.txt)
