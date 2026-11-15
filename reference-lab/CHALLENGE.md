# Managed-challenge reference recipe

[REF-CHALLENGE in issue #46](https://github.com/josephlhall/check_tor/issues/46)
is an offline candidate for a future batch. It pairs a disabled
[Cloudflare rule template](challenge-rule.json) with a
[challenge-only reading-room origin](challenge-routes.conf). The proposed
public entry is `https://challenge-lab.josephhall.org/reading-room`, subject
to the domain owner's approval. The checked-in rule uses the reserved
`challenge-lab.example.org` placeholder. Live authority and the actual zone
and account capabilities are unresolved.

## Rule and task

Add one zone-level WAF custom rule in `http_request_firewall_custom` with
action **Managed Challenge**. It matches only GET and HEAD on the exact
hostname and the two exact paths below, as evaluated by Cloudflare. The path
field excludes the query string so it remains in scope when Cloudflare resumes
a navigation. There is no IP, exit, user-agent, or country selector. The
completion URL is protected too, including when visited directly. Provider
challenge resources and the other lab routes are outside this rule. Review the
account's path normalization and routing settings in case requests are
transformed before reaching nginx. [Rule actions](https://developers.cloudflare.com/ruleset-engine/rules-language/actions/) ·
[URL normalization](https://developers.cloudflare.com/rules/normalization/)

| Path | Task content at the origin |
| --- | --- |
| `/reading-room` | Identify the example room's opening hours (9 a.m. to 5 p.m.), then follow **Read the visitor information** once. |
| `/reading-room/complete` | Recognize that the room is on the ground floor. This completes the task. |

The origin serves two small static HTTP 200 pages with no forms, scripts,
cookies, redirects, or external assets. It ignores query values. The Cloudflare
interstitial is a separate edge response and may add requests, redirects, and
cookies. Other methods and paths are not challenged by this rule. They reach only the
bounded origin rejection handlers: unsupported methods return 405 before route
lookup, body-bearing requests return 400, and other ordinary paths return 404.
These responses contain no protected task content. The origin emits no synthetic
challenge response or header. Turnstile
dummy keys exercise widget integration. [Cloudflare Challenge Pages](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/) ·
[Turnstile test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)

Run `python3 reference-lab/test_challenge.py -v` from the repository root
with the [lab test tools](OPERATIONS.md#reproduce-locally). The tests check the
disabled rule's exact action and match expression, then exercise the origin
over loopback HTTPS, including navigation, HEAD, and rejected routes. Their
coverage is limited to the checked-in configuration and origin behavior.

## Action card for a future deployment

1. **Confirm zone and access.** Obtain owner authorization for the exact
   hostname, dates, opt-out contact, and named DNS, security-rule and Tunnel
   operators. Cloudflare's public WAF documentation, checked 2026-11-14,
   lists zone custom rules and the Managed Challenge action on Free and paid
   plans, with five custom rules on Free. Confirm the actual plan, a free
   rule slot, the action and expression in the chosen zone, the hostname's
   DNS availability, and edge TLS coverage. Review inherited account/zone
   rules and rule order, including bot protection, redirects, rewrites,
   cache or Worker routing, rate limits and access policies. If isolation
   would require changing production policy or buying a feature without
   an approved budget, defer this condition. [Custom-rule availability](https://developers.cloudflare.com/waf/custom-rules/#availability) ·
   [Security rule ordering](https://developers.cloudflare.com/waf/feature-interoperability/) ·
   [Universal SSL limitations](https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/)
2. **Approve one short-lived origin and its costs.** The proposal needs
   one dedicated temporary Linux host with the lab's resource limits, one
   nginx process, one named Cloudflare Tunnel and connector, one proxied DNS
   record, and one rule slot. Use the [base lab's host sizing and cost
   checklist](OPERATIONS.md#deployment-action-card), keeping nginx bound to
   loopback. Confirm Tunnel entitlement, TLS and any domain charges, compute,
   transfer, and any other billable line items. Approve a total spending cap,
   deadline, and named teardown owner before provisioning. Budget maintenance,
   certificate issuance, and connector traffic separately from qualification
   and collection. The origin has no public ingress or direct transport-fault
   hostname. Edge TLS termination would mask direct transport failures.
3. **Prepare the origin and staged rule.** Pin the reviewed commit and
   software versions. On the dedicated host, install `nginx.conf` with
   `challenge-routes.conf` staged as `routes.conf`. Retain the HTTPS
   loopback listener and request/logging limits. Use an origin certificate
   with a SAN for `localhost` and a dedicated private CA, and verify both
   routes locally before publication. In a deployment copy of
   `challenge-rule.json`, substitute the approved hostname. Stage the one
   custom rule as a draft via the zone security dashboard, and review the
   exact expression, action, order, and effective settings before deploying it.
   [Create a WAF custom rule](https://developers.cloudflare.com/waf/custom-rules/create-dashboard/)
4. **Authorize and enable public routing.** Create one dedicated named Tunnel
   and install and run `cloudflared` on the temporary host. Configure one
   published application for the approved hostname to
   `https://127.0.0.1:18443`, with Origin Server Name `localhost` and CA Pool
   set to the dedicated CA's public certificate. Leave TLS verification
   enabled. Use only that exact hostname and service, with a final HTTP 404
   catch-all and no wildcard hostname, private-network route, or Access sign-in.
   Keep source-address classification and direct transport checks off this
   tunnel. Deploy the staged rule
   before publishing the exact proxied CNAME to the tunnel and making the
   connector reachable. Some dashboard workflows create the CNAME when
   saving the route. Keep the connector stopped until both scope and edge
   certificate are checked. Use named operator access limited to the selected
   zone for WAF and DNS, and authorized Tunnel administration in the account.
   Only the tunnel-specific connector token belongs on the temporary host.
   Keep it and TLS private keys out of Git, shell history, and shared logs.
   [Published applications](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/) ·
   [Tunnel TLS settings](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/#tls-settings)
5. **Protect evidence and retire the service.** Leave nginx access logging off.
   Before enabling public traffic, review Cloudflare and host logging,
   including captured source addresses, cookies, and events, access permissions,
   retention and deletion. An edge necessarily processes network metadata.
   Disable optional raw logging and exports and use only aggregate provider
   metrics where needed. Browser cookies, clearance tokens, and screenshots
   are excluded from collection and export. Keep origin and connector
   credentials, logs, source addresses, and any separately approved raw
   evidence outside the repository and public reporting.
   At the first rollback trigger, stop the connector so cached DNS cannot
   keep serving the origin. Remove the dedicated route and CNAME, then restore
   the prior rule state by removing the dedicated rule. At retirement delete
   the tunnel, revoke its credentials, retire the origin certificate/key,
   stop nginx, and destroy the host and any billable resources. Record
   completion, billing, and any provider retention beyond operator control.
   Retain source and sanitized operational notes for a future rebuild.
   [Data stewardship](../ETHICS-AND-DATA-STEWARDSHIP.md)

## Qualification and study boundary

Freeze the approved URLs, catalog ID, rule and deployment revisions, operator
authority, review date, browser versions, and known residual zone effects.
Verify edge TLS and review the effective rule and routing for both task paths
independently of scanner verdicts. Confirm the harmless task at the origin.
A Healthy tunnel status confirms connector connectivity. Origin task readiness
requires the separate route checks. Record a tunnel or origin outage as a
technical failure when supported by the evidence, with challenge interaction
left unknown if the observer cannot establish it.
Budget any future external smoke traffic explicitly before it runs, including
the scanner preflight if used, both browser paths, provider redirects and
auxiliary requests, and a deadline and halt rules. Treat eligibility checks and
the separately authorized analytic batch as different traffic. On unexpected
scope, heavy traffic, refusal, or ambiguous qualification, stop and record the
reason. Failed qualification supplies no permission to screen other clients,
exits, rules, or endpoints for a desired challenge.
[Readiness manifest and traffic ceilings](../VALIDATION-REFERENCE-PACKET.md#future-live-readiness-manifest-fields)

For a future approved case, follow the [browser protocol](../VALIDATION-REFERENCE-PROTOCOL.md#approved-browser-task-and-timing-rules).
Use its fresh browser state for each case and allow passive completion within
the existing deadlines. Preserve naturally acquired state during the same
task, including the first-party navigation. A successful challenge may set
a temporary `cf_clearance` cookie that affects subsequent requests, including
the completion path. Never transfer, clear, inspect for reuse, or replay
clearance to change a result. A CAPTCHA, verification click, login, consent
disclosure, or workaround stops the entire case immediately. Record
`PROHIBITED`, leave it untouched, and skip remaining instruments. For a
passively observed interstitial, record whether it completed automatically
and apply the existing timing and friction rules.
[Cloudflare Challenge Passage](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/challenge-passage/)

Provider behavior can vary across requests and over time, including with
browser version and security settings, exit and browser signals, existing
clearance, rule order, account configuration, and software maintenance. A
matching rule establishes the configured mechanism. Task success alone leaves
a challenge unobserved. Record contemporaneous browser facts or separately
approved response evidence before attributing an actual challenge.

The completed first batch used JSONL v1, which has no HTTP status, response
headers, or per-attempt verdicts. Retain its results and interpretation.
[Detailed JSONL v2](../DETAILED-OUTPUT.md) exposes per-attempt status, verdict
and selected structured response evidence. Cloudflare documents
`cf-mitigated: challenge` on actual Challenge Page responses, and this
recipe collects none. Any future switch to v2 or live header collection
requires prospective instrument review, explicit approval and traffic budget,
and private custody under the manifest. [Cloudflare response detection](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)
