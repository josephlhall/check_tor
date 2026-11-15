# Reference lab qualification results

On November 15, 2026, one operator ran four bounded checks on a temporary
reference lab using Tor Browser at Standard security and direct Firefox. The
scanner used the 20-second Tor startup check in `d7426bb`. These results
describe that deployment and those observations. Each future use needs its
own endpoint verification, traffic approval, and retirement plan.

| Case | What happened | Qualification |
|---|---|---|
| [#44](https://github.com/josephlhall/check_tor/issues/44) · Browser navigation | Both browsers reached the reading-room answer. The scanner received HTTP 403 over Tor and direct. Limited origin logging showed that requests matching the navigation-header rule received 200 and mismatches received 403. | **Partial.** We did not capture the parsed `Sec-Fetch-Mode: navigate` value for both document requests in each browser. Extra requests in the origin log could not be attributed to individual clients. |
| [#45](https://github.com/josephlhall/check_tor/issues/45) · Tor exit list | Tor Browser received 403. Direct Firefox loaded the start page and the answer. The scanner received 403 on three Tor attempts and passed its direct control. Origin logging corroborated the listed and unlisted branches. | The frozen IPv4 deployment showed the expected split. A later run needs a fresh reviewed snapshot and direct, source-preserving ingress. Two additional successful start requests could not be attributed to individual clients. |
| [#46](https://github.com/josephlhall/check_tor/issues/46) · Managed challenge | Both browsers saw a Cloudflare challenge and reached the answer without intervention. The first page took roughly 10–15 seconds in Tor Browser and 2 seconds in direct Firefox. | Both browsers completed this challenge passively. The challenge response header and edge request count were unavailable. A future challenge can behave differently. |
| Readable HTTP 202 | The scanner completed startup, reached the target over Tor and labeled its HTTP 202 response `CHALLENGE`. Its direct control also returned `CHALLENGE`. Both browsers read the accepted-and-pending message. | This was a new qualification endpoint. The [two earlier comparisons in #42](https://github.com/josephlhall/check_tor/issues/42) remain inconclusive because startup verification failed before the scanner made target requests. |

For the 202 case, a verified loopback check confirmed the status and body. The
public direct smoke check captured the body over verified TLS. Its shell
wrapper lost the numeric status. The scanner's Tor detail independently
recorded HTTP 202.

For #45, a synthetic loopback test on the deployment host served before
expiry, stopped five seconds before its deadline, and refused to restart
after expiry. The live origin was stopped early after the observations and
its listening socket was confirmed closed.

Both origins were stopped. The temporary host, firewall, test DNS records,
Tunnel, and challenge rule were removed, and the temporary credentials were
retired. Audited raw scanner outputs and the cached exit-list material were
deleted. The private structured observations follow the approved retention
schedule. The reusable lab is kept as source and tests.
