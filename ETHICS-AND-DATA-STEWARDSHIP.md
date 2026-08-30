# Ethics and Data Stewardship for Tor Access Comparison

> **Status:** APPROVED GOVERNANCE POLICY<br>
> **Applies to:** The five-case issue #32 dry run and any later study using the
> Tor Access Comparison Protocol<br>
> **Data steward:** Joseph Lorenzo Hall<br>
> **Incident owner:** Joseph Lorenzo Hall<br>
> **Contact, opt-out, and incident reports:**
> [joehall@gmail.com](mailto:joehall@gmail.com)<br>
> **Storage and retention:** Local owner-only root established, excluded from
> Time Machine, with retention schedule approved

This document is the public ethical-measurement pledge and normative
data-stewardship policy for the `check_tor` access comparison. It governs
[VALIDATION-PROTOCOL.md](VALIDATION-PROTOCOL.md) and can prohibit or halt a
protocol step. The policy governed the completed issue #32 dry run and remains
in force, but it does not by itself authorize issue #33 or any other live
collection.

## Public-interest purpose

The project studies whether an automated `curl`-over-Tor scanner describes the
practical access available to a human Tor Browser user. Better calibration may
help public-interest technologists recognize barriers faced by Tor users while
reducing unsupported claims about particular sites or operators.

The work does not seek to rank organizations, estimate Internet-wide blocking,
identify vulnerable targets, defeat anti-abuse controls, or create a reusable
evasion system. A useful result may be narrower scanner language or a decision
not to collect more data.

## Ethical principles

The study applies four principles adapted to this setting:

- **Respect for persons:** Consider people and organizations affected even when
  they are not conventional research subjects. Do not collect identities,
  private communications, credentials, or personal data. Provide a meaningful
  contact and opt-out path.
- **Beneficence:** Use the minimum traffic and data needed for a falsifiable
  public-interest question. Assess benefits, burdens, and foreseeable misuse;
  stop when marginal collection no longer justifies risk.
- **Justice:** Do not place measurement burdens on sensitive, vulnerable, or
  convenient targets merely because they are easy to reach. Review whether
  publishing a site's inclusion could create an unfair association.
- **Respect for law and public interest:** Perform legal and policy due
  diligence, make methods and limits public, keep accountable records, and
  escalate uncertainty rather than treating public reachability as unlimited
  permission.

These principles draw on the
[Menlo Report](https://research.rutgers.edu/sites/default/files/2022-09/Menlo%20Report_Ethical%20Principles%20Guiding%20Info%20and%20Comm%20Tech%20Research.pdf),
[current ACM Internet Measurement Conference ethics guidance](https://conferences.sigcomm.org/imc/2026/submission-instructions/),
and [RFC 1262](https://www.rfc-editor.org/rfc/rfc1262.html). They are safeguards
for this project, not a claim that following them resolves every institutional,
legal, or human-subjects obligation.

## Stakeholders and foreseeable harms

Stakeholders include:

- Tor users whose access problems the study hopes to understand;
- endpoint operators and their users;
- Tor relay and infrastructure operators;
- the researcher and human reviewer;
- organizations whose inclusion could imply that they block Tor or seek
  protection; and
- downstream readers who may overgeneralize a small purposive study.

Foreseeable harms include unnecessary load, triggering anti-abuse systems,
exposing target lists or observed IP addresses, linking ordinary and Tor
activity, publishing an unwanted association, overstating intent or causality,
and disclosing a vulnerability before an operator can respond.

The study design must minimize those harms and preserve enough public
methodology for others to audit what was and was not measured.

## Public pledge

For every approved measurement, the project commits to:

1. ask a bounded, documented public-interest question;
2. prefer purpose-built public test endpoints or explicitly authorized cases;
3. use deliberately public ordinary content only after association review;
4. minimize requests, collection, retention, and access;
5. avoid authentication, personal data, state-changing interactions, and
   access-control circumvention;
6. honor operator contact, opt-out, and abuse signals promptly;
7. halt on unexpected risk or suspected operational harm;
8. distinguish direct observation, automated inference, human classification,
   and causal hypothesis;
9. publish methods and limitations without exposing restricted evidence; and
10. require human review for protocol changes, causal or policy claims,
    publication decisions, and any safety exception.

## Endpoint eligibility

A case is eligible only when its catalog record states an authorization basis
and the human reviewer approves its use. Acceptable bases are:

- a purpose-built public test service that documents the intended behavior;
- explicit permission from the operator for the planned interaction; or
- deliberately public ordinary content, reviewed for proportionality and the
  risk that inclusion itself creates an unwanted association.

Public reachability alone does not authorize burdensome, deceptive, or
state-changing testing. A case that may impose unusual load or appear intrusive
requires operator permission. Non-public operational or historical target
lists are never eligible.

Candidate screening must itself follow the protocol and interaction budget.
Do not conduct a broad or random scan to find interesting cases. A prior result
does not substitute for the contemporaneous scanner observation, and the
current behavior of a third-party endpoint is never guaranteed by its catalog
entry.

## Prohibited interactions and collection

The study must not:

- log in or use credentials;
- enter or submit names, email addresses, contact information, payment data,
  or other personal information;
- submit forms, make purchases, post content, vote, upload, or download files;
- solve CAPTCHAs or interactive “prove you are human” tasks;
- bypass access controls, evade anti-abuse systems, or disguise traffic beyond
  the scanner's fixed request profile;
- exploit or validate a suspected vulnerability beyond the accidental
  observation that triggered the stop;
- select exit countries, assume control of exits, or attempt same-exit testing;
- use non-public operational or historical target lists, or any private target;
- collect credentials, cookies, challenge tokens, authentication material,
  packet captures, unrestricted network traces, or unrelated page content; or
- publish observed IP addresses, raw target lists, raw JSONL, screenshots, or
  private browsing notes.

Cookies and challenge tokens that a browser creates transiently are not study
artifacts. They must not be exported, copied, logged, or retained.

## Interaction budget

The approved issue #32 dry-run budget per case was:

- one `check_tor` invocation against one approved target; the scanner may make
  up to three Tor attempts plus its conditional clearnet control, and its Tor
  preflight also counts as study traffic;
- one direct page load and one approved first-party public navigation in Tor
  Browser;
- one direct page load and one approved first-party public navigation in the
  ordinary clearnet browser; and
- at most one ordinary reload per primary browser when the protocol's retry
  condition is met and recorded.

Redirects and browser subresources are part of those ordinary interactions.
Do not add refresh loops, discovery scans, concurrent cases, background
monitoring, or unplanned retries. Run one case at a time.

Each reference-endpoint entry may impose a lower limit. The lower limit wins.
Any need to exceed the approved budget is a stop, not an on-the-fly exception.

## Halt conditions

Stop the affected case immediately when:

- an operator or authorized representative asks for measurement to stop or
  opts out;
- an abuse report, block notice, or other signal indicates the traffic is
  unwelcome;
- the endpoint appears unstable or measurement may be affecting service;
- a page exposes unexpected personal, confidential, or authentication data;
- the task reaches a login, form, purchase, download, CAPTCHA, or access-control
  boundary;
- a vulnerability or dangerous misconfiguration is encountered;
- the interaction budget would be exceeded;
- the approved endpoint, environment, order, storage, or protocol is not the
  one actually in use;
- a safety-impacting protocol deviation occurs; or
- the researcher cannot distinguish permitted observation from prohibited
  interaction.

Record the minimum necessary incident or deviation metadata, then follow the
incident process. Do not capture additional evidence “just in case.”

## Data classification

| Tier | Examples | Location | Publication | Default retention |
|---|---|---|---|---|
| Public governed material | Protocol, stewardship policy, public catalog, sanitized procedural note, reviewed aggregate findings | This repository | Allowed after human review | Git history |
| Private structured observations | Case identifier, endpoint identity, authorization basis, versions, exact UTC times, normalized scanner fields, rubric outcomes, concise reviewed notes, deviations | `structured/` within the approved private study-data root outside this repository | Not public by default | Through issue #33 review; delete or formally extend within 90 days after that review closes |
| Restricted transient artifacts | Raw JSONL, screenshots approved by exception, raw browser notes, session metadata, accidentally observed IP addresses | `raw/` within the approved private study-data root, outside Git | Prohibited | Delete after record audit and no later than 30 days after collection |
| Prohibited data | Credentials, exported cookies or tokens, packet captures, unrestricted traces, personal form data, unrelated private content | Must not be collected | Prohibited | Immediate deletion and incident review if encountered |

An endpoint may be public while its raw observation remains restricted. Raw
JSONL contains the target and operational detail. A screenshot can capture
identifiers, tokens, browser chrome, or unrelated state. Public origin does not
make those artifacts safe to publish.

## Data minimization

Use normalized fields and controlled vocabularies where possible. Free-form
notes should answer a required protocol question and omit page content not
needed for classification.

Screenshots and free-form raw notes are disabled by default. A screenshot may
be authorized only before collection for a specific evidentiary question that
cannot be answered by structured fields, with a defined crop/redaction plan,
restricted location, access list, and deletion date.

Do not record Tor exit IP addresses. If one appears in a terminal, browser,
log, or screenshot, do not copy it into the structured record. Treat any saved
copy as a restricted artifact and minimize it during incident handling.

## Storage, access, and retention

This study uses one private study-data root with separate `structured/` and
`raw/` directories. No live observation may start until the storage and backup
decisions below are complete.

| Decision | Approved value |
|---|---|
| Responsible person | Joseph Lorenzo Hall |
| Private study-data root | `/Users/josephhall/Library/Application Support/check_tor/issue-32` |
| Directory protection | Owner-only (`0700`) root, `structured/`, and `raw/`; outside Git and the repository |
| Access | Joseph Lorenzo Hall only, unless another person is named before collection |
| Restricted raw-artifact deletion | After the structured row is audited and no later than 30 days after collection; approved 2026-08-29 |
| Structured-observation deletion | Delete or formally extend within 90 days after the issue #33 review closes; approved 2026-08-29 |
| Backup behavior | Time Machine reports the study root as excluded; verified 2026-08-29 |

The approved root must not be publicly accessible or broadly shared. Use the
device's normal account and volume protection and owner-only file permissions.
Do not use a service that would expose the data to unapproved people or
systems.

Retain only reviewed public material in Git. Any retention extension must name
a purpose and new deletion date. When data is deleted, record the tier, date,
and locations covered without reproducing the deleted content. A missing or
unexpectedly replicated copy is an incident.

## Contact, opt-out, and abuse response

Contact Joseph Lorenzo Hall at [joehall@gmail.com](mailto:joehall@gmail.com) to
ask about the study, opt out, or report concerning traffic. This address must
be monitored during any approved collection period.

An operator request to stop does not require proof beyond a reasonable check
that the requester represents the affected service. Pause first, verify
without collecting new data, remove the endpoint from future work, and apply
the approved deletion policy to non-public observations when requested or
ethically warranted.

If traffic is reported as abusive, stop all related collection, preserve only
the minimum metadata needed to respond, and document a sanitized outcome. Do
not debate intent while measurement continues.

## Incident response

Joseph Lorenzo Hall owns the response to unexpected exposure, loss, prohibited
collection, or operational impact:

1. stop the affected measurement and any similar pending case;
2. prevent further exposure or synchronization;
3. determine what happened, what data or services were affected, and whether
   contacting an operator would reduce harm; and
4. delete prohibited or unnecessary material as soon as safely possible and
   record a sanitized outcome if the incident changes the protocol.

Do not put restricted incident detail in GitHub, public issues, commit messages,
or model prompts.

## Unexpected vulnerability or ethical/legal uncertainty

If observation unexpectedly suggests a vulnerability, stop. Do not reproduce,
exploit, vary inputs, or expand targets. Keep only the minimum private
description needed to contact the operator through an appropriate
responsible-disclosure path. Public reporting requires human review.

If the authorization or ethical or legal basis for an activity becomes
unclear, stop and seek appropriate advice before resuming. This policy does not
make a categorical IRB or legal determination.

## Publication review

The designated human reviewer must approve every public artifact. Review must
confirm that it:

- distinguishes observation, inference, hypothesis, and unknown;
- does not expose private targets, raw rows, IP addresses, or restricted
  artifacts;
- describes deliberately selected cases without implying prevalence;
- does not attribute operator intent or policy without evidence;
- treats apparent mechanisms as hypotheses unless directly established;
- considers whether naming a public endpoint creates an unwanted association;
- reports deviations and limitations; and
- complies with any operator communication or disclosure constraint.

When naming is not necessary, use anonymous case IDs or mechanism-level
descriptions. Sanitization must preserve the meaning needed to audit a claim;
if it cannot, narrow or omit the claim.

## Model-assisted work

Models may help draft public protocol text, normalize approved structured
fields, check required-field completeness, or propose competing hypotheses.
They must not receive restricted artifacts, private target lists, credentials,
cookies, tokens, raw screenshots, packet captures, observed IP addresses, or
other data not approved for that model and purpose.

Human review remains authoritative for endpoint selection, safety exceptions,
browser access classification, causal and policy claims, incidents, disclosure,
protocol changes, and publication.

## Sources

- [Menlo Report: Ethical Principles Guiding Information and Communication Technology Research](https://research.rutgers.edu/sites/default/files/2022-09/Menlo%20Report_Ethical%20Principles%20Guiding%20Info%20and%20Comm%20Tech%20Research.pdf)
- [RFC 1262: Guidelines for Internet Measurement Activities](https://www.rfc-editor.org/rfc/rfc1262.html)
- [ACM IMC 2026 submission ethics guidance](https://conferences.sigcomm.org/imc/2026/submission-instructions/)
- [Tor Project: using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [`check_tor` measurement roadmap](MEASUREMENT-VALIDATION.md)
- [Tor Access Comparison Protocol](VALIDATION-PROTOCOL.md)
- [Reference endpoint catalog](REFERENCE-ENDPOINTS.md)
