# Reference lab operator handoff

The lab serves fixed examples for the [TACP-0.4 reference study](../VALIDATION-REFERENCE-PACKET.md). The response definitions live in [routes.conf](routes.conf). The checked-in [nginx configuration](nginx.conf) serves them over HTTPS on loopback. nginx handles TLS and HTTP limits without a custom application or a new scanner dependency. An edge-hosted static fixture could also serve these pages if it preserves terminal HTTP 202 and the same response on both routes. The direct origin gives the operator a simpler way to verify what the service sends and can support a future, separately scoped transport lab.

| Local route | Expected response | Browser task and completion |
|---|---|---|
| `/normal` | HTTP 200 | Identify the reading room's opening hours, then follow **Read the visitor information**. |
| `/normal/complete` | HTTP 200 | Recognize that the reading room is on the ground floor. This is the normal task's first-party link destination. |
| `/accepted` | HTTP 202 with a readable page | Read that the example request was accepted and is pending. The task ends on that page. |

The accepted page represents a fixed example with no asynchronous job, redirect, form, script, cookie, or external asset. The scanner's existing classifier maps HTTP 202 to `CHALLENGE`. The local tests establish the status independently of that verdict. A future browser observation would establish whether the person could complete the task. The approved JSONL v1 instrument has no structured HTTP status or headers.

## Reproduce locally

Use nginx with the HTTP TLS module, OpenSSL, Python 3.9 or newer, and the repository's normal scanner test tools on `PATH`. From the repository root:

```sh
python3 reference-lab/test_lab.py -v
```

The suite starts nginx on a temporary loopback port, trusts a disposable certificate only in the test clients, and cleans up when it finishes. It uses the scanner's shared target probe directly so there is no Tor startup check.

For a manual HTTPS check from the repository root, use a private temporary prefix and start nginx in the foreground:

```sh
(
  set -eu
  umask 077
  lab=$(mktemp -d)
  trap 'rm -r -- "$lab"' EXIT
  cp reference-lab/nginx.conf reference-lab/routes.conf "$lab/"
  cat > "$lab/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = server
[dn]
[server]
subjectAltName = IP:127.0.0.1
EOF
  (cd "$lab" && openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 \
    -config openssl.cnf -subj '/CN=reference lab local' \
    -out tls.crt -keyout tls.key)
  nginx -p "$lab/" -c nginx.conf -e stderr -t
  printf 'Certificate for the local check: %s/tls.crt\n' "$lab"
  nginx -p "$lab/" -c nginx.conf -e stderr -g 'daemon off; master_process off;'
)
```

In a second terminal, replace the certificate path with the printed one and check `/normal`, `/normal/complete`, and `/accepted`:

```sh
curl -q --noproxy '*' --cacert /path/to/local/tls.crt \
  --max-time 5 --include https://127.0.0.1:18443/accepted
```

Stop the foreground process with Ctrl-C. Keep the disposable certificate out of the system trust store. If port 18443 is occupied, change the listener in the temporary configuration and use the same port in curl.

## Service limits

- One nginx worker with 64 connection slots, no upstreams, and no keep-alive. TLS uses versions 1.2 and 1.3 with session caching and tickets disabled. HTTPS is the only listener in the fixture.
- Header reads have a five-second deadline. nginx uses a 1 KiB initial header buffer and at most two 4 KiB large buffers. Body-bearing requests are rejected and no request body is used by a handler. The 1 KiB nginx body limit also applies where body-size checking runs.
- Only GET and HEAD are served. Unknown routes return 404. Response bodies are fixed, and each successful page is under 1 KiB. The five-second send timeout limits time between writes. Connection draining after a rejected request is limited to five seconds.
- The server serves no filesystem tree, accepts no uploads, and exposes no proxy, resolver, or admin endpoint. Access logging is disabled and nginx error logging goes to the null device. Keep only bounded service lifecycle diagnostics in the host journal. Review cloud, firewall, and platform logging separately before any live use.

## Deployment action card

The starting configuration is loopback only. The following is a proposal for a later, separately authorized deployment.

| Decision | Proposed scope |
|---|---|
| Host and budget | One disposable, dedicated Linux VM with 1 vCPU, 1 GiB memory, a 25 GiB boot disk, and its bundled public address. As an example checked on 2026-11-13, DigitalOcean lists its regular 1 GiB Basic plan at about US$0.00893/hour or US$6/month with a listed 1,000 GiB monthly transfer allowance. Refresh the region, available plan, prorated transfer allowance, taxes, and all line items before purchase. Use no paid backup, snapshot, extra volume, or reserved IP for the baseline. Approve the spending cap and destruction date separately. [Plan pricing](https://www.digitalocean.com/pricing/droplets) · [Billing and transfer rules](https://docs.digitalocean.com/products/droplets/details/pricing/) |
| Public and private access | Approve one dedicated hostname and its address records, with TCP 443 open to the public so Tor exits can reach the service. Use a dedicated private management path or provider console. Keep public SSH and unrelated ports closed. Publish an AAAA record only if IPv6 reachability and firewall rules are verified. Avoid shared production hostnames, credentials, target lists, and routes into unrelated private networks. |
| TLS and maintenance | Approve the DNS and certificate actions for the dedicated hostname. DNS-01 can keep port 80 closed. Use a narrowly scoped credential for the validation record, preferably held off the web host. Record certificate expiry, renewal owner and schedule, and the certificate reload procedure. [ACME challenge types](https://letsencrypt.org/docs/challenge-types/) |
| Traffic accounting | For R02, allow at most one scanner invocation, one Tor verification request, up to three Tor target attempts and one conditional direct probe, and two browser loads plus up to two qualifying reloads total. Navigation is absent. Record redirects, browser auxiliary requests, and any lower endpoint limit at readiness. Budget admin traffic, OS updates, DNS and certificate validation, and any approved smoke checks separately from analytic cases. Review transfer from provider aggregates without retaining visitor IP addresses or request logs. |
| Cleanup | Schedule closure of public access, DNS cleanup, credential retirement, and destruction of the VM and any attached billable resource. Powering off a bundled VM keeps compute billing active. Verify that the provider shows the resources deleted. [Billing rules](https://docs.digitalocean.com/products/droplets/details/pricing/#bundled-cpu-droplet-billing) |

### Rebuild and verify after authorization

1. Record the approved source commit, OS image, nginx package/version, hostname, approved address families, resource IDs, certificate method, and maintenance owner. Use a security-maintained nginx package with TLS support. Review the lab tests again after package or configuration updates. Install the two configuration files from that commit.
2. Prepare a dedicated unprivileged service account and a private writable runtime prefix, such as `/var/lib/check-tor-reference-lab`. Keep configuration and certificates in a separate root-owned directory such as `/etc/check-tor-reference-lab`. Give the service account read access to the key through a dedicated group and file mode `0640`. For the deployment copy, change `listen` to port 443 on the approved addresses, set the exact `server_name`, and use absolute paths for the certificate and key. Keep `routes.conf` alongside `nginx.conf`. Preserve the request and logging limits.
3. Configure the dedicated systemd service to run `/usr/sbin/nginx -p /var/lib/check-tor-reference-lab/ -c /etc/check-tor-reference-lab/nginx.conf -e stderr -g 'daemon off;'` as the dedicated user. Use only `CAP_NET_BIND_SERVICE` to bind 443 and keep the same flags with `-t` for the pre-start check. Bound the service with an initial 128 MiB memory limit, 32 tasks, and 256 open files, and limit retained host journal size. Check the actual package paths and run `nginx -t` before start or reload. Renew by staging the new pair with the same permissions, validating, and reloading the service.
4. Before enabling public access, verify the effective nginx configuration, TLS chain, exact routes, no default service or unexpected listeners, firewall scope, request and resource limits, and private administration. Check the service restarts after reboot. Separately authorized smoke checks can establish public TLS and expected status and body from the approved routes, including reachability from Tor exits. Record the exact destinations, budget, and review result. Any unexpected status, edge behavior, public admin access, or resource use stops qualification.
5. On failure, close public ingress first. Restore the last reviewed files and certificate, validate, restart, and recheck under the approved budget. At retirement, close ingress, stop and disable the service, remove the DNS records, retire the dedicated key and any renewal credential, and destroy the VM and any associated resources. Record the teardown date and billing check. Keep the reviewed source and sanitized operator notes for rebuild.

## Qualification handoff for issue #41

The local routes are constructed fixtures. `/accepted` supplies the intended R02 `REF-202` behavior once a specific deployed endpoint is reviewed. The lab's normal route is a separate candidate. The first-batch proposal currently names `HTTPBIN-LINKS-2` for R01.

Provide #41 with the exact approved HTTPS URL and catalog ID, source and deployment configuration revisions, independently checked terminal status and visible completion criteria, operator authority and contact, verification date, redirect and resource review, lower traffic limits, and retirement conditions. Record any publication sensitivity and deployment or eligibility traffic approval in the readiness manifest. Live collection follows the separate #42 decision. [Readiness issue #41](https://github.com/josephlhall/check_tor/issues/41) · [Collection issue #42](https://github.com/josephlhall/check_tor/issues/42) · [Stewardship policy](../ETHICS-AND-DATA-STEWARDSHIP.md)
