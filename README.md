# WAF Inventory

A **read-only** tool for WAF products. It finds every web app and API published through them, shows the WAF configuration that applies to each host and path, and discovers the API endpoints in use from access logs.

- **Azure WAF:** Application Gateway v2 and Front Door Standard/Premium, collected live over ARM, with traffic from Log Analytics.
- **F5 BIG-IP** (LTM + ASM / Advanced WAF): collected live over iControl REST, or offline from `bigip.conf` and ASM policy exports.
- **Output:**
  - a web dashboard
  - CSV, JSON and Excel exports
  - a self-contained HTML report
  - an OpenAPI 3.1 spec per host
  - posture findings: no WAF, detection-only mode, outdated rule sets, disabled rules, wildcard URLs, shadow/dormant APIs and more

The design and research behind it are in [`docs/PLAN.md`](docs/PLAN.md) and [`docs/plan.html`](docs/plan.html).

## Quick start (demo data, no credentials)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"

waf-inv -c examples/demo.toml collect     # load the sample Contoso estate
waf-inv -c examples/demo.toml reset-password admin   # the console needs an account (12+ characters)
waf-inv -c examples/demo.toml serve       # open http://127.0.0.1:8000 and sign in
```

The demo estate is fictitious and lives in [`examples/`](examples):
- 2 Application Gateways and 1 Front Door Premium profile
- 1 BIG-IP with 6 virtual servers and 6 ASM policies
- about 200 aggregated access-log rows
- one OpenAPI spec

## Run with Docker (production)

The image `ghcr.io/rezztor/waf-inventory` is published by [`release.yml`](.github/workflows/release.yml) for every `v*.*.*` tag (amd64 and arm64, with SBOM and a signed provenance attestation). On a Linux host with Docker:

```bash
mkdir waf-inventory && cd waf-inventory
curl -fsSLO https://raw.githubusercontent.com/Rezztor/WAF-Inventory/main/deploy/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/Rezztor/WAF-Inventory/main/deploy/install.sh
sh install.sh
```

`install.sh` creates `secrets/master_key`, asks for the admin username and password and starts the console on `https://<host>:8443`. It then prints the certificate fingerprint to compare in your browser. The password reaches the container over stdin only; just its Argon2id hash is stored. Back up `secrets/master_key` and the `waf-data` volume separately.

- **Sign-in:** every page needs it, except `/login` and `/healthz`. Sessions time out after 30 minutes idle or 12 hours. After 5 failed sign-ins, attempts are delayed, up to 15 minutes at most.
- **Forgotten password:** run `docker compose exec waf-inventory waf-inv reset-password admin` (or run `install.sh` again).
- **Upgrade:** `docker compose pull && docker compose up -d`. To pin a version, set `WAF_INV_VERSION=1.2.3`.
- **Verify an image:** `gh attestation verify oci://ghcr.io/rezztor/waf-inventory:<version> --owner Rezztor`

**Certificate from your internal CA.** The private key is generated inside the container and never leaves it:

```bash
docker compose exec -T waf-inventory waf-inv tls csr --dns waf.corp.example --ip 10.0.0.5 > waf.csr
# have the CA sign waf.csr, then install the server certificate followed by the intermediates:
cat waf.crt intermediate.pem | docker compose exec -T waf-inventory waf-inv tls install
docker compose restart
```

## Connecting real environments

**In the console** (the way to do it in the container): Sources › Add. Every type below has a form, a Test connection button that names the missing permission or wrong setting, and Run now with a live job log.
- **Azure:** the console makes the sign-in certificate. Download the `.cer`, upload it to the app registration, then test. A client secret also works.
- **F5 BIG-IP:** Fetch certificate shows the device's certificate. Compare its SHA-256 fingerprint on the BIG-IP and trust it; from then on, only that certificate is accepted.
- **Credentials** are encrypted in the database with the master key (`/run/secrets/master_key`, or the file named by `WAF_INV_MASTER_KEY_FILE`). They are never shown again; leave a field blank to keep the saved value.
- **`config.toml`:** sources found there at first start are imported once, with F5 passwords read from their environment variables. From then on, `waf-inv collect` and the console both use the sources stored in the console, and every run appears under Jobs.

**From a config file** (local use without the console):

```bash
cp config.example.toml config.toml        # edit it
export F5_DC1_PASSWORD=...                # secrets only via environment variables
waf-inv collect                           # all sources, then findings
waf-inv serve
```

| Source `type` | What it reads | Access needed |
|---|---|---|
| `azure` | ARM REST: all App Gateways, AppGW WAF policies, Front Door Std/Premium profiles (endpoints, custom domains, routes, origin groups, security policies) and Front Door WAF policies, in every listed (or visible) subscription. With `log_workspaces`, also the App Gateway and Front Door access logs, aggregated in KQL. | `DefaultAzureCredential` (managed identity, service principal env vars or `az login`) with **Reader** on the subscriptions and **Log Analytics Reader** on the workspaces |
| `azure_bundle` | The same data from a JSON file (`waf-inv collect --save-raw DIR` writes one from a live run) | none |
| `f5_rest` | iControl REST: virtual servers, pools, LTM policies (first-match by ordinal), iRules, client-SSL SNI, ASM policies with a **declarative JSON export** (1 MB chunks). If the account may not export, it falls back to REST subcollections. | BIG-IP **Auditor** account; HTTPS to the management address; `ca_cert` pins the device certificate |
| `f5_offline` | A folder with `bigip.conf` (or `tmsh list … recursive` output) and ASM policy JSON exports | none |
| `logs` | JSONL/CSV access-log rows (`host, method, path, status, content_type, user_agent, hits, first_seen, last_seen`), e.g. F5 request logs exported from a SIEM | none |

**Read-only by design:**
- Azure and the F5 inventory use only GET.
- The Log Analytics query is a read-only POST.
- The F5 ASM export is a task POST that writes a file on the device and changes no configuration.
- Query-string values are discarded on input; only parameter names are stored.

## Commands

```
waf-inv collect [--source NAME] [--save-raw DIR]   collect, run API discovery, recompute findings
waf-inv findings                                    recompute findings only
waf-inv export -f xlsx|csv|json|html|openapi [-t TABLE] [-o PATH]
waf-inv serve [--host 127.0.0.1] [--port 8000]
```

Tables: `applications`, `routes`, `policies`, `policy_settings`, `endpoints`, `findings`, `sources`. Every dashboard list also has CSV, JSON and Excel export links that keep the current filter.

## How it works

- **Effective policy.** For a host and path, the tool uses the first matching route in evaluation order:
  - App Gateway: path rule → listener → gateway policy.
  - Front Door: domain → security policy.
  - BIG-IP: LTM policy rule (`ordinal`, first-match) → iRule `ASM::enable` → the policy's virtual servers.
- **API discovery** (`discovery.py`):
  - Each path segment is typed: `{uuid}`, `{int}`, `{date}`, `{hex}`, `{email}`, and high-entropy tokens.
  - A trie per host turns a position with ≥ `collapse_threshold` distinct non-word values into `{param}`. Resource names such as `users` and `orders` stay literal.
  - `overrides` fixes templates the heuristics can't infer (e.g. usernames).
  - Endpoints with fewer than `min_hits` hits are unconfirmed.
  - Each endpoint is classified as api / web / static / ws / unknown.
- **Shadow APIs** are confirmed API endpoints that don't match the ASM allowed URLs, or don't match the OpenAPI specs listed under `discovery.openapi_specs`. **Dormant APIs** are documented operations that never appear in traffic.

## Development

```bash
pip install -e ".[test]" ruff
ruff check src tests && pytest -q
```

The tests run without network access:
- Live Azure (paging, 429 retry, Log Analytics) and live F5 REST (token auth, 503 retry, chunked ASM export, 403 fallback) run against mock HTTP servers.
- The REST and offline F5 paths are checked to produce the same inventory.

**Not yet covered:** Classic Front Door (retires March 2027), App Gateway for Containers, reading F5 logs directly over syslog, BIG-IQ, and cloud WAFs (Cloudflare, AWS WAF, Akamai, Imperva). See the roadmap in the plan.

## Licence

Copyright (C) 2026 Rezztor Technologies (Private) Limited.

WAF Inventory is free software under the GNU Affero General Public License version 3 ([LICENSE](LICENSE)). If you run a
modified version as a network service, you must offer its source to the people who use it.

Rezztor Technologies also licenses WAF Inventory commercially, without the AGPL's obligations, for organisations that
cannot meet them. Contributions are not accepted from outside (see [CONTRIBUTING.md](CONTRIBUTING.md)), so every line
can be offered under both licences.

"Rezztor" and its logo are trademarks of Rezztor Technologies (Private) Limited and are not licensed with the code:
see [TRADEMARKS.md](TRADEMARKS.md).
