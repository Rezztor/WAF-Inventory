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
waf-inv -c examples/demo.toml serve       # open http://127.0.0.1:8000
```

The demo estate is fictitious and lives in [`examples/`](examples):
- 2 Application Gateways and 1 Front Door Premium profile
- 1 BIG-IP with 6 virtual servers and 6 ASM policies
- about 200 aggregated access-log rows
- one OpenAPI spec

## Connecting real environments

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
