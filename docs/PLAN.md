# WAF Inventory & API Discovery: Plan

> Status: **MVP built (phases 0–5)**, see [§0](#0-implementation-status) · Last updated: 2026-10-24 · HTML version: [`docs/plan.html`](plan.html)

## Contents
0. [Implementation status](#0-implementation-status)
1. [Goal & scope](#1-goal--scope)
2. [Architecture](#2-architecture)
3. [Vendor-neutral data model](#3-vendor-neutral-data-model)
4. [Azure WAF connector](#4-azure-waf-connector)
5. [F5 BIG-IP connector](#5-f5-big-ip-connector)
6. [API discovery engine](#6-api-discovery-engine)
7. [Findings](#7-findings)
8. [Dashboard & exports](#8-dashboard--exports)
9. [Roadmap](#9-roadmap)
10. [Prerequisites checklist](#10-prerequisites-checklist)
11. [Risks & open questions](#11-risks--open-questions)
12. [Sources](#12-sources)

---

## 0. Implementation status

| Phase | Status | Where |
|---|---|---|
| 0: skeleton, data model, CLI, SQLite, fixtures | Done | `src/waf_inventory/models.py`, `cli.py`, `examples/` |
| 1: Azure config (App Gateway v2 + Front Door Std/Premium, effective policy) | Done | `azure.py` |
| 2: F5 REST + offline (`bigip.conf` / tmsh + ASM declarative export) | Done | `f5.py` |
| 3: Log Analytics traffic → discovery → OpenAPI | Done | `azure.py` (KQL), `discovery.py` |
| 4: Dashboard + exports (HTML / JSON / CSV / XLSX / OpenAPI) | Done | `web.py`, `report.py`, `templates/` |
| 5: Findings | Done | `findings.py` |
| 5: Snapshot diffing | **Not yet.** Every policy stores `raw` + `raw_hash` so a diff can be added later | |
| 6: F5 log ingestion over syslog, BIG-IQ, classic Front Door, App Gateway for Containers, cloud WAFs | Not started. F5 logs can already be loaded as JSONL/CSV via the `logs` source | |

**Where the build differs from the plan below, and why:**
- **Azure SDKs replaced by plain ARM REST calls** (`httpx` + `azure-identity`), with api-versions pinned in `azure.API`.
  - This avoids five management SDKs.
  - Live collection produces exactly the ARM JSON that the offline `azure_bundle` source and the tests use.
  - The App Gateway, WAF policy and Front Door resources come from per-subscription list calls rather than Resource Graph. This is simpler, and Resource Graph doesn't index the Front Door child resources anyway.
- **`argparse`** instead of Typer, and **server-rendered Jinja pages without HTMX**: plain GET forms do the filtering.
- **Normalized policy settings are stored as a JSON column on `WafPolicy`** rather than a `PolicySetting` table. The `policy_settings` export still flattens them to one row per setting.
- **Applications** are derived from listener hostnames (or address:port) instead of a separate table.
- **Effective policy** is the first matching route in evaluation order, with F5 LTM policy rules sorted by `ordinal` (first-match strategy).
- **Log Analytics workspaces** are listed in the config (`log_workspaces`), not auto-discovered from diagnostic settings.
- **Not verified against live tenants or devices.** All live code paths are tested against mock ARM, Log Analytics and iControl REST servers that follow the documented shapes. Before relying on the results, run the first live collection with `--save-raw` and review it.

## 1. Goal & scope

This is a **read-only** tool. It connects to WAF products and inventories every web app and API published through them. For each app it answers three questions:

| Question | What we capture |
|---|---|
| **What is published?** | Hostnames/FQDNs, listeners and virtual servers (IP:port, TLS/SNI), URL path routes, backends and origins |
| **How is the WAF configured for it?** | Mode (detect/block), managed rule sets and versions, disabled rules and overrides, exclusions, custom, rate-limit, geo and IP rules, request size and file limits, bot protection, allowed URLs, methods, file types and parameters. Each is resolved to the **effective policy per host and path**. |
| **Which APIs are actually used?** | API endpoints found in traffic logs: `method + host + path template`, first and last seen, hit count, status codes, content types, query parameter names. Exported as **OpenAPI**. |

**Phase 1 vendors:**
- **Azure WAF:** Application Gateway v2 and Front Door Standard/Premium. Classic Front Door gets basic support only, because it retires on 31 Mar 2027.
- **F5 BIG-IP on-prem:** LTM plus ASM / Advanced WAF, read over iControl REST (live) **or** from offline config files.

**Later:** Cloudflare, AWS WAF, Akamai and Imperva, added through the same connector interface.

**Decisions made:**
- F5 is collected both live (REST) and offline (config files).
- Traffic logs come from **Azure Log Analytics**. F5 logs are not centralised yet; see §5.6.
- The MVP is a **web dashboard** with export to **HTML, JSON, CSV and Excel**.

---

## 2. Architecture

```
 Connectors (read-only)                        Core                               UI / Output
 ┌───────────────────────────────┐
 │ azure_config  ARG + ARM SDKs  │──┐
 │ azure_logs    Log Analytics   │──┤   ┌───────────────┐   ┌──────────────┐   ┌──────────────────────────┐
 │ f5_rest       iControl REST   │──┼──▶│ normalize      │──▶│ SQLite       │──▶│ FastAPI + Jinja2 + HTMX  │
 │ f5_offline    bigip.conf/ASM  │──┤   │ (pydantic)     │   │ (Postgres-   │   │ dashboard                │
 │ (later) f5_logs, cloudflare,  │──┘   │ discovery eng. │   │  ready)      │   │ exports: HTML/JSON/CSV/  │
 │ aws_waf, akamai, imperva      │      │ findings eng.  │   └──────────────┘   │ XLSX/OpenAPI             │
 └───────────────────────────────┘      └───────────────┘                      └──────────────────────────┘
```

**Stack**
- Python 3.12 and pydantic v2.
- SQLAlchemy 2 on SQLite, with a schema kept portable to Postgres.
- FastAPI + Jinja2 + HTMX. The dashboard is server-rendered, so there is no SPA build step.
- Typer CLI: `waf-inv collect | discover | serve | export`.
- Azure: `azure-identity`, `azure-mgmt-resourcegraph`, `azure-mgmt-network`, `azure-mgmt-cdn`, `azure-mgmt-frontdoor`, `azure-monitor-query`.
- F5: plain `httpx` behind a thin wrapper. `f5-sdk` and `bigrest` are not used because both are unmaintained.
- Excel output: `openpyxl`. CSV and JSON use the standard library.

**Connector contract**
- Each connector implements one small `Protocol`:
  - `collect_config() -> Snapshot` returns the inventory and policies.
  - `iter_traffic(since) -> Iterable[HttpObservation]` is optional and only for log sources.
- Connectors are registered in a plain dict. Entry-point plugins can wait until a third vendor arrives.

**Security of the tool itself**
- Read-only by construction. The HTTP layer allows only GET, plus the F5 export-policy task POST. That POST creates a file and does not change config.
- Azure authenticates with `DefaultAzureCredential` (managed identity or service principal). F5 credentials come from env/.env or Key Vault. Secrets are never written to the DB or to reports.
- Query-string **values are redacted**; only parameter names are stored, because URLs often carry tokens.
- F5 self-signed management certs are pinned by fingerprint or CA. TLS verification is never turned off.

---

## 3. Vendor-neutral data model

```
Source        (id, kind[azure|f5_rest|f5_offline|…], name, last_sync, status)
Gateway       (id, source_id, vendor, kind[appgw|afd|afd_classic|bigip], native_id, region, version, ha_group)
Application   (id, fqdn, aliases[], env, owner)                         -- key = normalized FQDN
Listener      (id, gateway_id, protocol, ip, port, hostnames[], tls_cert, native_id)   -- AppGW listener / AFD domain / F5 virtual server
Route         (id, listener_id, path_pattern, match_type, backend_id, policy_id)       -- path rule / AFD route / LTM policy rule / iRule
Backend       (id, gateway_id, members[], protocol, port)                               -- backend pool / origin group / F5 pool
WafPolicy     (id, gateway_id, native_id, name, vendor, raw_json, raw_hash, fetched_at)
PolicySetting (policy_id, scope[gateway|listener|path], category, key, value_json)
     category ∈ mode, rulesets, disabled_rules, exclusions, custom_rules, rate_limit, geo,
                ip_lists, size_limits, bot, allowed_urls, allowed_methods, filetypes, parameters, tls
ApiEndpoint   (id, app_id, method, path_template, kind[api|web|static|ws|unknown], confidence,
               first_seen, last_seen, hits, status_counts{}, content_types[], query_params[])
EndpointObservation (app_id, method, template_id, day, hits, status_counts)    -- daily rollup
Finding       (id, rule_id, severity, subject_type, subject_id, evidence_json, state, first_seen, last_seen)
```

- **Raw vendor JSON and its hash** are stored on every snapshot. This lets us diff policy versions over time and re-normalize later without calling the vendor again.
- **Effective policy** is computed for each (listener, route) pair, so every host and path shows exactly which settings apply to it.
- **Logs are stored as daily aggregates**, never as raw lines. That keeps storage cheap and avoids holding personal data.
- **Findings are idempotent**: the key is `(rule_id, subject)`, so a finding can be suppressed and later reopened.
- No standard WAF-policy schema exists. The `PolicySetting` categories above are our own normalization. For log ingestion, OCSF *HTTP Activity* (class 4002) or ECS `http.*`/`url.*` is a reasonable shape.

---

## 4. Azure WAF connector

### 4.1 Enumeration with Azure Resource Graph (all subscriptions in the tenant)

ARG indexes Application Gateways, both WAF policy types, Front Door classic, `cdn/profiles` and `afdEndpoints`. It does **not** index AFD routes, custom domains, origin groups, rule sets or security policies. Those are fetched per profile through the SDK.

```kusto
// App Gateway listeners + policy at gateway and listener level
resources
| where type =~ 'microsoft.network/applicationgateways'
| extend gwPolicy = tostring(properties.firewallPolicy.id), sku = tostring(properties.sku.tier)
| mv-expand limit 2000 l = properties.httpListeners
| project subscriptionId, resourceGroup, gw = name, sku, gwPolicy,
    listener = tostring(l.name), protocol = tostring(l.properties.protocol),
    hostNames = iff(isnotempty(l.properties.hostNames), l.properties.hostNames, pack_array(l.properties.hostName)),
    listenerPolicy = tostring(l.properties.firewallPolicy.id)
```
```kusto
// App Gateway path rules (per-URI policy)
resources
| where type =~ 'microsoft.network/applicationgateways'
| mv-expand limit 2000 m = properties.urlPathMaps
| mv-expand limit 2000 r = m.properties.pathRules
| project gw = name, pathMap = tostring(m.name), rule = tostring(r.name), paths = r.properties.paths,
    pool = tostring(r.properties.backendAddressPool.id), pathPolicy = tostring(r.properties.firewallPolicy.id)
```
```kusto
// All WAF policies (both flavours) + Front Door profiles/endpoints
resources
| where type in~ ('microsoft.network/applicationgatewaywebapplicationfirewallpolicies',
                  'microsoft.network/frontdoorwebapplicationfirewallpolicies',
                  'microsoft.cdn/profiles', 'microsoft.cdn/profiles/afdendpoints', 'microsoft.network/frontdoors')
| project id, type, name, subscriptionId, sku, mode = tostring(properties.policySettings.mode),
    ruleSets = properties.managedRules.managedRuleSets, customRules = properties.customRules
```

**ARG limits:**
- Pages are 1,000 rows; follow `skip_token`.
- Throttling allows 15 queries per 5 s; honour the `x-ms-user-quota-*` headers.
- Each `mv-expand` is capped at 2,000 rows.
- Scope is one tenant per credential.
- ARG is eventually consistent, so the final policy read is an ARM GET.

### 4.2 Authoritative detail (Python SDK)

| Area | Package (default api-version) | Calls |
|---|---|---|
| App Gateway + WAF policy | `azure-mgmt-network` (2026-03-01) | `application_gateways.list_all()`, `web_application_firewall_policies.list_all()`, `application_gateways.list_available_waf_rule_sets()` |
| Front Door Std/Premium | `azure-mgmt-cdn` (2025-12-01) | `profiles.list()`, `afd_endpoints.list_by_profile`, `routes.list_by_endpoint`, `afd_custom_domains.list_by_profile`, `afd_origin_groups/afd_origins`, `rule_sets/rules`, **`security_policies.list_by_profile`** |
| AFD WAF policy | `azure-mgmt-frontdoor` (2025-10-01) | `policies.list_by_subscription()`, `managed_rule_sets.list()`, classic: `front_doors.list()` |
| Logs | `azure-monitor-query` | `LogsQueryClient.query_workspace` / `query_resource` |
| Diagnostic settings | `azure-mgmt-monitor` | `diagnostic_settings.list(resource_uri)` shows which workspace holds each resource's logs |

### 4.3 Resolving the effective policy

- **App Gateway:**
  - A policy can be attached at three levels: the gateway (global), a listener (per site) or a path rule (per URI).
  - The most specific one wins: **path rule → listener → gateway**.
  - Cross-check against the policy's back-links (`applicationGateways[]`, `httpListeners[]`, `pathBasedRules[]`).
  - Old gateways may still carry the legacy `webApplicationFirewallConfiguration`; report and flag it.
  - **L4 TLS/TCP listeners are not WAF-inspected.**
- **Front Door Std/Premium:**
  - The WAF follows **domains**, not routes. Resolve `route → customDomain (or default *.azurefd.net) → securityPolicy.associations → WAF policy`.
  - A domain with no security policy is **unprotected**.
  - The WAF policy also has back-links in `securityPolicyLinks[]`.
- Policies may live in another subscription or resource group. Resolve each one by its full ID and flag any we cannot reach.

### 4.4 WAF settings captured

| Setting | App Gateway WAF policy | Front Door WAF policy |
|---|---|---|
| Mode and state | `policySettings.mode` (Detection/Prevention), `state` | `policySettings.mode`, `enabledState` |
| Body and size | `requestBodyCheck`, `requestBodyInspectLimitInKB`, `maxRequestBodySizeInKb`, `requestBodyEnforcement`, `fileUploadLimitInMb`, `fileUploadEnforcement` | `requestBodyCheck` |
| Managed rules | `managedRules.managedRuleSets[]` (type and version: DRS 2.2/2.1, OWASP CRS 3.x, Microsoft_BotManagerRuleSet), `ruleGroupOverrides`, read-only **`computedDisabledRules`** | `managedRuleSets[]` (DRS 2.x, BotManager 1.0/1.1; Premium only), `ruleSetAction`, `ruleGroupOverrides` |
| Exclusions | `managedRules.exclusions[]` | exclusions at rule-set, rule-group or rule level |
| Custom rules | `customRules[]` (MatchRule/RateLimitRule, `rateLimitThreshold`/`Duration`, `groupByUserSession`, IPMatch/GeoMatch conditions, action) | `customRules.rules[]` (same, plus `groupBy` and Premium grouping by country/ASN/JA4) |
| Other | `customBlockResponse*`, `logScrubbing`, JS challenge/CAPTCHA expiry | `redirectUrl`, `customBlockResponse*`, `logScrubbing` |

Caveats on interpreting these settings:
- DRS 2.x and CRS 3.x use **anomaly scoring**, so a "Matched" log line is not a block.
- **Detection mode is reported as unprotected.**
- Changing the AFD rule-set version resets its overrides.

### 4.5 Traffic and API discovery from Log Analytics

| Source | Category | Table | Useful columns |
|---|---|---|---|
| App Gateway | `ApplicationGatewayAccessLog` | `AGWAccessLogs` (or `AzureDiagnostics`) | Host, OriginalHost, RequestUri, HttpMethod, HttpStatus, **ContentType**, UserAgent, ClientIp, ListenerName, RuleName, BackendPoolName, WafPolicyId, WAFMode, TransactionId |
| App Gateway | `ApplicationGatewayFirewallLog` | `AGWFirewallLogs` | RequestUri, Hostname, RuleSetType/Version, RuleId, Action, Message, PolicyScope, TransactionId |
| AFD Std/Premium | `FrontDoorAccessLog` | `AzureDiagnostics` (`ResourceProvider == "MICROSOFT.CDN"`) | hostName_s, requestUri_s, httpMethod_s, httpStatusCode_s, userAgent_s, endpoint_s, originName_s, trackingReference_s |
| AFD Std/Premium | `FrontDoorWebApplicationFirewallLog` | `AzureDiagnostics` | host_s, requestUri_s, ruleName_s, action_s, policy_s, policyMode_s, trackingReference_s |

Run `getschema` on the live workspace before hard-coding column names. The firewall logs are joined to the access logs on `TransactionId` (App Gateway) or `TrackingReference` (AFD).

```kusto
// App Gateway: aggregate server-side, never pull raw rows
AGWAccessLogs
| where TimeGenerated > ago(30d)
| extend path = tostring(split(RequestUri, "?")[0])
| summarize hits = count(), statuses = make_set(HttpStatus, 20), ctypes = make_set(ContentType, 5),
            qparams = make_set(extract_all(@"[?&]([^=&]+)=", RequestUri), 20),
            firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated)
    by Host, HttpMethod, path, ListenerName, RuleName, _ResourceId, day = bin(TimeGenerated, 1d)
```
```kusto
// Front Door Std/Premium
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CDN" and Category == "FrontDoorAccessLog" and TimeGenerated > ago(30d)
| extend path = tostring(parse_url(requestUri_s).Path)
| summarize hits = count(), statuses = make_set(httpStatusCode_s, 20)
    by host = hostName_s, method = httpMethod_s, path, endpoint_s, day = bin(TimeGenerated, 1d)
```

Limits of log-based discovery:
- **Request and response bodies are never logged**, so we get endpoints but no JSON schemas or GraphQL operation names.
- Only endpoints that received traffic within the retention window are visible. The default is 30 days; 90 is recommended.
- Long time ranges are split into chunks and aggregated in KQL, to stay inside result size limits.
- Native Azure features do not fill this gap. Defender for APIs only covers APIs in **API Management**, and Defender CSPM API posture only covers Functions and Logic Apps. Neither discovers APIs from App Gateway or AFD traffic. They are useful only to import OpenAPI specs from APIM, to enrich our results.

### 4.6 Access needed
- **Reader** at management-group or subscription scope, for ARG and every config GET.
- **Log Analytics Reader** on each workspace.
- Authentication through `DefaultAzureCredential`. Use one credential per tenant, or Azure Lighthouse.

---

## 5. F5 BIG-IP connector

### 5.1 Authentication and safe use of iControl REST
- `POST /mgmt/shared/authn/login {"username","password","loginProviderName":"tmos"}` returns a token, sent as the `X-F5-Auth-Token` header.
  - Tokens last 1,200 s; extend with PATCH up to 36,000 s.
  - There is a limit of 100 tokens per user. Reuse one token per run and DELETE it at the end.
- **Role:** a dedicated **Auditor** account (read-only on all config) with access to all partitions.
  - The Guest role often returns 401 on REST.
  - There is no built-in ASM-only read-only role.
- restjavad is a single, fragile JVM. Keep **at most 2–4 concurrent requests** and back off on 503.
- Self-signed management certificates: pin by fingerprint or CA.

### 5.2 Inventory endpoints (LTM)

| Purpose | Endpoint |
|---|---|
| Identity and modules | `/mgmt/tm/sys/version`, `/mgmt/tm/sys/global-settings`, `/mgmt/tm/sys/provision` (is ASM/AFM/AVR provisioned?), `/mgmt/toc` |
| HA | `/mgmt/tm/cm/device`, `/mgmt/tm/cm/device-group` (sync-failover; ASM sync flag), `/mgmt/tm/cm/sync-status`. Collect once per sync group. If ASM sync is off, collect ASM from every member. |
| Partitions and route domains | `/mgmt/tm/auth/partition`, `/mgmt/tm/net/route-domain`. A destination such as `/Common/10.1.1.1%2:443` means route domain 2. |
| Virtual servers | `/mgmt/tm/ltm/virtual?expandSubcollections=true`: destination, pool, `rules[]`, profiles (including `websecurity`, which means ASM is attached; also bot-defense, DoS, http, client-ssl), `policiesReference`, `securityLogProfiles[]` |
| Pools | `/mgmt/tm/ltm/pool?expandSubcollections=true` |
| LTM policies | `/mgmt/tm/ltm/policy?expandSubcollections=true`: conditions `httpHost`/`httpUri` and actions `asm enable policy …`, `forward pool`. Ignore `/Common/Drafts`. |
| iRules | `/mgmt/tm/ltm/rule`: scan for `ASM::enable/disable`, `HTTP::host`, `HTTP::uri` and `pool` |
| TLS/SNI | `/mgmt/tm/ltm/profile/client-ssl` (`serverName`, `sniDefault`, `certKeyChain`), `/mgmt/tm/sys/file/ssl-cert` (CN/SAN and expiry) |
| Security profiles | `/mgmt/tm/security/bot-defense/profile` (14.1+), `/mgmt/tm/security/dos/profile`, `/mgmt/tm/security/log/profile` |
| AS3 (if installed) | `/mgmt/shared/appsvcs/info`, then `GET /mgmt/shared/appsvcs/declare`. This only covers AS3-managed apps, so it does not replace the `/mgmt/tm` sweep. |

Use OData `$select`, `$filter`, `$top` and `$skip` for paging. `expandSubcollections` is **ignored** on `/mgmt/tm/asm/policies`.

### 5.3 WAF configuration (ASM / Advanced WAF)
"Advanced WAF" is the licence name. The module is still `asm`, and every endpoint is under `/mgmt/tm/asm/...`.

```
# 1. List policies
GET  /mgmt/tm/asm/policies?$select=id,name,fullPath,virtualServers,manualVirtualServers,
       enforcementMode,active,type,parentPolicyName,applicationLanguage,versionDatetime

# 2. Export each policy as declarative JSON (TMOS 15.1+)
POST /mgmt/tm/asm/tasks/export-policy
     {"filename":"<id>.json","format":"json","minimal":false,
      "policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/<id>"}}
GET  /mgmt/tm/asm/tasks/export-policy/<taskId>        # poll until COMPLETED
GET  /mgmt/tm/asm/file-transfer/downloads/<id>.json   # 1 MB chunks via Content-Range
```

1. **List policies** with `$select` to get enforcement mode, attached virtual servers, active flag and parent policy.
2. **Export each policy as declarative JSON.** This is the best machine-readable source.
   - `minimal:false` returns the effective values, not just the differences from the template.
   - Downloads larger than **1,048,576 bytes are truncated** unless fetched in chunks. Validate the JSON after joining the chunks.
3. **Fallback**, if Auditor cannot run the export task: GET the subcollections under `/mgmt/tm/asm/policies/<id>/`: `urls`, `parameters`, `filetypes`, `methods`, `headers`, `cookies`, `host-names`, `signature-sets`, `blocking-settings/violations`, `blocking-settings/evasions`, `blocking-settings/http-protocols`, `whitelist-ips`, `geolocation-enforcement`, `data-guard`, `brute-force-attack-preventions`, `json-profiles`, `xml-profiles`, `policy-builder`, `open-api-files`. Always page `signatures` and `suggestions`.

**Settings normalized from the export:**
- Enforcement mode (transparent or blocking), and whether the policy is active.
- Signature sets, plus the signatures still **in staging**.
- Learning mode.
- Allowed URLs, including the `*` wildcard; allowed methods; file types; parameters; headers and cookies.
- Violations and their blocking flags (alarm/block).
- Evasions and HTTP-protocol checks.
- Data guard, brute force, IP whitelist, geolocation, IP intelligence.
- JSON/XML profiles and imported OpenAPI files.
- Bot-defense and DoS profiles, from the virtual server.
- Parent/child inheritance (the child export holds the effective settings).

### 5.4 Mapping a policy to an app (host and path)
Three sources are combined:
1. The policy's `virtualServers[]`.
2. LTM policy rules on the virtual server, whose **`httpHost`/`httpUri` conditions** decide which ASM policy applies to which host or path. One virtual server can carry several ASM policies.
3. iRules that call `ASM::enable <policy>` or `ASM::disable`.

The `websecurity` profile on a virtual server confirms ASM is in the traffic path. Hostnames come from the LTM policy conditions, the client-ssl SNI and the certificate SAN.

### 5.5 Offline mode (no REST access)
- **Inputs:**
  - `bigip.conf` / `bigip_base.conf`, or `tmsh -q -c "cd /; list ltm virtual recursive all-properties"` output (also for pool, policy, rule and profile client-ssl).
  - **ASM policy exports** in JSON or XML.
  - UCS or qkview archives, which are unpacked to read `/config/bigip*.conf`.
- **Parser:** brace-depth tokenizer, because blocks nest. It produces the same `Snapshot` as the REST connector.
- `bigip.conf` only holds an ASM *stub*, not the policy content. The full WAF detail needs the policy exports.

### 5.6 API discovery from F5
| Option | Requires change on BIG-IP? | Notes |
|---|---|---|
| ASM learned entities (`urls`, `parameters`, `suggestions`) | No | Read-only. Shows which URLs ASM has learned, as explicit or wildcard entries. |
| ASM local request log `GET /mgmt/tm/asm/events/requests` | No | About 3M records, usually illegal requests only, slow at scale. Gives a sample only. |
| AVR analytics (if provisioned) | No | Per-URL statistics. |
| **ASM remote logging, "all requests"** (key-value/CEF to syslog/SIEM) | **Yes** (log profile) | Recommended v2 path. Fields include method, uri, query_string, response_code, vs_name, policy_name and the request headers (truncated). |
| LTM Request Logging profile (HSL) | Yes | Covers virtual servers without ASM. Cheap. |
| Telemetry Streaming → Kafka/Splunk/HTTP | Yes (iLX extension) | Sends to a central sink. It could also go into Log Analytics so it reuses the Azure discovery path. |

F5 Distributed Cloud "API Discovery for BIG-IP" and F5 API Security Local Edition are commercial equivalents. They are useful as a benchmark for our output.

---

## 6. API discovery engine

The same engine runs on both Azure and F5 traffic.

1. **Normalize**
   - Lowercase the host and strip the port.
   - Split off the query string; keep the sorted **parameter names** only.
   - Percent-decode, strip `;jsessionid=`, and collapse `//` and trailing `/`.
2. **Typed segment masks**, applied per segment in this order:

| Mask | Pattern |
|---|---|
| `{uuid}` | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` |
| `{int}` | `^\d+$` |
| `{hex}` | `^[0-9a-f]{16,}$` (ObjectId, MD5, SHA) |
| `{date}` | `^\d{4}-\d{2}-\d{2}`, `^\d{8}$` |
| `{email}` | `^[^@/]+@[^@/]+\.[a-z]{2,}$` |
| `{b64}` | `^[A-Za-z0-9_-]{22,}={0,2}$` with mixed case and digits |
| `{token}` | Shannon entropy ≥ 3.5 bits/char and length ≥ 12 |

   `v1`, `v2.1`, `api`, `rest` and similar segments stay literal.

3. **Cardinality collapse.** Build a trie per (host, method).
   - When a node has **≥ 10 distinct literal children** that are not dictionary words and whose subtrees look alike, collapse them into `{param}`.
   - Name the parameter from the parent segment, e.g. `/users/{user_id}`.
   - Never collapse words such as `login`, `search` or `logout`.
4. **Evidence floor.** A template needs **at least 5 hits** to be promoted; anything below that stays *unconfirmed*. The threshold is configurable. For comparison, Cloudflare uses 500 hits in 10 days.
5. **Classify** each endpoint as `api`, `web`, `static`, `ws` or `unknown`, with a confidence value:

| Class | Signals |
|---|---|
| `api`, strong | JSON/XML/grpc content type, or `/api`, `/rest`, `/v\d+`, `/graphql`, `/odata`, `.asmx`, `.svc`, `?wsdl` |
| `api`, medium | POST, PUT, PATCH or DELETE; `api.*` host; non-browser user agent (okhttp, axios, python-requests) |
| `static` | Asset extensions (js, css, png, …) or `/static`, `/assets` |
| `ws` | Status 101, or `/ws`, `/socket.io`, `/signalr` |
| `web` | GET with `text/html` and a browser user agent |
| `unknown` | Shown in the UI with a per-host override |

6. **User overrides.** Users can force a segment literal or parametrized, rename a parameter, or merge or split templates. Overrides are stored as rules and **re-applied on every run** so results stay stable. This follows the mitmproxy2swagger and Akto merge/de-merge pattern.
7. **OpenAPI 3.1 export per host.**
   - Covers paths, methods, typed path parameters, observed status codes and query parameter names.
   - Each operation gets `x-discovered`, `x-first-seen`, `x-last-seen` and `x-hit-count`.
   - **No body schemas**, because logs carry no bodies.

---

## 7. Findings

| Rule | Severity | Source |
|---|---|---|
| Host or domain published with **no WAF policy**: AFD domain without a security policy, virtual server without ASM, App Gateway listener with no effective policy | High | Config |
| Policy in **Detection/transparent** mode, or disabled | High | Config |
| L4 TLS/TCP listener in front of HTTP apps (not WAF-inspected) | Medium | Config |
| Outdated managed rule set (e.g. CRS 3.0/3.1), or no bot rule set | Medium | Config |
| Disabled rules, broad exclusions, signatures still in staging | Medium | Config |
| ASM allowed URLs still `*` wildcard (URL enforcement off) | Medium | Config |
| Request body inspection off, or very large size limits | Medium | Config |
| **Shadow API**: observed endpoint not in the WAF allowed URLs or the imported or APIM OpenAPI | High | Logs + Config |
| **Dormant/zombie API**: declared but not seen in 90 days | Low | Logs + Config |
| TLS certificate expiring within 30 days | Medium | Config |
| Legacy config: classic Front Door, App Gateway `webApplicationFirewallConfiguration` | Low | Config |

---

## 8. Dashboard & exports

**Pages**
- **Overview:** number of apps, gateways, policies and endpoints; WAF coverage %; findings by severity; mode breakdown.
- **Applications:** one row per FQDN. Drill-down: listeners → routes → **effective WAF policy and settings** → discovered endpoints → findings.
- **WAF Policies:** normalized settings side by side, a raw JSON viewer, and a **diff** between snapshots or between two policies.
- **API Endpoints:** filter by host, kind, method and last seen. Shows the template, hits, statuses and query parameters. Includes the override editor.
- **Findings:** filter by severity and state, with suppression.
- **Sources / Runs:** connector configuration (without secrets), run history and errors.

**Exports**, available from every list:
- **CSV** and **JSON** for the current filter.
- **Excel (.xlsx)** with one sheet per entity: Applications, Routes, Policies, PolicySettings, Endpoints, Findings.
- A **self-contained HTML report** of the full inventory, for audit or email.
- **OpenAPI 3.1** per host.

---

## 9. Roadmap

| Phase | Scope | Outcome |
|---|---|---|
| **0** | Repo skeleton, data model, Typer CLI, SQLite, recorded sample fixtures (Azure JSON, F5 REST JSON, bigip.conf) | `waf-inv` runs end-to-end on fixtures |
| **1** | Azure config connector (ARG + ARM; App Gateway + AFD; effective policy) | Azure app and WAF inventory |
| **2** | F5 REST connector + offline (`bigip.conf` + ASM export) connector | BIG-IP app and WAF inventory |
| **3** | Azure Log Analytics traffic → discovery engine → OpenAPI | API endpoint inventory |
| **4** | Dashboard (FastAPI + HTMX) + exports (HTML/JSON/CSV/XLSX) | Usable UI |
| **5** | Findings engine + snapshot diffing | Posture and shadow-API report |
| **6** | F5 log ingestion (after the logging change) + Cloudflare, AWS WAF, Akamai, Imperva | Wider coverage |

Each phase ends with fixture-based tests. Connectors are tested against recorded JSON, so CI needs no live credentials.

---

## 10. Prerequisites checklist

**Azure**
- [ ] Service principal or managed identity with **Reader** on the management group(s) or subscriptions.
- [ ] **Log Analytics Reader** on the workspaces.
- [ ] Diagnostic settings on every App Gateway and Front Door profile sending the **access + WAF logs** to Log Analytics. Resource-specific tables are preferred.
- [ ] Workspace retention ≥ 30 days (90 recommended).
- [ ] List of tenants and subscriptions in scope.

**F5 BIG-IP**
- [ ] **Auditor** account (all partitions) on each device, or on one device per sync-failover group.
- [ ] HTTPS reachability from the collector host to the management IPs. Note the cert fingerprints.
- [ ] TMOS versions confirmed. The declarative JSON export needs 15.1 or later.
- [ ] Lab test: can Auditor run `asm/tasks/export-policy`?
- [ ] For offline mode: `bigip.conf` (or the `tmsh list … recursive` output) + ASM policy exports (JSON/XML).
- [ ] (Phase 6) Change request: ASM remote logging "all requests", or an LTM request-log profile to a central sink.

---

## 11. Risks & open questions

| Risk | Mitigation |
|---|---|
| Auditor may not be allowed to POST the ASM export task | Fall back to per-subcollection GETs; verify in a lab first |
| ASM exports over 1 MB get truncated | Download in Content-Range chunks, validate the JSON, record a hash |
| restjavad overload on busy BIG-IPs | Limit concurrency to 2–4, back off on 503, schedule off-peak |
| Log volume and Log Analytics query cost/limits | Aggregate in KQL by day; chunk long time ranges; never pull raw rows |
| Path templating mistakes (over- or under-collapse) | Typed masks first, conservative threshold, user overrides persisted |
| No bodies in logs, so no schemas | Accept for v1. Enrich from APIM/OpenAPI or ASM-imported OpenAPI. |
| Cross-tenant/subscription policy references | Resolve by ID; flag unreachable references |
| Classic Front Door retirement (31 Mar 2027) | Basic support only; flag as legacy |

**Open questions for you:**
1. How many Azure tenants and subscriptions, and how many BIG-IP devices and sync groups?
2. TMOS versions in use?
3. Where should the tool run (a VM in Azure with a managed identity, or on-prem near the F5s)? This decides auth and network paths.
4. Can we get a sample (sanitised) `bigip.conf` + one ASM export and one App Gateway / AFD JSON export to build fixtures from?

---

## 12. Sources

**Microsoft Learn**
- App Gateway WAF policy overview and per-site/per-URI policies: https://learn.microsoft.com/azure/web-application-firewall/ag/policy-overview · https://learn.microsoft.com/azure/web-application-firewall/ag/per-site-policies
- CRS/DRS rule groups: https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules
- Request size limits: https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits
- AFD DRS: https://learn.microsoft.com/azure/web-application-firewall/afds/waf-front-door-drs
- AFD WAF monitoring: https://learn.microsoft.com/azure/web-application-firewall/afds/waf-front-door-monitor
- App Gateway monitoring reference: https://learn.microsoft.com/azure/application-gateway/monitor-application-gateway-reference
- Front Door monitoring reference: https://learn.microsoft.com/azure/frontdoor/monitor-front-door-reference
- Log tables `AGWAccessLogs` and `AGWFirewallLogs`: https://learn.microsoft.com/azure/azure-monitor/reference/tables/agwaccesslogs · https://learn.microsoft.com/azure/azure-monitor/reference/tables/agwfirewalllogs
- Resource Graph supported tables and throttling: https://learn.microsoft.com/azure/governance/resource-graph/reference/supported-tables-resources · https://learn.microsoft.com/azure/governance/resource-graph/concepts/guidance-for-throttled-requests
- Defender API security posture: https://learn.microsoft.com/azure/defender-for-cloud/api-security-posture-overview
- Classic Front Door retirement: https://azure.microsoft.com/updates?id=azure-front-door-classic-will-be-retired-on-31-march-2027

**F5**
- User roles: https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-systems-user-account-administration/user-roles.html
- Declarative WAF policy schema (v17.1): https://clouddocs.f5.com/products/waf-declarative-policy/declarative_policy_v17_1.html
- Declarative policy getting started (16.1): https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-declarative-security-policy/declarative-policy-getting-started.html
- Attaching ASM policies via REST: https://devcentral.f5.com/s/articles/methods-to-attach-asm-policy-to-virtual-server-via-rest-api-requests-30687
- ASM export JSON size limit: https://community.f5.com/discussions/technicalforum/asm-export-json---size-limit-/340392
- ASM logging (17.0): https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-asm-implementations/logging-application-security-events.html
- AS3 API: https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/refguide/apidocs.html
- Telemetry Streaming: https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html
- BIG-IQ virtual servers with WAF: https://clouddocs.f5.com/products/big-iq/mgmt-api/v5.4/HowToSamples/bigiq_api_modules/asm/t_asm_virtual_servers.html
- F5 XC API Discovery for BIG-IP: https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/api-security/big-ip-virt-server

**API discovery prior art**
- Cloudflare API Discovery: https://developers.cloudflare.com/api-shield/security/api-discovery/
- Akto (MIT, URLTemplate typed slots): https://github.com/akto-api-security/akto
- mitmproxy2swagger (MIT, two-pass templating): https://github.com/alufers/mitmproxy2swagger
- Drain3 (log template mining): https://github.com/logpai/Drain3
- openapi-pydantic (MIT): https://github.com/mike-oakley/openapi-pydantic

> A few details came from search snippets or SDK inspection rather than a fetched doc page: the exact F5 ASM subcollection names, the remote-log key list, and the Azure column casing. Verify them against `/mgmt/toc` and `getschema` in Phase 0 before hard-coding.
