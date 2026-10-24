# WAF Inventory

A read-only tool that connects to WAF products, starting with **Azure WAF** (Application Gateway, Front Door) and **F5 BIG-IP** (LTM + ASM/Advanced WAF). It inventories every published web app and API, captures the WAF configuration that applies to each host and path, and discovers the API endpoints actually in use from traffic logs. Results are shown in a dashboard and can be exported as HTML, JSON, CSV, Excel and OpenAPI.

Status: planning. See the plan in [`docs/PLAN.md`](docs/PLAN.md) or [`docs/plan.html`](docs/plan.html).
