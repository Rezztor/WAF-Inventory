"""Posture findings over the stored inventory: unprotected apps, weak policies, shadow and dormant APIs."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from . import remedies, tuning
from .baffinbay import RISKY_METHODS
from .discovery import glob_rx, template_rx
from .models import Endpoint, Finding, Listener, WafPolicy
from .report import Inventory

MIN_RULESET = {"OWASP": (3, 2), "Microsoft_DefaultRuleSet": (2, 1), "DefaultRuleSet": (1, 0), "CRS": (4, 0)}


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in str(v).split(".") if x.isdigit())


def run(session: Session, specs: Iterable[dict] = ()) -> list[Finding]:
    """Recompute all findings. `specs` are OpenAPI documents (servers[0].url gives the host)."""
    session.query(Finding).delete()
    out: list[Finding] = []

    def add(rule, severity, title, subject, detail=""):
        out.append(Finding(rule=rule, severity=severity, title=title, subject=subject, detail=detail))

    used: set[int] = set()
    for lst in session.query(Listener):
        subj = f"{lst.gateway.name} / {lst.name}" + (f" ({', '.join(lst.hostnames)})" if lst.hostnames else "")
        used |= {lst.policy_id, *(r.policy_id for r in lst.routes)} - {None}
        if not lst.waf_capable:
            if lst.gateway.kind == "appgw":
                add("l4-listener", "medium", "Layer-4 listener is not inspected by the WAF", subj, lst.protocol)
            continue
        protected = [r for r in lst.routes if r.policy]
        if lst.policy is None and not protected:
            add("no-waf", "high", "Application is published with no WAF policy", subj)
        elif lst.policy is None:
            add("partial-waf", "medium", "Default route has no WAF policy", subj,
                f"{len(protected)}/{len(lst.routes)} routes protected")
        else:
            for r in lst.routes:
                if r.policy is None:
                    add("route-no-waf", "medium", "Route bypasses the WAF", f"{subj} {r.name}", ", ".join(r.paths))

    for p in session.query(WafPolicy):
        st, subj = p.settings, f"{p.vendor}: {p.name}"
        if p.id not in used:  # an unattached policy protects nothing: one finding, no mode noise
            add("unused-policy", "low", "WAF policy is not attached to any listener or route", subj, f"mode {p.mode}")
        elif p.mode == "detect":
            add("detection-mode", "high", "WAF policy only detects (does not block)", subj)
        elif p.mode == "off":
            add("waf-disabled", "high", "WAF policy is disabled or inactive", subj)
        elif p.mode == "unknown":
            add("policy-unreadable", "low", "WAF policy could not be read", subj, st.get("note", ""))
        for rs in st.get("rulesets", []):
            floor = MIN_RULESET.get(rs.get("type"))
            if floor and _ver(rs.get("version")) < floor:
                add("old-ruleset", "medium", "Outdated managed rule set", subj, f"{rs['type']} {rs['version']}")
        if p.vendor in ("azure", "baffinbay") and p.mode != "unknown" and not st.get("bot"):
            add("no-bot-protection", "low", "No bot protection rule set", subj)
        if st.get("disabled_rules"):
            add("disabled-rules", "medium", "Managed rules / signatures disabled", subj,
                f"{len(st['disabled_rules'])}: {', '.join(st['disabled_rules'][:10])}")
        if st.get("exclusions"):
            add("exclusions", "low", "Rule exclusions configured", subj, f"{len(st['exclusions'])} exclusion(s)")
        if st.get("request_body_check") is False:
            add("body-inspection-off", "medium", "Request body inspection is off", subj)
        if st.get("legacy"):
            add("legacy-waf-config", "low", "Legacy WAF configuration (migrate to a WAF policy)", subj)
        if any(u["name"] == "*" for u in st.get("allowed_urls", [])):
            add("wildcard-urls", "medium", "Allowed URLs include the '*' wildcard (URL enforcement off)", subj)
        if st.get("signature_staging") or st.get("staged_signatures"):
            add("signature-staging", "medium", "Attack signatures in staging (not blocking)", subj,
                "; ".join(x for x in ("staging enabled for the policy" if st.get("signature_staging") else "",
                                      f"{st['staged_signatures']} signature(s) staged" if st.get("staged_signatures") else "") if x))
        if st.get("violations_not_blocking"):
            add("violations-not-blocking", "low", "Violations set to alarm only", subj, ", ".join(st["violations_not_blocking"][:10]))
        if p.vendor == "baffinbay":
            _baffinbay(add, st, subj)
        if p.vendor == "f5" and st.get("export") == "missing":
            add("policy-detail-missing", "low", "No ASM policy export available; settings incomplete", subj)

    out += _api_findings(session, list(specs))
    todo: dict[str, int] = {}
    for g in tuning.groups(session):
        if g["verdict"] == "false positive" and not g["decision"]:
            todo[g["proxy"]] = todo.get(g["proxy"], 0) + 1
    for proxy, n in sorted(todo.items()):
        add("tuning-candidates", "low", "Likely WAF false positives to review", f"baffinbay: {proxy}", f"{n} on the Tuning page")
    session.add_all(out)
    session.commit()
    remedies.remember_score(session)
    return out


def _baffinbay(add, st: dict, subj: str) -> None:
    if not st.get("rate_limits"):
        add("no-rate-limit", "medium", "No rate limit enforced", subj)
    if st.get("backend_tls") in ("plaintext", "not verified"):
        add("backend-tls-unverified", "medium", "Traffic to the backend is not verified TLS", subj, st["backend_tls"])
    if risky := sorted(set(st.get("allowed_methods", [])) & RISKY_METHODS):
        add("risky-methods", "medium", "Risky HTTP methods allowed", subj, ", ".join(risky))
    wide = [e["selector"] for e in st.get("exclusions", []) if e["variable"] == "path" and re.match(r"/?(\{\*\}|\*)", e["selector"] or "")]
    wide += [x for x in st.get("source_exclusions", []) if ipaddress.ip_network(x, strict=False).num_addresses > 256]
    if wide:
        add("wide-exclusion", "medium", "Exclusion covers every path or a wide source range", subj, ", ".join(wide))
    if not st.get("matched_data"):
        add("matched-data-off", "low", "WAF matched data is not recorded, so false positives are harder to judge", subj)
    if st.get("hsts") is False:
        add("no-hsts", "low", "HTTPS without HSTS", subj)
    if st.get("frontend_tls") is False:
        add("no-frontend-tls", "medium", "Published over plain HTTP", subj)
    if st.get("paranoia_level") == 1:
        add("paranoia-1", "low", "WAF at paranoia level 1, the least strict", subj, "try level 2 in the Staged WAF first")


def _api_findings(session: Session, specs: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    inv = Inventory(session)
    spec_paths: dict[str, list[tuple[str, str]]] = {}  # host -> [(METHOD, template)]
    for spec in specs:
        host = urlsplit((spec.get("servers") or [{}])[0].get("url", "")).hostname or ""
        for path, ops in spec.get("paths", {}).items():
            spec_paths.setdefault(host.lower(), []).extend((m.upper(), path) for m in ops if not m.startswith("x-"))

    seen: dict[str, list[Endpoint]] = {}
    unknown: dict[str, list[Endpoint]] = {}
    for e in session.query(Endpoint):
        seen.setdefault(e.host, []).append(e)
        subj, sample = f"{e.method} {e.host}{e.template}", (e.samples or [e.template])[0]
        if not inv.listeners_for(e.host):
            unknown.setdefault(e.host, []).append(e)
            continue
        if e.kind != "api" or not e.confirmed:
            continue
        lst, pol = inv.effective(e.host, sample)
        if pol is None:
            out.append(Finding(rule="unprotected-api", severity="high", title="API endpoint not covered by a WAF policy",
                               subject=subj, detail=f"{e.hits} request(s)"))
        urls = [u for u in (pol.settings.get("allowed_urls", []) if pol else []) if u.get("name")]
        if urls and not any(u["name"] == "*" for u in urls) and not any(
                glob_rx(u["name"]).match(s) and u.get("method", "*") in ("*", e.method) for u in urls for s in e.samples):
            out.append(Finding(rule="shadow-api", severity="high", title="Shadow API: not in the WAF allowed URL list",
                               subject=subj, detail=f"policy {pol.name}"))
        if e.host in spec_paths and not any(m == e.method and template_rx(t).match(s)
                                            for m, t in spec_paths[e.host] for s in e.samples):
            out.append(Finding(rule="shadow-api", severity="high", title="Shadow API: not in the OpenAPI spec",
                               subject=subj, detail=f"{e.hits} request(s)"))

    stray = []  # hosts with no confirmed endpoint: mostly scanners sending made-up Host headers
    for host, eps in unknown.items():  # one finding per host, however many paths it was probed on
        if not any(e.confirmed for e in eps):
            stray.append(host)
            continue
        out.append(Finding(rule="unknown-host", severity="medium", title="Traffic for a host not in the inventory", subject=host,
                           detail=f"{len(eps)} endpoint(s), {sum(e.hits for e in eps)} request(s)"))
    if stray:
        out.append(Finding(rule="stray-hosts", severity="low", title="A few requests for hosts not in the inventory",
                           subject=f"{len(stray)} host(s)", detail=", ".join(sorted(stray)[:10]) + (" …" if len(stray) > 10 else "")))

    for host, ops in spec_paths.items():
        eps = seen.get(host, [])
        for m, t in ops:
            if not any(e.method == m and template_rx(t).match(s) for e in eps for s in e.samples):
                out.append(Finding(rule="dormant-api", severity="low", title="Documented API not seen in traffic",
                                   subject=f"{m} {host}{t}", detail="zombie/dormant candidate for the log window"))
    return out
