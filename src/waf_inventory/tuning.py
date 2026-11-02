"""False-positive tuning: WAF events grouped by proxy, rule and path template, scored from counted evidence, with the
narrowest exclusion proposed for each likely false positive.

Deterministic on purpose, with no language model: the same events always give the same plan, and no request content an
attacker writes can argue its way into an exclusion. A person approves every proposal; nothing is applied from here.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from sqlalchemy.orm import Session

from .discovery import discover, normalize, template_rx
from .models import TuningDecision, WafEvent, WafPolicy, get_setting

NOISY = ("920", "921", "932", "941", "942")  # CRS families known to misfire on ordinary input (protocol, injection on free text)
SCANNER = re.compile(r"zgrab|masscan|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|dirb/|wpscan|feroxbuster|ffuf|httpx|"
                     r"python-requests|go-http-client|libwww|curl/|wget/|scan", re.I)
MIN_EVENTS = 5
LIKELY = 60  # score from which a group is a likely false positive


def _params_to_wildcards(template: str) -> str:
    return re.sub(r"\{[^}/]+\}", "{*}", template)


def groups(session: Session) -> list[dict]:
    """One row per proxy + rule + method + path template, strongest false positives first."""
    events = session.query(WafEvent).all()
    if not events:
        return []
    # shortcut: groups are recomputed from all stored events on each call; store them per run if tenants grow past ~100k events
    templates: dict[tuple, list[tuple[re.Pattern, str]]] = defaultdict(list)
    for e in discover({"host": x.host, "method": x.method, "path": x.path} for x in events):
        templates[(e["host"], e["method"])].append((template_rx(e["template"]), e["template"]))
    policies = {p.native_id: p for p in session.query(WafPolicy).filter_by(vendor="baffinbay")}
    decisions = {d.key: d for d in session.query(TuningDecision)}
    agg: dict[tuple, list[WafEvent]] = defaultdict(list)
    for x in events:
        raw = "/" + "/".join(normalize(x.path)[0])
        t = next((t for rx, t in templates.get((x.host, (x.method or "").upper()), []) if rx.match(raw)), raw)
        for r in x.rules:
            agg[(x.proxy, r["id"], (x.method or "").upper(), t)].append(x)
    out = [_score(key, evs, policies.get(key[0]), decisions) for key, evs in agg.items()]
    return sorted(out, key=lambda g: ({"false positive": 0, "unsure": 1, "attack": 2}[g["verdict"]], -g["score"], -g["events"]))


def _score(key: tuple, evs: list[WafEvent], pol: WafPolicy | None, decisions: dict) -> dict:
    proxy_id, rule, method, template = key
    n, ips = len(evs), {e.source_ip for e in evs if e.source_ip}
    days = {e.time[:10] for e in evs}
    logged = [e for e in evs if e.action == "LOGGED" and e.status]  # these reached the application: its answer is evidence
    ok = sum(200 <= e.status < 400 for e in logged) / len(logged) if logged else None
    single = sum(len(e.rules) == 1 for e in evs) / n
    scanner = sum(not e.user_agent or bool(SCANNER.search(e.user_agent)) for e in evs) / n
    notfound = sum(e.status == 404 for e in logged) / len(logged) if logged else 0
    per_request = sum(len(e.rules) for e in evs) / n
    attack = [why for cond, why in (
        (scanner >= 0.3, f"{scanner:.0%} scanner or empty user agents"),
        (notfound >= 0.5, "the application answers 404: probe paths"),
        (per_request >= 3, f"{per_request:.1f} rules per request on average"),
        (n >= 10 and len(ips) <= 2, f"all {n} events from {len(ips)} source(s)")) if cond]
    score = round(min(30, 3 * len(ips)) + min(15, 5 * (len(days) - 1)) + 20 * single + (25 * ok if ok is not None else 0)
                  + (10 if rule[:3] in NOISY else 0))
    evidence = [f"{n} event(s) from {len(ips)} source(s) in {len({e.country for e in evs if e.country})} countr(ies) "
                f"over {len(days)} day(s)", f"{single:.0%} of requests matched only this rule"]
    if ok is not None:
        evidence.append(f"the application answered {ok:.0%} of the {len(logged)} logged request(s) with 2xx or 3xx")
    if rule[:3] in NOISY:
        evidence.append(f"rule family {rule[:3]} often misfires on ordinary input")
    matched = sorted({m for e in evs for m in e.matched})[:3]
    verdict = "attack" if attack else "unsure" if n < MIN_EVENTS else "false positive" if score >= LIKELY else "unsure"
    proposal, note = None, ""
    if verdict == "false positive":
        segs = template.strip("/").split("/")
        if not segs[0] or segs[0].startswith("{"):
            note = "No proposal: an exclusion here would cover the whole site. Check the matched data and decide by hand."
        else:
            proposal = {"match": _params_to_wildcards(template), "rule": rule}
    k = f"{proxy_id}|{rule}|{method}|{template}"
    d = decisions.get(k)
    return {"key": k, "verdict": verdict, "score": score, "proxy": pol.name if pol else proxy_id or "", "proxy_id": proxy_id,
            "mode": pol.mode if pol else "", "host": ", ".join(sorted({e.host for e in evs})), "method": method, "path": template,
            "rule": rule, "rule_name": next((r["name"] for e in evs for r in e.rules if r["id"] == rule and r.get("name")), ""),
            "events": n, "sources": len(ips), "days": len(days), "first": min(e.time for e in evs), "last": max(e.time for e in evs),
            "evidence": evidence, "attack_signs": attack, "matched": matched, "note": note,
            "proposal": proposal, "decision": d.decision if d else "", "decided_by": d.user if d else "",
            "support_ids": sorted({e.support_id for e in evs if e.support_id})}


def support_lookup(session: Session, support_id: str) -> tuple[WafEvent | None, list[dict]]:
    """The event a blocked user's Support ID points at, and the groups it belongs to."""
    e = session.query(WafEvent).filter_by(support_id=support_id.strip().replace("-", "").lower()).first()
    return e, [g for g in groups(session) if e and e.support_id in g["support_ids"]] if e else []


def approved(session: Session) -> list[dict]:
    """Per proxy: its current exclusions plus the approved additions, as the API and Terraform want them (whole lists)."""
    pols = {p.native_id: p for p in session.query(WafPolicy).filter_by(vendor="baffinbay")}
    adds: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for g in groups(session):
        if g["decision"] == "approved" and g["proposal"] and g["proxy_id"] in pols:
            p = pols[g["proxy_id"]]
            uuid = get_setting(session, f"crs:{p.settings.get('crs_id')}").get(g["rule"])
            adds[g["proxy_id"]][g["proposal"]["match"]].append({"type": "rule", "id": uuid or g["rule"], "modSecId": g["rule"],
                                                               "name": g["rule_name"], "known": bool(uuid)})
    out = []
    for pid, matches in adds.items():
        p = pols[pid]
        waf = (p.raw.get("attributes") or {}).get("waf") or {}
        staged = waf.get("stagedWaf") or {}
        out.append({"proxy": p.name, "id": pid, "additions": {m: rules for m, rules in matches.items()},
                    "staged": _merged(staged.get("pathExclusions", []) if staged.get("state") == "ENABLED" else waf.get("pathExclusions", []),
                                      matches),
                    "active": _merged(waf.get("pathExclusions", []), matches),
                    "staged_was": staged if staged.get("state") == "ENABLED" else None,
                    "paranoia_level": waf.get("paranoidLevel"), "cookie_exclusions": waf.get("cookieExclusions", [])})
    return out


def _merged(current: list[dict], adds: dict[str, list[dict]]) -> list[dict]:
    out = [dict(e, rules=list(e.get("rules", []))) for e in current]
    for match, rules in adds.items():
        e = next((x for x in out if x.get("match") == match and not x.get("disableAll")), None)
        if e is None:
            out.append(e := {"match": match, "disableAll": False, "rules": []})
        e["rules"] += [{"type": "rule", "id": r["id"]} for r in rules if r["id"] not in {x.get("id") for x in e["rules"]}]
    return out


def patch_json(session: Session) -> str:
    """Request bodies for PATCH /api/v2/traffic-mgmt/traffic-configs/{id}: first the Staged WAF, after 24 to 48 hours the WAF."""
    out = []
    for a in approved(session):
        sw = a["staged_was"] or {"state": "ENABLED", "mode": "PARANOIA_LEVEL", "paranoiaLevel": a["paranoia_level"],
                                 "cookieExclusions": a["cookie_exclusions"]}
        out.append({"proxy": a["proxy"], "traffic_config_id": a["id"],
                    "rule_ids": {r["id"]: f"{r['modSecId']} {r['name']}".strip() for rs in a["additions"].values() for r in rs},
                    "unknown_rule_ids": sorted({r["modSecId"] for rs in a["additions"].values() for r in rs if not r["known"]}),
                    "1_stage": {"data": {"type": "httpProxy", "id": a["id"],
                                         "attributes": {"waf": {"stagedWaf": {**sw, "pathExclusions": a["staged"]}}}}},
                    "2_promote": {"data": {"type": "httpProxy", "id": a["id"], "attributes": {"waf": {"pathExclusions": a["active"]}}}}})
    return json.dumps(out, indent=2)


def terraform(session: Session) -> str:
    """The same change for a baffinbay/threat-protection pipeline: the lists to set on each baffinbay_http_proxy."""
    lines = ["# Approved false-positive exclusions from WAF Inventory. Review before applying.",
             "# Step 1: set waf.staged_waf.path_exclusions and watch the staged events for 24 to 48 hours.",
             "# Step 2: if the false positives are gone and nothing else changed, set waf.path_exclusions to the same list.", ""]
    for a in approved(session):
        lines += [f"# {a['proxy']} (traffic configuration {a['id']})"]
        for m, rules in a["additions"].items():
            lines += [f"#   adds {m}: " + ", ".join(f"{r['modSecId']} {r['name']}".strip() for r in rules)]
        if unknown := sorted({r["modSecId"] for rs in a["additions"].values() for r in rs if not r["known"]}):
            lines += [f"#   rule(s) {', '.join(unknown)} were not in the collected rule catalogue: replace them with the catalogue's rule id"]
        lines += ["path_exclusions = ["]
        lines += [f'  {{ match = {json.dumps(e["match"])}, disable_all = {str(bool(e.get("disableAll"))).lower()}, '
                  f'rule_ids = {json.dumps([r["id"] for r in e.get("rules", [])])} }},' for e in a["staged"]]
        lines += ["]", ""]
    return "\n".join(lines)
