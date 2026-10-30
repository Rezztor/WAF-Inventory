"""The fix plan: findings grouped into issues, each with why it matters and how to fix it per vendor, and a posture score.

The score is the share of applicable checks the estate passes, weighted by severity (high 10, medium 4, low 1). A check
applies when the estate has a vendor it covers; one finding fails the whole check, so the score moves only when an
issue is fixed everywhere.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy.orm import Session

from .models import Finding, Gateway, WafPolicy, get_setting, now, put_setting
from .report import Inventory

WEIGHT = {"high": 10, "medium": 4, "low": 1}
VENDOR = {"azure": "Azure", "f5": "F5 BIG-IP", "baffinbay": "Baffin Bay", "any": "Any vendor"}

# rule: (severity, action, why, {vendor | "any": how to fix})
CHECKS: dict[str, tuple[str, str, str, dict[str, str]]] = {
    "no-waf": ("high", "Put a WAF in front of unprotected applications",
               "Every request reaches the application uninspected: injection, cross-site scripting and bots go straight to the code.",
               {"azure": "Application Gateway: associate a WAF policy with the gateway or this listener (WAF policy › Associated "
                         "application gateways). Front Door: add a security policy that links a WAF policy to this domain.",
                "f5": "Local Traffic › Virtual Servers › the virtual server › Security › Policies: enable Application Security "
                      "Policy and pick a policy. The virtual server needs an HTTP profile."}),
    "waf-disabled": ("high", "Turn disabled WAF policies back on",
                     "The policy exists and looks protected in the portal, but inspects nothing.",
                     {"azure": "WAF policy › Policy settings: set the state to Enabled.",
                      "f5": "Security › Application Security › Security Policies: make the policy active and attach it to its virtual server.",
                      "baffinbay": "Set the proxy's WAF enforcement from DISABLED to LOG, watch the Tuning page for a few days, then BLOCK."}),
    "detection-mode": ("high", "Switch WAF policies from detect to block",
                       "Attacks are logged but still reach the application. Detection is for the first weeks of tuning, not for good.",
                       {"azure": "Check the WAF logs for false positives first, then WAF policy › Overview › Switch to prevention mode.",
                        "f5": "Review the policy's learning suggestions, then set Enforcement Mode to Blocking in the policy's "
                              "general settings and Apply Policy.",
                        "baffinbay": "Review the Tuning page, then set the proxy's WAF enforcement to BLOCK. Try it in the Staged "
                                     "WAF first if you are unsure."}),
    "unprotected-api": ("high", "Cover live API endpoints with a WAF policy",
                        "Real API traffic reaches the backend with no WAF in the path.",
                        {"any": "Open the application, find the route that serves the endpoint and attach a WAF policy to it, or "
                                "remove the bypass (an F5 LTM policy rule with an asm disable action)."}),
    "shadow-api": ("high", "Document or remove shadow APIs",
                   "An endpoint answers in production that nobody documented, so nobody reviews or protects it.",
                   {"any": "Find its owner. If it should exist, add it to the OpenAPI spec or the ASM allowed URLs (the API "
                           "endpoints page exports an OpenAPI file to start from). If not, block it at the WAF and remove it from the app."}),
    "partial-waf": ("medium", "Protect the default route",
                    "Requests that match none of the protected routes reach the backend uninspected.",
                    {"azure": "Associate the WAF policy with the listener itself, so every route without its own policy inherits it.",
                     "f5": "Enable the security policy on the virtual server and check LTM policies for asm disable actions."}),
    "route-no-waf": ("medium", "Close routes that bypass the WAF",
                     "This path is published, but requests to it skip the WAF.",
                     {"azure": "Associate a WAF policy with the path rule, or with the listener so the path inherits it.",
                      "f5": "An LTM policy rule turns ASM off for this path. Remove the asm disable action, or limit it to "
                            "paths that truly need it, such as a health check."}),
    "old-ruleset": ("medium", "Upgrade outdated managed rule sets",
                    "Older rule sets miss newer attack techniques and no longer get fixes.",
                    {"azure": "Move Application Gateway to DRS 2.1 and Front Door to Microsoft_DefaultRuleSet 2.1. Rule IDs "
                              "change between versions: re-create exclusions and run in detection for a few days first.",
                     "baffinbay": "Request CRS 4.* for the proxy. Test the new version in the Staged WAF (mode CRS_VERSION) first."}),
    "disabled-rules": ("medium", "Re-enable rules switched off everywhere",
                       "A disabled rule stops looking for that attack on every path, not just where it misfired.",
                       {"azure": "Turn the rule back on and add an exclusion for the one request attribute that caused the false positive.",
                        "f5": "Re-enable the signature and, if it misfired on one parameter, disable it on that parameter only.",
                        "baffinbay": "Replace path exclusions that disable all rules with a list of the rules that misfire. "
                                     "The Tuning page proposes the narrowest one."}),
    "wide-exclusion": ("medium", "Narrow exclusions that cover the whole site",
                       "An exclusion on every path, or for a wide source range, switches the WAF off for far more than intended.",
                       {"baffinbay": "Replace it with exclusions for one path and the rules that misfire there; the Tuning page shows which."}),
    "body-inspection-off": ("medium", "Inspect request bodies",
                            "Attacks sent in POST bodies (JSON, forms, XML) pass without inspection.",
                            {"azure": "WAF policy › Policy settings: turn on Inspect request body.",
                             "baffinbay": "Turn JSON, XML and multipart parsing back on for these paths in HTTP compliance."}),
    "wildcard-urls": ("medium", "Replace the * allowed URL with real URLs",
                      "With * allowed, ASM does not enforce URLs, so any path the application answers is reachable.",
                      {"f5": "Let traffic learning or the Policy Builder collect the real URLs, add them as explicit entries, "
                             "then remove * or make it a staged wildcard."}),
    "signature-staging": ("medium", "Enforce staged attack signatures",
                          "Signatures in staging only raise alarms; matching attacks are not blocked.",
                          {"f5": "Review the staging suggestions in Traffic Learning, then enforce the signatures that have not "
                                 "fired on good traffic. Turn staging off for the policy once it is tuned."}),
    "l4-listener": ("medium", "Inspect or restrict layer-4 listeners",
                    "TCP and TLS listeners pass traffic without any HTTP inspection.",
                    {"azure": "If the service speaks HTTP, publish it on an HTTP or HTTPS listener instead. Otherwise limit "
                              "who can reach it with a network security group."}),
    "backend-tls-unverified": ("medium", "Verify TLS to the backend",
                               "Traffic between the WAF and the server can be read or changed on the way.",
                               {"baffinbay": "Connect to the backend over TLS and verify its certificate (system or own CA)."}),
    "no-frontend-tls": ("medium", "Serve the application over HTTPS",
                        "Passwords and session cookies cross the internet in clear text.",
                        {"baffinbay": "Add a certificate, set the frontend to SECURE and turn on the HTTP to HTTPS redirect."}),
    "no-rate-limit": ("medium", "Add a rate limit",
                      "Nothing slows down credential stuffing, scraping or floods from one source.",
                      {"baffinbay": "Turn on the per-source-IP rate limit in BLOCK. Start generous, then lower it after a week of data."}),
    "risky-methods": ("medium", "Disallow risky HTTP methods",
                      "TRACE, CONNECT and WebDAV methods are rarely needed and widen the attack surface.",
                      {"baffinbay": "Remove them from the allowed HTTP methods unless the application needs them."}),
    "unknown-host": ("medium", "Account for traffic to unknown hosts",
                     "Traffic arrives for a host that no connection knows: a missing connection, a forgotten app or an old DNS record.",
                     {"any": "Add the connection that publishes the host, or remove the DNS record that points at it."}),
    "no-bot-protection": ("low", "Turn on bot protection",
                          "Scrapers, credential stuffing and vulnerability scanners are not told apart from people.",
                          {"azure": "Add the Microsoft_BotManagerRuleSet managed rule set (Application Gateway, Front Door Premium).",
                           "baffinbay": "Turn on bot protection for the proxy."}),
    "no-hsts": ("low", "Turn on HSTS",
                "Without HSTS a first visit over plain HTTP can be intercepted and kept on HTTP.",
                {"baffinbay": "Turn on HTTP Strict Transport Security for the frontend; use a one-year max-age once every subdomain serves HTTPS."}),
    "paranoia-1": ("low", "Raise the paranoia level",
                   "Level 1 runs only the rules that almost never misfire, so it also misses more attacks.",
                   {"baffinbay": "Run paranoia level 2 in the Staged WAF for a week, tune with the Tuning page, then move the WAF to it."}),
    "matched-data-off": ("low", "Record matched data",
                         "Without it nobody can see what triggered a rule, so false positives are guessed at.",
                         {"baffinbay": "Turn on matched data in the proxy's Data Settings."}),
    "tuning-candidates": ("low", "Review likely false positives",
                          "Blocked customers and noisy logs hide real attacks.",
                          {"baffinbay": "Open the Tuning page and approve or reject each proposal."}),
    "violations-not-blocking": ("low", "Block violations that only alarm",
                                "These violations are detected but never blocked.",
                                {"f5": "Set the Block flag for them in Learning and Blocking Settings once they no longer fire on good traffic."}),
    "exclusions": ("low", "Review rule exclusions",
                   "Each exclusion is a deliberate gap in inspection.",
                   {"any": "Review them every quarter. Keep only exclusions scoped to one field or path and one rule."}),
    "legacy-waf-config": ("low", "Migrate legacy WAF configuration",
                          "Application Gateway WAF configuration is being retired in favour of WAF policies, which also allow per-site rules.",
                          {"azure": "Application Gateway › Web application firewall › Migrate to WAF policy."}),
    "unused-policy": ("low", "Attach or delete unused policies",
                      "An unattached policy protects nothing, and someone may be editing it thinking it does.",
                      {"any": "Attach it where it was meant to go, or delete it."}),
    "policy-detail-missing": ("low", "Add the missing ASM policy exports",
                              "Without the export the policy's settings cannot be checked.",
                              {"f5": "Add the ASM policy export (XML or JSON) to the offline connection, or switch to the REST connection, which reads it directly."}),
    "policy-unreadable": ("low", "Fix unreadable policies",
                          "The policy could not be read, so none of its checks ran.",
                          {"any": "Open the connection and run Test connection; it names the missing permission."}),
    "dormant-api": ("low", "Retire documented APIs nobody calls",
                    "Endpoints no client uses are attack surface with nobody watching it.",
                    {"any": "Confirm with the owner, then remove it from the application and the spec, or note why it is idle."}),
    "stray-hosts": ("low", "Reject requests for unknown hosts",
                    "Mostly scanners sending made-up Host headers.",
                    {"any": "Make the default listener or virtual server reject requests whose Host is not one of yours."}),
}


def _locate(session: Session) -> callable:
    """subject -> (vendor or None, link or None), for the shapes findings.py writes."""
    pols = {f"{p.vendor}: {p.name}": (p.vendor, f"/policy/{p.id}") for p in session.query(WafPolicy)}
    gws = {g.name: g.vendor for g in session.query(Gateway)}
    inv = Inventory(session)

    def locate(subject: str) -> tuple[str | None, str | None]:
        if subject in pols:
            return pols[subject]
        if m := re.match(r"(azure|f5|baffinbay): ", subject):
            return m[1], None
        if " / " in subject:
            hosts = re.search(r"\(([^,)]+)", subject)
            return gws.get(subject.split(" / ")[0]), f"/apps/{hosts[1]}" if hosts else None
        if m := re.match(r"[A-Z]+ ([^/\s]+)/", subject):
            return None, f"/apps/{m[1]}" if inv.listeners_for(m[1]) else None
        return None, None
    return locate


def plan(session: Session) -> dict:
    """The score and the open issues, biggest gain first."""
    vendors = {v for (v,) in session.query(Gateway.vendor).distinct()} | {v for (v,) in session.query(WafPolicy.vendor).distinct()}
    checks = {r: c for r, c in CHECKS.items() if "any" in c[3] or vendors & c[3].keys()}
    total = sum(WEIGHT[c[0]] for c in checks.values()) or 1
    by: dict[str, list[Finding]] = defaultdict(list)
    for f in session.query(Finding):
        by[f.rule].append(f)
    locate = _locate(session)
    issues = []
    for rule, fs in by.items():
        sev, action, why, fixes = CHECKS.get(rule, (fs[0].severity, fs[0].title, "", {}))
        items = [{"subject": f.subject, "detail": f.detail, "title": f.title, "vendor": v, "link": link}
                 for f in sorted(fs, key=lambda f: f.subject) for v, link in [locate(f.subject)]]
        seen = {i["vendor"] for i in items} - {None}
        shown = [(VENDOR[k], text) for k, text in fixes.items() if k == "any" or k in seen] or [(VENDOR[k], t) for k, t in fixes.items()]
        issues.append({"rule": rule, "severity": sev, "action": action, "why": why, "fixes": shown, "items": items,
                       "gain": round(100 * WEIGHT[sev] / total) if rule in checks else 0})
    issues.sort(key=lambda i: (-WEIGHT.get(i["severity"], 0), -len(i["items"]), i["action"]))
    lost = sum(WEIGHT[checks[r][0]] for r in by if r in checks)
    return {"score": round(100 * (total - lost) / total), "checks": len(checks), "passed": len(set(checks) - set(by)),
            "issues": issues}


def remember_score(session: Session) -> None:
    """Add the current score to the history (90 points). Runs that finish within 10 minutes share one point."""
    pts = get_setting(session, "score_history").get("points", [])
    t = now()
    if pts and (t - datetime.fromisoformat(pts[-1]["time"])).total_seconds() < 600:
        pts = pts[:-1]
    put_setting(session, "score_history", {"points": (pts + [{"time": t.isoformat(), "score": plan(session)["score"]}])[-90:]})
    session.commit()


def score_history(session: Session) -> list[dict]:
    return get_setting(session, "score_history").get("points", [])
