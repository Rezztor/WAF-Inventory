"""The Overview's two questions, answered from counted facts: how protected are we, and what do I fix first? No model, no guess."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import report
from .models import get_setting, put_setting

HISTORY_DAYS = 90
MODE_POINTS = {"block": 100, "detect": 40, "unknown": 20, "off": 0, "none": 0}
FINDING_COST = {"high": 10, "medium": 3, "low": 0}
PUTS_IN_BLOCKING = {"no-waf", "waf-disabled", "detection-mode"}  # fixing one of these moves the application to blocking mode
ORDER = {"high": 0, "medium": 1, "low": 2}
STATE = {"block": "ok", "detect": "warn", "off": "crit", "none": "crit", "unknown": "na"}
LABEL = {"block": "Blocking", "detect": "Detect only", "off": "WAF off", "none": "No WAF", "unknown": "Unknown"}
FIX = {
    "no-waf": "Attach a WAF policy to the listener, domain or virtual server. A Basic Application Gateway needs moving to WAF_v2 first.",
    "partial-waf": "Attach a policy to the default route too.",
    "route-no-waf": "Attach a policy to the routes that bypass the WAF.",
    "unprotected-api": "Publish the API through a protected listener or route.",
    "detection-mode": "Check the logged events, tune them, then switch the policy to blocking.",
    "waf-disabled": "Enable the policy, or remove it if it is not needed.",
    "old-ruleset": "Move to the current managed rule set, after testing it.",
    "disabled-rules": "Review each disabled rule. Replace it with a narrow exclusion where you can.",
    "body-inspection-off": "Turn request body inspection on.",
    "wildcard-urls": "Learn the real URLs, then remove the wildcard.",
    "signature-staging": "Enforce the staged signatures once they are tuned.",
    "wide-exclusion": "Narrow the exclusion to the paths or sources that need it.",
    "no-rate-limit": "Turn rate limiting on for this proxy.",
    "backend-tls-unverified": "Use TLS to the backend and verify its certificate.",
    "no-frontend-tls": "Publish over HTTPS with a certificate.",
    "risky-methods": "Remove the methods the application does not use.",
    "shadow-api": "Add the API to the specification and the allowed URLs, or block it if it should not exist.",
    "unknown-host": "Add the WAF that publishes this host as a connection, or check why the logs name it.",
    "l4-listener": "Move the listener to HTTP or HTTPS, or accept that the WAF cannot inspect it.",
    "tuning-candidates": "Review the proposals on the Tuning page.",
}


def _tiles(s: Session, findings: list[dict]) -> list[dict]:
    """One tile per application: its worst listener, and the findings that name it, its gateway listener or its policy."""
    tiles: dict[str, dict] = {}
    for a in report.table(s, "applications"):
        t = tiles.setdefault(a["application"], {"host": a["application"], "gateway": a["gateway"], "vendor": a["vendor"], "mode": a["mode"],
                                                "scored": a["waf_capable"], "names": set(), "found": []})
        if a["waf_capable"] and (not t["scored"] or MODE_POINTS[a["mode"]] < MODE_POINTS[t["mode"]]):
            t.update(mode=a["mode"], scored=True)
        t["names"] |= {f"{a['gateway']} / {a['listener']}"} | ({f"{a['vendor']}: {a['waf_policy']}"} if a["waf_policy"] else set())
    for t in tiles.values():
        t["found"] = [(f["rule"], f["severity"]) for f in findings if t["host"] in f["subject"] or any(n in f["subject"] for n in t["names"])]
    return list(tiles.values())


def _points(t: dict, fixed: str = "") -> int:
    mode = "block" if fixed in PUTS_IN_BLOCKING and (fixed, "high") in t["found"] else t["mode"]
    cost = sum(FINDING_COST[sev] for rule, sev in t["found"] if rule != fixed and rule not in PUTS_IN_BLOCKING)
    return max(0, MODE_POINTS[mode] - cost)


def _score(tiles: list[dict], fixed: str = "") -> float | None:
    scored = [t for t in tiles if t["scored"]]
    return sum(_points(t, fixed) for t in scored) / len(scored) if scored else None


def _grade(score: int) -> tuple[str, str]:
    for floor, word, tone in ((85, "Strong", "ok"), (60, "Fair", "warn"), (35, "At risk", "warn")):
        if score >= floor:
            return word, tone
    return "Exposed", "crit"


def snapshot(s: Session, day: str = "") -> None:
    """Keep the day's score, and what was open on the last two days, so the Overview can say what changed. Runs after every recompute."""
    day = day or datetime.now(timezone.utc).date().isoformat()
    findings = report.table(s, "findings")
    raw = _score(_tiles(s, findings))
    if raw is None:
        return
    days = [d for d in get_setting(s, "posture_history").get("days", []) if d["day"] != day]
    open_now = sorted({f"{f['title']}\t{f['subject']}" for f in findings if f["severity"] != "low"})[:500]
    days = [{"day": d["day"], "score": d["score"]} for d in days[:-1]] + days[-1:] + [{"day": day, "score": round(raw), "open": open_now}]
    put_setting(s, "posture_history", {"days": days[-HISTORY_DAYS:]})


def _trend(s: Session) -> dict | None:
    days = get_setting(s, "posture_history").get("days", [])
    if len(days) < 2:
        return None
    last, before = days[-1], days[-2]
    now, then = set(last.get("open", [])), set(before.get("open", []))
    width = 120 / (len(days) - 1)
    return {"delta": last["score"] - before["score"], "since": before["day"],
            "line": " ".join(f"{i * width:.1f},{26 - d['score'] * .24:.1f}" for i, d in enumerate(days)),
            "new": [x.split("\t") for x in sorted(now - then)], "fixed": [x.split("\t") for x in sorted(then - now)]}


def view(s: Session) -> dict:
    findings = report.table(s, "findings")
    tiles = _tiles(s, findings)
    raw = _score(tiles)
    groups: dict[str, dict] = {}
    for f in findings:
        g = groups.setdefault(f["rule"], {"rule": f["rule"], "severity": f["severity"], "title": f["title"], "count": 0, "fix": FIX.get(f["rule"], "")})
        g["count"] += 1
    for g in groups.values():
        g["apps"] = sum(any(rule == g["rule"] for rule, _ in t["found"]) for t in tiles)
        g["gain"] = max(0, round(_score(tiles, g["rule"]) - raw)) if raw is not None else 0
        g["link"] = "/tuning" if g["rule"] == "tuning-candidates" else f"/t/findings?rule={g['rule']}&severity={g['severity']}"
    queue = sorted(groups.values(), key=lambda g: (-g["gain"], ORDER.get(g["severity"], 9), -g["count"]))

    for t in tiles:
        t["state"] = STATE[t["mode"]] if t["scored"] else "na"
        t["label"] = LABEL[t["mode"]] if t["scored"] else "Not inspected"
        t["high"] = sum(sev == "high" and rule not in PUTS_IN_BLOCKING for rule, sev in t["found"])
    gateways: dict[str, dict] = {}
    for t in sorted(tiles, key=lambda t: ({"crit": 0, "warn": 1, "na": 2, "ok": 3}[t["state"]], t["host"])):
        gateways.setdefault(t["gateway"], {"name": t["gateway"], "vendor": t["vendor"], "tiles": []})["tiles"].append(t)
    counts = {k: sum(t["state"] == k for t in tiles) for k in ("crit", "warn", "ok", "na")}
    score = round(raw) if raw is not None else None
    grade, tone = _grade(score) if score is not None else ("", "na")
    return {"score": score, "grade": grade, "tone": tone, "web": sum(t["scored"] for t in tiles), "counts": counts,
            "map": sorted(gateways.values(), key=lambda g: [t["state"] != "crit" for t in g["tiles"]][:1] + [g["name"]]),
            "queue": queue[:6], "trend": _trend(s)}
