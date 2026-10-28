"""API discovery from access-log observations: path templating, classification, OpenAPI export.

Observation: {"host", "method", "path" (may include ?query), "status", "content_type", "user_agent", "hits",
              "first_seen", "last_seen"}. Query values are dropped on input; only parameter names are kept.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

MASKS = [  # (type, regex) applied per path segment, first match wins
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("int", re.compile(r"^\d+$")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}([tT ][\d:.]+[zZ]?)?$")),
    ("hex", re.compile(r"^(?=.*\d)[0-9a-f]{16,}$", re.I)),
    ("email", re.compile(r"^[^@/]+@[^@/]+\.[a-z]{2,}$", re.I)),
]
LITERAL = re.compile(r"^(v\d+(\.\d+)*|api|rest|graphql|gql|odata|rpc)$", re.I)
WORDLIKE = re.compile(r"^[a-z]+([-_][a-z]+)*$")  # resource names; never collapsed by cardinality
TYPES = {"int": ("integer", None), "uuid": ("string", "uuid"), "date": ("string", "date"), "email": ("string", "email")}
STATIC_EXT = {"js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot", "otf",
              "webp", "avif", "mp4", "webm", "mp3", "pdf", "txt"}
API_PATH = re.compile(r"(^|/)(api|rest|graphql|gql|odata|rpc|jsonrpc|services|v\d+(\.\d+)*)(/|$)", re.I)
API_EXT = {"asmx", "svc", "ashx", "jws", "json", "xml"}
STATIC_PATH = re.compile(r"/(static|assets|_next/static|wp-content|wp-includes|images|img|css|js|fonts|media)/", re.I)
BROWSER_UA = re.compile(r"mozilla/", re.I)


@dataclass
class Config:
    collapse_threshold: int = 10  # distinct literal values at one position before it becomes a parameter
    min_hits: int = 5  # evidence floor for a confirmed endpoint
    overrides: dict[str, list[str]] = field(default_factory=dict)  # host -> ["/api/users/{username}", ...]


def normalize(path: str) -> tuple[list[str], list[str]]:
    """-> (segments, sorted query parameter names)."""
    parts = urlsplit(path if path.startswith("/") or "://" in path else "/" + path)
    p = re.sub(r";jsessionid=[^/?#]*", "", unquote(parts.path), flags=re.I)
    segs = [s for s in p.split("/") if s]
    return segs, sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})


def mask(seg: str) -> tuple[str, str]:
    if LITERAL.match(seg):
        return ("lit", seg)
    for name, rx in MASKS:
        if rx.match(seg):
            return ("param", name)
    if len(seg) >= 16 and _entropy(seg) >= 3.5 and re.search(r"\d", seg) and re.search(r"[a-zA-Z]", seg) and "." not in seg:
        return ("param", "token")
    return ("lit", seg)


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


class _Node:
    __slots__ = ("children", "collapsed")

    def __init__(self):
        self.children: dict[tuple[str, str], _Node] = {}
        self.collapsed = False


def _merge(a: _Node, b: _Node) -> None:
    for k, child in b.children.items():
        if k in a.children:
            _merge(a.children[k], child)
        else:
            a.children[k] = child


def _collapse(node: _Node, threshold: int) -> None:
    lits = [k for k in node.children if k[0] == "lit" and not LITERAL.match(k[1])]
    if len(lits) >= threshold and sum(not WORDLIKE.match(k[1]) for k in lits) >= 0.8 * len(lits):
        target = node.children.setdefault(("param", "string"), _Node())
        for k in lits:
            _merge(target, node.children.pop(k))
        node.collapsed = True
    for child in node.children.values():
        _collapse(child, threshold)


def _override_rx(template: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\\\{[^/]+?\\\}", "[^/]+", re.escape(template.rstrip("/") or "/")) + "/?$")


@dataclass
class _Agg:
    hits: int = 0
    first: str | None = None
    last: str | None = None
    statuses: Counter = field(default_factory=Counter)
    ctypes: set = field(default_factory=set)
    qparams: set = field(default_factory=set)
    agents: Counter = field(default_factory=Counter)
    types: list = field(default_factory=list)
    samples: list = field(default_factory=list)


def discover(observations: Iterable[dict], cfg: Config | None = None) -> list[dict]:
    """Aggregate observations into endpoint dicts (host, method, template, kind, hits, ...)."""
    cfg = cfg or Config()
    obs = []
    for o in observations:
        host = (o.get("host") or "").lower().split(":")[0]
        if not host or not o.get("method"):
            continue
        segs, qnames = normalize(o.get("path") or "/")
        obs.append((host, o["method"].upper(), segs, qnames, o))

    overrides = {h.lower(): [(t, _override_rx(t)) for t in ts] for h, ts in cfg.overrides.items()}
    tries: dict[str, _Node] = {}
    for host, _, segs, _, _ in obs:
        node = tries.setdefault(host, _Node())
        for s in segs:
            node = node.children.setdefault(mask(s), _Node())
    for t in tries.values():
        _collapse(t, cfg.collapse_threshold)

    aggs: dict[tuple, _Agg] = {}
    for host, method, segs, qnames, o in obs:
        raw = "/" + "/".join(segs)
        fixed = next((t for t, rx in overrides.get(host, []) if rx.match(raw)), None)
        if fixed:
            key, types = tuple(fixed.strip("/").split("/")) if fixed.strip("/") else (), []
        else:
            node, toks, types = tries[host], [], []
            for s in segs:
                k = mask(s)
                if k not in node.children and node.collapsed and k[0] == "lit":
                    k = ("param", "string")
                node = node.children[k]
                toks.append(k[1] if k[0] == "lit" else None)
                if k[0] == "param":
                    types.append(k[1])
            key = tuple(toks)
        a = aggs.setdefault((host, method, key), _Agg())
        n = int(o.get("hits") or 1)
        a.hits += n
        for attr, ts, pick in (("first", "first_seen", min), ("last", "last_seen", max)):
            if v := o.get(ts) or o.get("time"):
                cur = getattr(a, attr)
                setattr(a, attr, pick(cur, str(v)) if cur else str(v))
        if o.get("status"):
            a.statuses[str(o["status"])] += n
        if o.get("content_type"):
            a.ctypes.add(o["content_type"].split(";")[0].strip().lower())
        if o.get("user_agent"):
            a.agents[o["user_agent"]] += n
        a.qparams.update(qnames)
        a.types.append(types)
        if len(a.samples) < 5 and raw not in a.samples:
            a.samples.append(raw)

    out = []
    for (host, method, key), a in aggs.items():
        if a.statuses and set(a.statuses) <= {"404"}:
            continue  # only ever "not found": scanner probes and typos, not an endpoint
        template, params = _name(key, a.types)
        kind, conf = classify(host, method, template, a.ctypes, a.statuses, a.agents)
        out.append({"host": host, "method": method, "template": template, "kind": kind, "confidence": conf,
                    "confirmed": a.hits >= cfg.min_hits, "hits": a.hits, "first_seen": a.first, "last_seen": a.last,
                    "statuses": dict(a.statuses), "content_types": sorted(a.ctypes), "query_params": sorted(a.qparams),
                    "path_params": params, "samples": a.samples})
    return sorted(out, key=lambda e: (e["host"], e["template"], e["method"]))


def _name(key: tuple, types_seen: list[list[str]]) -> tuple[str, dict]:
    """Turn a token tuple (None = parameter) into /users/{user_id} and a name -> type map."""
    if any(t and t.startswith("{") for t in key):  # user override template, already named
        return "/" + "/".join(key), {t[1:-1]: "string" for t in key if t.startswith("{")}
    segs, params, i = [], {}, 0
    for pos, tok in enumerate(key):
        if tok is not None:
            segs.append(tok)
            continue
        kinds = {ts[i] for ts in types_seen if i < len(ts)}
        i += 1
        prev = key[pos - 1] if pos and key[pos - 1] else ""
        base = (prev[:-3] + "y" if prev.endswith("ies") else prev[:-1] if prev.endswith("s") else prev) if WORDLIKE.match(prev) else ""
        name = re.sub(r"[^a-z0-9]+", "_", base.lower()).strip("_")
        name = f"{name}_id" if name else "param"
        while name in params:
            name += "_"
        params[name] = kinds.pop() if len(kinds) == 1 else "string"
        segs.append("{" + name + "}")
    return "/" + "/".join(segs), params


def classify(host: str, method: str, template: str, ctypes: set, statuses: Counter, agents: Counter) -> tuple[str, float]:
    last = template.rsplit("/", 1)[-1]
    ext = last.rsplit(".", 1)[-1].lower() if "." in last and not last.startswith("{") else ""
    ct = " ".join(ctypes)
    if "101" in statuses or re.search(r"/(ws|websocket|socket\.io|signalr|hubs?)(/|$)", template, re.I):
        return "ws", 0.8
    if ext in STATIC_EXT or STATIC_PATH.search(template + "/") or re.search(r"\b(image|font|video|audio)/", ct):
        return "static", 0.9
    if re.search(r"json|xml|grpc|protobuf|ndjson", ct) and "html" not in ct:
        return "api", 0.95
    if API_PATH.search(template) or ext in API_EXT or re.match(r"^(api|apis|rest|gateway)[.-]", host):
        return "api", 0.85
    if "html" in ct:
        return "web", 0.9
    non_browser = agents and sum(n for ua, n in agents.items() if not BROWSER_UA.search(ua)) > sum(agents.values()) / 2
    if method in ("POST", "PUT", "PATCH", "DELETE") or non_browser:
        return "api", 0.6
    if method == "GET":
        return "web", 0.5
    return "unknown", 0.3


def glob_rx(pattern: str) -> re.Pattern:
    """WAF/route glob (`*` = anything incl. '/') -> regex."""
    return re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$", re.I)


def template_rx(template: str) -> re.Pattern:
    """OpenAPI-style template -> regex matching concrete paths."""
    return _override_rx(template)


def openapi(host: str, endpoints: Iterable, kinds: tuple[str, ...] = ("api",)) -> dict:
    """OpenAPI 3.1 document for one host from discovered endpoints (no body schemas: logs carry none)."""
    paths: dict[str, dict] = {}
    for e in endpoints:
        e = e if isinstance(e, dict) else {c: getattr(e, c) for c in ("host", "method", "template", "kind", "hits", "first_seen",
                                                                       "last_seen", "statuses", "query_params", "path_params",
                                                                       "content_types", "confirmed")}
        if e["host"] != host or e["kind"] not in kinds:
            continue
        params = [{"name": n, "in": "path", "required": True, "schema": _schema(t)} for n, t in e["path_params"].items()]
        params += [{"name": q, "in": "query", "required": False, "schema": {"type": "string"}} for q in e["query_params"]]
        ctype = next((c for c in e["content_types"] if "json" in c or "xml" in c), None)
        responses = {s: {"description": "Observed", **({"content": {ctype: {}}} if ctype and s.startswith("2") else {})}
                     for s in sorted(e["statuses"])} or {"default": {"description": "Observed"}}
        op = {"summary": f"Discovered {e['method']} {e['template']}", "responses": responses,
              "x-discovered": True, "x-hit-count": e["hits"], "x-first-seen": e["first_seen"], "x-last-seen": e["last_seen"],
              "x-confirmed": e["confirmed"], "x-kind": e["kind"]}
        if params:
            op["parameters"] = params
        paths.setdefault(e["template"], {})[e["method"].lower()] = op
    return {"openapi": "3.1.0", "info": {"title": f"{host} (discovered)", "version": "discovered"},
            "servers": [{"url": f"https://{host}"}], "paths": dict(sorted(paths.items()))}


def _schema(t: str) -> dict:
    typ, fmt = TYPES.get(t, ("string", None))
    return {"type": typ, **({"format": fmt} if fmt else {})}
