"""F5 BIG-IP (LTM + ASM / Advanced WAF): live iControl REST, read-only tmsh over SSH, or offline bigip.conf + ASM policy JSON exports.

Both paths produce the same intermediate `cfg` dict, which `build()` turns into the vendor-neutral model:
  device       {"hostname", "version"}
  virtuals     [{"name", "destination", "pool", "profiles", "policies", "rules", "enabled"}]
  pools        {pool: [member, ...]}
  ltm_policies {policy: [{"name", "conditions": [{"kind", "op", "values", "not"}], "actions": [{"asm", "policy"} | {"pool"}]}]}
  irules       {rule: tcl text}
  client_ssl   {profile: {"server_name"}}
  http_profiles [profile, ...]
  asm          {policy: {"mode", "active", "virtual_servers", "export": declarative JSON | None}}
"""
from __future__ import annotations

import json
import re
import ssl
import time
from collections.abc import Callable
from pathlib import Path

import httpx

from .models import Gateway, Listener, Route, WafPolicy

ASM_MODE = {"blocking": "block", "transparent": "detect"}
CHUNK = 1024 * 1024  # ASM file-transfer downloads are capped at 1 MB per request


# ---------------------------------------------------------------- live: iControl REST

def address(host: str, port: int | None) -> str:
    """host[:port] for the management interface; a port already written in the host wins."""
    return host if not port or port == 443 or re.search(r":\d+$", host) else f"{host}:{port}"


class F5Client:
    def __init__(self, host: str, username: str, password: str, ca_cert: str | None = None,
                 http: httpx.Client | None = None, timeout: float = 120, token: bool = True):
        if http is None:
            verify: ssl.SSLContext | bool = True
            if ca_cert:  # pin the device's own (usually self-signed) management certificate: a PEM file path or PEM text
                pem = ca_cert.lstrip().startswith("-----BEGIN")
                verify = ssl.create_default_context(cadata=ca_cert if pem else None, cafile=None if pem else ca_cert)
                verify.check_hostname = False
                verify.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # the pinned certificate is the trust anchor
                verify.verify_flags &= ~ssl.VERIFY_X509_STRICT  # BIG-IP default certificates predate the strict profile
            http = httpx.Client(base_url=f"https://{host}", verify=verify, timeout=timeout)
        self.http, self.username, self.password, self.token, self.use_token = http, username, password, None, token

    def login(self) -> None:
        if not self.use_token:  # basic auth on every call, for devices where token sign-in is turned off
            self.http.auth = (self.username, self.password)
            return
        r = self.http.post("/mgmt/shared/authn/login",
                           json={"username": self.username, "password": self.password, "loginProviderName": "tmos"})
        r.raise_for_status()
        self.token = r.json()["token"]["token"]
        self.http.headers["X-F5-Auth-Token"] = self.token

    def logout(self) -> None:
        if self.token:
            self.http.delete(f"/mgmt/shared/authz/tokens/{self.token}")
            self.token = None

    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        for attempt in range(4):  # restjavad answers 503 when overloaded
            r = self.http.request(method, path, **kw)
            if r.status_code != 503:
                r.raise_for_status()
                return r
            time.sleep(2 ** attempt)
        r.raise_for_status()
        return r

    def get(self, path: str, **params) -> dict:
        return self._req("GET", path, params=params or None).json()

    def items(self, path: str, **params) -> list[dict]:
        out, body = [], self.get(path, **params)
        while True:
            out += body.get("items", [])
            nxt = body.get("nextLink")
            if not nxt:
                return out
            body = self._req("GET", nxt.replace("https://localhost", "")).json()

    def export_policy(self, policy_id: str, timeout: float = 300) -> dict:
        """Declarative JSON export (TMOS 15.1+): start task, poll, download in 1 MB Content-Range chunks."""
        fname = f"waf-inventory-{policy_id}.json"
        task = self._req("POST", "/mgmt/tm/asm/tasks/export-policy", json={
            "filename": fname, "format": "json", "minimal": False,
            "policyReference": {"link": f"https://localhost/mgmt/tm/asm/policies/{policy_id}"}}).json()
        deadline = time.monotonic() + timeout
        while (status := self.get(f"/mgmt/tm/asm/tasks/export-policy/{task['id']}").get("status")) not in ("COMPLETED", "FAILURE"):
            if time.monotonic() > deadline:
                raise TimeoutError(f"ASM export of {policy_id} still {status}")
            time.sleep(2)
        if status == "FAILURE":
            raise RuntimeError(f"ASM export of {policy_id} failed")
        data, start, size = b"", 0, None
        while True:
            end = start + CHUNK - 1 if size is None else min(start + CHUNK - 1, size - 1)
            r = self._req("GET", f"/mgmt/tm/asm/file-transfer/downloads/{fname}",
                          headers={"Content-Range": f"{start}-{end}/{size or 0}", "Content-Type": "application/octet-stream"})
            data += r.content
            total = r.headers.get("Content-Range", "").rsplit("/", 1)[-1]
            size = int(total) if total.isdigit() else len(data)
            start = len(data)
            if start >= size:
                break
        return json.loads(data)  # a truncated download fails loudly here

    def policy_subcollections(self, policy_id: str, name: str, mode: str) -> dict:
        """Fallback when the account may not run export tasks: rebuild the export shape from GETs."""
        base = f"/mgmt/tm/asm/policies/{policy_id}"
        pol = {"name": name, "enforcementMode": mode, "source": "rest-subcollections"}
        for key in ("urls", "methods", "filetypes", "parameters", "headers", "cookies", "whitelist-ips", "signature-sets"):
            try:
                pol[key] = self.items(f"{base}/{key}")
            except httpx.HTTPStatusError:
                pass
        try:
            pol["blocking-settings"] = {"violations": [{**v, "name": v.get("name") or v.get("description")}
                                                       for v in self.items(f"{base}/blocking-settings/violations")]}
        except httpx.HTTPStatusError:
            pass
        for s in pol.get("signature-sets", []):
            s.setdefault("name", (s.get("signatureSetReference") or {}).get("link", "").rsplit("/", 1)[-1].split("?")[0])
        return {"policy": pol}


def _kebab(d: dict) -> dict:
    return {re.sub(r"(?<!^)(?=[A-Z])", "-", k).lower(): v for k, v in d.items()}


def device_version(c: F5Client) -> str:
    ver = next(iter(c.get("/mgmt/tm/sys/version").get("entries", {}).values()), {})
    ver = ver.get("nestedStats", {}).get("entries", {})
    return " ".join(ver.get(k, {}).get("description", "") for k in ("Version", "Build")).strip()


def fetch_rest(c: F5Client, export: bool = True) -> tuple[dict, list[str]]:
    """Read the whole device. Returns (cfg, warnings)."""
    warnings: list[str] = []
    gs = c.get("/mgmt/tm/sys/global-settings")
    cfg = {
        "device": {"hostname": gs.get("hostname"), "version": device_version(c)},
        "virtuals": [], "pools": {}, "ltm_policies": {}, "irules": {}, "client_ssl": {}, "http_profiles": [], "asm": {}}
    for v in c.items("/mgmt/tm/ltm/virtual", expandSubcollections="true"):
        cfg["virtuals"].append({
            "name": v["fullPath"], "destination": v.get("destination", ""), "pool": v.get("pool"),
            "profiles": [p["fullPath"] for p in v.get("profilesReference", {}).get("items", [])],
            "policies": [p["fullPath"] for p in v.get("policiesReference", {}).get("items", [])],
            "rules": v.get("rules", []), "enabled": not v.get("disabled", False)})
    for p in c.items("/mgmt/tm/ltm/pool", expandSubcollections="true"):
        cfg["pools"][p["fullPath"]] = [m.get("fullPath") or m["name"] for m in p.get("membersReference", {}).get("items", [])]
    for p in c.items("/mgmt/tm/ltm/policy", expandSubcollections="true"):
        if p["fullPath"].startswith("/Common/Drafts/") or p.get("status") == "draft":
            continue
        cfg["ltm_policies"][p["fullPath"]] = sorted((
            _rule(r["name"], [_kebab(x) for x in r.get("conditionsReference", {}).get("items", [])],
                  [_kebab(x) for x in r.get("actionsReference", {}).get("items", [])], r.get("ordinal"))
            for r in p.get("rulesReference", {}).get("items", [])), key=lambda r: r["ordinal"])
    cfg["irules"] = {r["fullPath"]: r.get("apiAnonymous", "") for r in c.items("/mgmt/tm/ltm/rule")}
    cfg["client_ssl"] = {p["fullPath"]: {"server_name": p.get("serverName")} for p in c.items("/mgmt/tm/ltm/profile/client-ssl")}
    cfg["http_profiles"] = [p["fullPath"] for p in c.items("/mgmt/tm/ltm/profile/http")]

    provisioned = {p["name"]: p.get("level") for p in c.items("/mgmt/tm/sys/provision")}
    if provisioned.get("asm", "none") == "none":
        return cfg, warnings
    for p in c.items("/mgmt/tm/asm/policies", **{"$select": "id,name,fullPath,enforcementMode,active,virtualServers,type"}):
        if p.get("type") == "parent":
            continue
        info = {"mode": p.get("enforcementMode"), "active": p.get("active", True),
                "virtual_servers": p.get("virtualServers", []), "export": None}
        if export:
            try:
                info["export"] = c.export_policy(p["id"])
            except (httpx.HTTPStatusError, RuntimeError, TimeoutError, json.JSONDecodeError) as e:
                warnings.append(f"{p['fullPath']}: export failed ({e}); using REST subcollections")
                info["export"] = c.policy_subcollections(p["id"], p["name"], p.get("enforcementMode"))
        cfg["asm"][p["fullPath"]] = info
    return cfg, warnings


# ---------------------------------------------------------------- offline: bigip.conf / tmsh list output

def _tmsh_items(text: str) -> list:
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[{}]|\n|[^\s{}"]+', re.sub(r"(?m)^\s*#.*$", "", text))
    pos = 0

    def block() -> list:
        nonlocal pos
        items, words = [], []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == "\n" or t == "}":
                if words:
                    items.append((words, None))
                    words = []
                if t == "}":
                    return items
            elif t == "{":
                items.append((words, block()))
                words = []
            else:
                words.append(t[1:-1] if t.startswith('"') else t)
        if words:
            items.append((words, None))
        return items

    return block()


def _d(items: list | None) -> dict:
    """tmsh block -> dict. Bare words become flags (True); nested blocks stay raw for the caller."""
    out = {}
    for words, children in items or []:
        if children is not None:
            out[" ".join(words)] = children
        elif words:
            out[words[0]] = True if len(words) == 1 else words[1] if len(words) == 2 else words[1:]
    return out


def _words(items: list | None) -> list[str]:
    return [w for words, _ in items or [] for w in words]


NAMED = ("ltm virtual", "ltm pool", "ltm policy", "ltm profile client-ssl", "ltm profile http", "asm policy")


def parse_conf(text: str) -> dict:
    """Parse bigip.conf / `tmsh list ... recursive` text. iRule bodies are kept verbatim."""
    irules, rest, last = {}, [], 0
    for m in re.finditer(r"(?m)^ltm rule (\S+) \{", text):  # iRules are Tcl: cut them out before tokenizing
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        irules[_full(m.group(1))] = text[m.end():i - 1].strip()
        rest.append(text[last:m.start()])
        last = i
    rest.append(text[last:])
    objs: dict[str, dict] = {}
    for words, children in _tmsh_items("".join(rest)):
        if children is None:
            continue
        head = " ".join(words)
        kind = next((k for k in NAMED if head.startswith(k + " ")), None)
        name = _full(words[-1]) if kind else ""
        objs.setdefault(kind or head, {})[name] = _d(children)
    version = re.search(r"#TMSH-VERSION:\s*(\S+)", text)
    return {"objs": objs, "irules": irules, "version": version.group(1) if version else None}


def load_offline(path: str | Path) -> dict:
    """Directory with *.conf / *.txt (tmsh output) and ASM declarative exports (*.json), or a single .conf file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(2, "No such file or directory", str(path))
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    text = "\n".join(f.read_text(errors="replace") for f in files if f.suffix in (".conf", ".txt"))
    return from_conf(text, path.stem, [json.loads(f.read_text()) for f in files if f.suffix == ".json"])


SSH_LISTS = ("sys global-settings", "ltm virtual", "ltm pool", "ltm policy", "ltm rule", "ltm profile client-ssl", "ltm profile http")


def ssh_version(run: Callable[[str], tuple[int, str]]) -> tuple[str, str | None]:
    """How to call tmsh for this account ("tmsh -q -c" from bash, or bare when tmsh is the login shell) and the version."""
    for prefix in ("tmsh -q -c ", ""):
        status, out = run(prefix + '"show sys version"' if prefix else "show sys version")
        if status == 0 and (m := re.search(r"(?m)^\s*Version\s+(\S+)", out)):
            build = re.search(r"(?m)^\s*Build\s+(\S+)", out)
            return prefix, f"{m.group(1)} {build.group(1)}" if build else m.group(1)
    raise ValueError("tmsh did not answer 'show sys version'. Give the account the Auditor role and tmsh or bash terminal access")


def fetch_ssh(run: Callable[[str], tuple[int, str]]) -> tuple[dict, list[str]]:
    """Read the device with read-only tmsh list commands over SSH; tmsh prints the same syntax as bigip.conf."""
    prefix, version = ssh_version(run)
    texts, warnings = [], []
    for what in (*SSH_LISTS, "asm policy"):
        cmd = f"cd /; list {what} recursive" if what != "sys global-settings" else f"list {what}"
        status, out = run(f'{prefix}"{cmd}"' if prefix else cmd)
        if status:  # e.g. ASM not provisioned
            warnings.append(f"tmsh list {what}: {out.strip().splitlines()[0] if out.strip() else f'exit {status}'}")
            continue
        texts.append(out)
    cfg = from_conf("\n".join(texts), "bigip", [])
    cfg["device"]["version"] = version
    return cfg, warnings


def only_partitions(cfg: dict, partitions: list[str]) -> dict:
    """Keep the objects in these partitions (all when empty)."""
    if not partitions:
        return cfg
    keep = tuple(f"/{p.strip('/')}/" for p in partitions)
    return {**cfg, "virtuals": [v for v in cfg["virtuals"] if v["name"].startswith(keep)],
            **{k: {n: v for n, v in cfg[k].items() if n.startswith(keep)} for k in ("pools", "ltm_policies", "asm")}}


def from_conf(text: str, fallback_name: str, exports: list[dict]) -> dict:
    parsed = parse_conf(text)
    o = parsed["objs"]
    gs = o.get("sys global-settings", {}).get("", {})
    cfg = {
        "device": {"hostname": gs.get("hostname") or fallback_name, "version": parsed["version"]},
        "virtuals": [], "pools": {}, "ltm_policies": {}, "irules": parsed["irules"], "asm": {},
        "client_ssl": {n: {"server_name": d.get("server-name")} for n, d in o.get("ltm profile client-ssl", {}).items()},
        "http_profiles": list(o.get("ltm profile http", {})),
    }
    for name, d in o.get("ltm virtual", {}).items():
        cfg["virtuals"].append({"name": name, "destination": d.get("destination", ""),
                                "pool": _full(d["pool"]) if d.get("pool") else None,
                                "profiles": [_full(x) for x in _d(d.get("profiles"))],
                                "policies": [_full(x) for x in _d(d.get("policies"))],
                                "rules": [_full(x) for x in _words(d.get("rules"))], "enabled": "disabled" not in d})
    for name, d in o.get("ltm pool", {}).items():
        cfg["pools"][name] = [_full(m) for m in _d(d.get("members"))]
    for name, d in o.get("ltm policy", {}).items():
        if name.startswith("/Common/Drafts/"):
            continue
        rules = []
        for rname, r in _d(d.get("rules")).items():
            r = _d(r)
            conds = [{**_d(c), "values": _words(_d(c).get("values"))} for c in _d(r.get("conditions")).values()]
            rules.append(_rule(rname, conds, [_d(a) for a in _d(r.get("actions")).values()], r.get("ordinal")))
        cfg["ltm_policies"][name] = sorted(rules, key=lambda r: r["ordinal"])  # first-match order
    for name, d in o.get("asm policy", {}).items():
        cfg["asm"][name] = {"mode": "blocking" if d.get("blocking-mode") == "enabled" else "transparent",
                            "active": bool(d.get("active")), "export": None,
                            "virtual_servers": [_full(v) for v in _words(d.get("virtual-servers"))]}
    for exp in exports:
        pol = exp.get("policy", {})
        full = pol.get("fullPath") or f"/Common/{pol.get('name')}"
        info = cfg["asm"].setdefault(full, {"mode": pol.get("enforcementMode"), "active": True, "virtual_servers": []})
        info["export"] = exp
    return cfg


def _rule(name: str, conditions: list[dict], actions: list[dict], ordinal=0) -> dict:
    conds = []
    for c in conditions:
        kind = "host" if c.get("http-host") else "uri" if c.get("http-uri") else None
        if kind and c.get("values"):
            op = next((o for o in ("starts-with", "ends-with", "contains") if c.get(o)), "equals")
            conds.append({"kind": kind, "op": op, "values": list(c["values"]), "not": bool(c.get("not"))})
    acts = []
    for a in actions:
        if a.get("asm"):
            acts.append({"asm": "disable" if a.get("disable") else "enable", "policy": _full(a["policy"]) if a.get("policy") else None})
        elif a.get("forward") and a.get("pool"):
            acts.append({"pool": _full(a["pool"])})
    return {"name": name, "conditions": conds, "actions": acts, "ordinal": int(ordinal or 0)}


# ---------------------------------------------------------------- cfg -> model

def _pattern(op: str, v: str) -> str:
    return {"starts-with": f"{v}*", "ends-with": f"*{v}", "contains": f"*{v}*"}.get(op, v)


def _dest(dest: str) -> tuple[str, int | None]:
    s = dest.rsplit("/", 1)[-1]
    addr, _, port = s.rpartition(":") if s.count(":") == 1 else s.rpartition(".")
    return addr, int(port) if port.isdigit() else None


def _full(name: str) -> str:
    """Full /Partition/name path; tmsh prints names relative to the current folder."""
    return name if name.startswith("/") else f"/{name}" if "/" in name else f"/Common/{name}"


def build(cfg: dict) -> tuple[list[Gateway], list[WafPolicy]]:
    pols = {name: normalize_asm(name, info) for name, info in cfg["asm"].items()}
    dev = cfg["device"]
    gw = Gateway(vendor="f5", kind="bigip", name=dev.get("hostname") or "bigip", native_id=dev.get("hostname"),
                 version=dev.get("version"))
    http_profiles = set(cfg.get("http_profiles", [])) | {"/Common/http"}

    def backend(pool):
        return {"name": pool, "members": cfg["pools"].get(pool, [])} if pool else None

    for vs in cfg["virtuals"]:
        addr, port = _dest(vs["destination"])
        profs = set(vs["profiles"])
        ssl_profs = [p for p in profs if p in cfg["client_ssl"]]
        is_http = bool(profs & http_profiles or ssl_profs or any("http" in p.rsplit("/", 1)[-1] for p in profs))
        hosts = {cfg["client_ssl"][p]["server_name"].lower() for p in ssl_profs
                 if cfg["client_ssl"][p].get("server_name") not in (None, "", "none")}
        lst = Listener(name=vs["name"], protocol="https" if ssl_profs else "http" if is_http else "tcp",
                       address=addr, port=port, waf_capable=is_http, native_id=vs["name"])
        default, default_set, ruled = None, False, []
        for pname in vs["policies"]:
            for rule in cfg["ltm_policies"].get(pname, []):
                asm = next((a for a in rule["actions"] if "asm" in a), None)
                pol = pols.get(asm["policy"]) if asm and asm["asm"] == "enable" and asm.get("policy") else None
                hp = [_pattern(c["op"], v.lower()) for c in rule["conditions"] if c["kind"] == "host" and not c["not"] for v in c["values"]]
                up = [_pattern(c["op"], v) for c in rule["conditions"] if c["kind"] == "uri" and not c["not"] for v in c["values"]]
                pool = next((a["pool"] for a in rule["actions"] if "pool" in a), None)
                if not hp and not up:
                    if asm:
                        default, default_set = pol, True
                    continue
                hosts |= set(hp)
                ruled.append((Route(name=f"{pname}:{rule['name']}", hosts=hp, paths=up or ["/*"], backend=backend(pool or vs["pool"])),
                              asm is not None, pol))
        if not default_set:
            for r in vs["rules"]:  # ponytail: iRule logic isn't evaluated; an ASM::enable anywhere counts as protected
                tcl = cfg["irules"].get(r, "")
                if m := re.search(r"ASM::enable\s+([^\s;\]}]+)", tcl):
                    default, default_set = pols.get(_full(m.group(1))), True
                    break
                if "ASM::disable" in tcl:
                    default_set = True
        if not default_set:
            attached = [p for n, p in pols.items() if vs["name"] in cfg["asm"][n].get("virtual_servers", [])]
            default = attached[0] if len(attached) == 1 else None
        lst.policy = default
        for route, explicit, pol in ruled:
            route.policy = pol if explicit else default
            lst.routes.append(route)
        lst.routes.append(Route(name="default", paths=["/*"], backend=backend(vs["pool"]), policy=default))
        lst.hostnames = sorted(hosts)
        gw.listeners.append(lst)
    return [gw], list(pols.values())


def normalize_asm(name: str, info: dict) -> WafPolicy:
    exp = (info.get("export") or {}).get("policy", {})
    active = info.get("active", True)
    mode = ASM_MODE.get(exp.get("enforcementMode") or info.get("mode"), "unknown") if active else "off"
    sigs = exp.get("signatures", [])
    names = lambda key: [x.get("name") for x in exp.get(key, [])]  # noqa: E731
    settings = {
        "export": "declarative" if exp and exp.get("source") != "rest-subcollections" else exp.get("source", "missing"),
        "template": (exp.get("template") or {}).get("name"),
        "learning_mode": (exp.get("policy-builder") or {}).get("learningMode"),
        "allowed_urls": [{"name": u.get("name"), "method": u.get("method", "*"), "type": u.get("type", "explicit"),
                          "protocol": u.get("protocol")} for u in exp.get("urls", [])],
        "allowed_methods": names("methods"),
        "filetypes": names("filetypes"),
        "parameters": names("parameters"),
        "signature_sets": [{"name": s.get("name"), "block": s.get("block"), "alarm": s.get("alarm")} for s in exp.get("signature-sets", [])],
        "signature_staging": (exp.get("signature-settings") or {}).get("signatureStaging"),
        "staged_signatures": sum(1 for s in sigs if s.get("performStaging")),
        "disabled_rules": [str(s.get("signatureId")) for s in sigs if s.get("enabled") is False],
        "violations_not_blocking": [v.get("name") for v in (exp.get("blocking-settings") or {}).get("violations", [])
                                    if v.get("block") is False],
        "ip_lists": [f"{w.get('ipAddress')}/{w.get('ipMask')}" for w in exp.get("whitelist-ips", [])],
        "geo": [g.get("countryName") or g.get("countryCode") for g in (exp.get("geolocation-enforcement") or {}).get("disallowedLocations", [])],
        "data_guard": (exp.get("data-guard") or {}).get("enabled"),
        "brute_force": bool(exp.get("brute-force-attack-preventions")),
        "openapi_files": [o.get("link") or o.get("filename") for o in exp.get("open-api-files", [])],
        "server_technologies": [t.get("serverTechnologyName") for t in exp.get("server-technologies", [])],
    }
    return WafPolicy(vendor="f5", name=name, native_id=name, mode=mode, settings=settings, raw=info.get("export") or {})
