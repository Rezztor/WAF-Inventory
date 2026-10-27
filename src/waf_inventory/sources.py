"""Sources managed in the console: their fields, credentials from the vault, connection tests and errors in plain words."""
from __future__ import annotations

import glob
import os
import re
import ssl
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from . import azure, f5, vault
from .models import SourceConfig


class Field(NamedTuple):
    key: str
    label: str
    kind: str  # text | list | int | bool | secret | choice
    help: str = ""
    required: bool = False
    choices: tuple[tuple[str, str], ...] = ()


AZURE_AUTH = (("certificate", "Certificate made by this app (recommended)"), ("secret", "Client secret"),
              ("default", "This machine's Azure login (az login or environment variables)"))
TYPES: dict[str, tuple[str, list[Field]]] = {
    "azure": ("Azure Application Gateway and Front Door", [
        Field("tenant_id", "Tenant ID", "text", "Directory (tenant) ID of the app registration", True),
        Field("client_id", "Client ID", "text", "Application (client) ID of the app registration", True),
        Field("auth", "Sign in with", "choice", "", True, AZURE_AUTH),
        Field("client_secret", "Client secret", "secret", "Only for client secret sign-in: the secret's Value, not its ID"),
        Field("subscriptions", "Subscriptions", "list", "One subscription ID per line. Empty: every subscription the app can read"),
        Field("log_workspaces", "Log Analytics workspaces", "list",
              "Workspace IDs (GUIDs) receiving App Gateway / Front Door access logs, one per line. Empty: configuration only"),
        Field("log_days", "Days of access logs", "int", "", True),
    ]),
    "f5_rest": ("F5 BIG-IP (iControl REST)", [
        Field("host", "Management address", "text", "IP address or hostname, with :port if not 443", True),
        Field("username", "Username", "text", "A read-only account with the Auditor role", True),
        Field("password", "Password", "secret", "", True),
        Field("export", "Read ASM policies with the declarative export (TMOS 15.1+)", "bool"),
    ]),
    "f5_offline": ("F5 BIG-IP (offline files)", [
        Field("path", "Folder on the server", "text", "Holds bigip.conf and ASM policy JSON exports", True)]),
    "azure_bundle": ("Azure (offline bundle file)", [
        Field("path", "Bundle file on the server", "text", "JSON saved with waf-inv collect --save-raw", True)]),
    "logs": ("Access logs (files)", [
        Field("path", "Files on the server", "text", "A glob of JSONL or CSV files, e.g. logs/*.jsonl", True)]),
}
DEFAULTS = {"azure": {"auth": "certificate", "log_days": 30}, "f5_rest": {"export": True}}
PATH_TYPES = {"f5_offline", "azure_bundle", "logs"}


def secret_state(sc: SourceConfig | None) -> dict[str, dict]:
    """kind -> {updated, meta} for the secrets this source has, never their values."""
    return {x.kind: {"updated": x.updated, "meta": x.meta} for x in (sc.secrets if sc else [])}


def apply_form(sc: SourceConfig, form: dict[str, str]) -> list[str]:
    """Copy form values onto the source. Blank secret fields keep the stored value. Returns problems found."""
    errors, settings = [], dict(sc.settings or {})
    for f in TYPES[sc.type][1]:
        v = form.get(f.key, "").strip()
        if f.kind == "secret":
            if v:
                vault.put(sc, f.key, v)
            continue
        if f.kind == "list":
            settings[f.key] = [x for x in re.split(r"[\s,]+", v) if x]
        elif f.kind == "int":
            settings[f.key] = int(v) if v.isdigit() else v
            if not v.isdigit():
                errors.append(f"{f.label} must be a whole number")
        elif f.kind == "bool":
            settings[f.key] = f.key in form
        elif f.kind == "choice" and v not in dict(f.choices):
            errors.append(f"Choose {f.label.lower()}")
        else:
            settings[f.key] = v
        if f.required and not v and f.kind != "bool":
            errors.append(f"{f.label} is required")
    sc.settings = settings
    if sc.type == "azure" and settings.get("auth") == "secret" and not secret_state(sc).get("client_secret"):
        errors.append("Client secret is required for client secret sign-in")
    if sc.type == "f5_rest" and not secret_state(sc).get("password"):
        errors.append("Password is required")
    return sorted(set(errors), key=errors.index)


# ---------------------------------------------------------------- credentials

def make_azure_certificate(sc: SourceConfig) -> None:
    """RSA key + self-signed certificate (12 months) for the app registration. Only the public part is ever shown."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"waf-inventory {sc.name}")])
    t = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(t - timedelta(minutes=5))
            .not_valid_after(t + timedelta(days=365)).sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    vault.put(sc, "certificate", key_pem + cert_pem, meta={
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),  # the thumbprint Azure shows is SHA-1
        "expires": cert.not_valid_after_utc.date().isoformat(), "cert_pem": cert_pem})


def azure_credential(sc: SourceConfig):
    from azure.identity import CertificateCredential, ClientSecretCredential, DefaultAzureCredential
    st = sc.settings
    if st.get("auth") == "default":
        return DefaultAzureCredential()
    if st.get("auth") == "secret":
        return ClientSecretCredential(st["tenant_id"], st["client_id"], vault.get(sc, "client_secret") or "")
    pem = vault.get(sc, "certificate")
    if not pem:
        raise ValueError("No certificate yet: generate one on the source's page and upload the .cer to the app registration")
    return CertificateCredential(st["tenant_id"], st["client_id"], certificate_data=pem.encode())


def f5_client(sc: SourceConfig, timeout: float = 120) -> f5.F5Client:
    password = vault.get(sc, "password")
    if not password:
        raise ValueError("No password saved for this source")
    st = sc.settings
    return f5.F5Client(st["host"], st["username"], password, ca_cert=st.get("ca_pem"), timeout=timeout)


def fetch_certificate(host: str) -> dict:
    """The certificate the device presents now, for the admin to compare and trust."""
    u = urlsplit(f"https://{host}")
    pem = ssl.get_server_certificate((u.hostname, u.port or 443), timeout=10)
    c = x509.load_pem_x509_certificate(pem.encode())
    return {"pem": pem, "fingerprint": c.fingerprint(hashes.SHA256()).hex(":").upper(), "subject": c.subject.rfc4514_string(),
            "expires": c.not_valid_after_utc.date().isoformat()}


# ---------------------------------------------------------------- collect, test, explain

def resolve(cfg: dict, p: str) -> Path:
    return Path(p) if Path(p).is_absolute() else cfg["_dir"] / p


def collect(s: Session, cfg: dict, sc: SourceConfig, log: Callable[[str], None]) -> str:
    from .cli import collect_source
    src = {"name": sc.name, "type": sc.type, **sc.settings}
    credential = azure_credential(sc) if sc.type == "azure" else None
    password = vault.get(sc, "password") if sc.type == "f5_rest" else None
    if sc.type == "f5_rest" and not password:
        raise ValueError("No password saved for this source")
    return collect_source(s, cfg, src, credential=credential, password=password, log=log)


def test(cfg: dict, sc: SourceConfig) -> list[str]:
    """Sign in and read a little. Returns what was found; raises on the first thing that does not work."""
    st = sc.settings
    if sc.type == "azure":
        arm = azure.Arm(azure_credential(sc), httpx.Client(timeout=30))
        subs = {x["subscriptionId"]: x["displayName"] for x in arm.list("/subscriptions", azure.API["subscriptions"])}
        out = [f"Signed in. Readable subscriptions: {', '.join(f'{n} ({i})' for i, n in subs.items()) or 'none'}."]
        if not subs:
            out.append("Give the app registration the Reader role on each subscription to inventory.")
        out += [f"Not readable: {sid}. Check the ID, or give the app Reader on it." for sid in st.get("subscriptions", []) if sid not in subs]
        for ws in st.get("log_workspaces", []):
            arm.query_logs(ws, "print ok=1", 1)
            out.append(f"Log Analytics workspace {ws}: readable.")
        return out
    if sc.type == "f5_rest":
        c = f5_client(sc, timeout=20)
        c.login()
        try:
            return [f"Signed in to {st['host']}. BIG-IP {f5.device_version(c) or 'version unknown'}."]
        finally:
            c.logout()
    p = resolve(cfg, st["path"])
    if sc.type == "logs":
        files = glob.glob(str(p))
        if not files:
            raise ValueError(f"No files match {p}")
        return [f"{len(files)} file(s) match {p}."]
    if not p.exists():
        raise ValueError(f"{p} does not exist on the server")
    return [f"Found {p}."]


AADSTS = {
    "AADSTS700016": "no app with that client ID in this tenant. Check the tenant ID and client ID.",
    "AADSTS90002": "tenant not found. Check the tenant ID.",
    "AADSTS7000215": "the client secret is wrong. Enter the secret's Value, not its Secret ID.",
    "AADSTS7000222": "the client secret has expired. Create a new one and enter it here.",
    "AADSTS700027": "Azure does not accept this certificate. Upload the .cer from this page to the app registration "
                    "(Certificates & secrets > Certificates).",
}


def explain(e: Exception, sc: SourceConfig | None = None) -> str:
    """One line a person can act on. Never a stack trace."""
    if isinstance(e, vault.VaultError | ValueError):
        return str(e)
    if isinstance(e, FileNotFoundError):
        return f"Not found on the server: {e.filename}"
    if "Unable to get authority configuration" in str(e):
        return "Azure sign-in failed: tenant not found. Check the tenant ID."
    if type(e).__name__ == "ClientAuthenticationError" or "AADSTS" in str(e):
        code = re.search(r"AADSTS\d+", str(e))
        return "Azure sign-in failed: " + (AADSTS.get(code.group(), str(e).splitlines()[0]) if code else str(e).splitlines()[0])
    if isinstance(e, httpx.ConnectError) and "CERTIFICATE_VERIFY_FAILED" in str(e):
        return "The device's certificate is not trusted. Use Fetch certificate, compare the fingerprint, then trust it."
    if isinstance(e, ssl.SSLError | httpx.ConnectError | httpx.ConnectTimeout | OSError) and not isinstance(e, httpx.HTTPStatusError):
        return f"Cannot connect ({e}). Check the address, the port and any firewall in between."
    if isinstance(e, httpx.TimeoutException):
        return "No answer in time. The device or service may be overloaded; try again."
    if isinstance(e, httpx.HTTPStatusError):
        code, url = e.response.status_code, e.request.url
        if sc is not None and sc.type == "f5_rest":
            if code == 401:
                return "401 from the BIG-IP: check the username and password."
            if code == 403:
                return f"403 from the BIG-IP on {url.path}: the account lacks a role for this. Auditor covers everything read."
        if url.host == azure.LOGS.removeprefix("https://"):
            if code == 403:
                return "No access to the Log Analytics workspace: give the app the Log Analytics Reader role on it."
            if code in (400, 404):
                return "Log Analytics workspace not found: use the workspace ID (a GUID), not its name."
        if code == 403:
            return f"403 from Azure on {url.path}: give the app registration the Reader role there."
        return f"HTTP {code} from {url.host}{url.path}"
    return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------- import

def import_config(s: Session, cfg: dict) -> int:
    """First start only: copy config.toml sources into the console. Passwords are read from their environment variables."""
    if s.query(SourceConfig.id).first() or not cfg.get("sources"):
        return 0
    for src in cfg["sources"]:
        st = {k: v for k, v in src.items() if k not in ("name", "type", "password_env", "ca_cert")}
        sc = SourceConfig(name=src["name"], type=src["type"], settings=st)
        if src["type"] in PATH_TYPES:
            st["path"] = str(resolve(cfg, src["path"]))
        if src["type"] == "azure":
            st.setdefault("auth", "default")
        if src.get("ca_cert"):
            st["ca_pem"] = Path(src["ca_cert"]).read_text()
            st["ca_fingerprint"] = x509.load_pem_x509_certificate(st["ca_pem"].encode()).fingerprint(hashes.SHA256()).hex(":").upper()
        if src["type"] == "f5_rest" and (pw := os.environ.get(src.get("password_env", "F5_PASSWORD"))):
            vault.put(sc, "password", pw)
        s.add(sc)
    s.commit()
    return len(cfg["sources"])
