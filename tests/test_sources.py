"""Sources managed in the console: encrypted credentials, forms, tests, jobs, certificates, import."""
import shutil
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from conftest import PASSWORD, add, csrf, wait
from cryptography import x509
from cryptography.fernet import Fernet

from waf_inventory import f5, report, sources, tls, vault
from waf_inventory.cli import load_config, main
from waf_inventory.models import Job, Secret, SourceConfig, connect


def test_vault_encrypts_and_needs_the_key(master_key, tmp_path, monkeypatch):
    sc = SourceConfig(name="x", type="f5_rest", settings={})
    vault.put(sc, "password", "s3cret-Pa55")
    assert "s3cret" not in sc.secrets[0].token and vault.get(sc, "password") == "s3cret-Pa55"
    master_key.write_text(Fernet.generate_key().decode() + "\n" + master_key.read_text())  # new key first, old still reads
    assert vault.get(sc, "password") == "s3cret-Pa55"
    master_key.write_text(Fernet.generate_key().decode())
    with pytest.raises(vault.VaultError, match="different master key"):
        vault.get(sc, "password")
    monkeypatch.setenv("WAF_INV_MASTER_KEY_FILE", str(tmp_path / "missing"))
    with pytest.raises(vault.VaultError, match="master key unreadable"):
        vault.put(sc, "password", "x")


def test_demo_sources_added_tested_and_collected_from_the_browser(console):
    c = console
    ids = [add(c, "azure_bundle", name="azure-sample", path="azure/bundle.json"),
           add(c, "f5_offline", name="bigip-offline", path="f5"),
           add(c, "logs", name="logs", path="logs/*.jsonl")]
    for sid in ids:
        r = c.post(f"/sources/{sid}/test", data={"csrf": csrf(c)})
        assert "Connection works." in r.text, r.text
        job = c.post(f"/sources/{sid}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"]
        assert "Findings recomputed" in wait(c, job)
    with connect(c.db) as s:
        assert {j.status for j in s.query(Job)} == {"ok"}
        assert {"no-waf", "shadow-api", "detection-mode"} <= {f["rule"] for f in report.table(s, "findings")}
    assert "partners.contoso.com" in c.get("/t/applications").text
    page = c.get("/sources").text
    assert page.count('class="pill ok">Working') == 3 and "Run now" in page
    # a broken path is reported in plain words, on the job and on the source list
    bad = add(c, "f5_offline", name="broken", path="nowhere")
    assert "does not exist on the server" in c.post(f"/sources/{bad}/test", data={"csrf": csrf(c)}).text
    job = c.post(f"/sources/{bad}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"]
    assert "Not found on the server" in wait(c, job) and "broken: last run failed" in c.get("/sources").text


def test_f5_password_is_write_only_and_encrypted(console):
    c = console
    assert "Password is required" in c.post("/sources/new/f5_rest", data={
        "csrf": csrf(c), "name": "bigip", "host": "192.0.2.10", "username": "auditor"}).text
    sid = add(c, "f5_rest", name="bigip", host="192.0.2.10", username="auditor", password="Very-Secret-Pw1", export="on")
    page = c.get(f"/sources/{sid}").text
    assert "Very-Secret-Pw1" not in page and "Leave blank to keep the saved value" in page and "Fetch certificate" in page
    r = c.post(f"/sources/{sid}", data={"csrf": csrf(c), "host": "192.0.2.11", "username": "auditor", "password": ""},
               follow_redirects=False)
    assert r.status_code == 303
    with connect(c.db) as s:
        sc = s.query(SourceConfig).one()
        assert sc.settings == {"host": "192.0.2.11", "port": 443, "username": "auditor", "token": False, "export": False,
                               "schedule": {"every": "off", "at": "02:00", "day": 0, "tz": "UTC"}, "next_run": None}
        assert vault.get(sc, "password") == "Very-Secret-Pw1"  # blank field kept it
    assert b"Very-Secret-Pw1" not in open(c.db, "rb").read()


def test_azure_certificate_is_made_here_and_only_the_public_part_leaves(console):
    c = console
    sid = add(c, "azure", name="azure-prod", tenant_id="11111111-1111-1111-1111-111111111111",
              client_id="22222222-2222-2222-2222-222222222222", auth="certificate", subscriptions="aaa\nbbb", log_days="30")
    page = c.get(f"/sources/{sid}").text
    assert "Thumbprint" in page and "PRIVATE KEY" not in page
    cer = x509.load_der_x509_certificate(c.get(f"/sources/{sid}/azure/certificate.cer").content)
    with connect(c.db) as s:
        sc = s.get(SourceConfig, sid)
        assert sc.settings["subscriptions"] == ["aaa", "bbb"]
        assert cer.fingerprint(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA1"]).SHA1()).hex().upper() == \
            sources.secret_state(sc)["certificate"]["meta"]["thumbprint"]
        assert type(sources.azure_credential(sc)).__name__ == "CertificateCredential"
        assert "PRIVATE KEY" not in s.query(Secret).one().token


def test_delete_needs_the_password_and_removes_inventory(console):
    c = console
    sid = add(c, "f5_offline", name="bigip-offline", path="f5")
    wait(c, c.post(f"/sources/{sid}/run", data={"csrf": csrf(c)}, follow_redirects=False).headers["location"])
    assert c.post(f"/sources/{sid}/delete", data={"csrf": csrf(c), "password": "wrong"}).status_code == 403
    assert c.post(f"/sources/{sid}/delete", data={"csrf": csrf(c), "password": PASSWORD}, follow_redirects=False).status_code == 303
    with connect(c.db) as s:
        assert report.table(s, "sources") == [] and not s.query(SourceConfig).count()
    assert c.post(f"/sources/{sid}/run", data={"csrf": "x"}).status_code == 403  # CSRF before anything else


class _Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_f5_certificate_fetch_trust_and_pin(console, tmp_path):
    cert, key = tls.ensure_cert(tmp_path / "dev")
    other, _ = tls.ensure_cert(tmp_path / "other")
    srv = HTTPServer(("127.0.0.1", 0), _Hello)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = f"127.0.0.1:{srv.server_port}"
    try:
        fetched = sources.fetch_certificate(host)
        assert fetched["fingerprint"] == tls.fingerprint(cert)
        assert f5.F5Client(host, "u", "p", ca_cert=fetched["pem"], timeout=5).http.get("/").status_code == 200  # pinned: accepted
        with pytest.raises(httpx.ConnectError) as e:
            f5.F5Client(host, "u", "p", ca_cert=other.read_text(), timeout=5).http.get("/")
        assert "certificate is not trusted" in sources.explain(e.value)

        c = console
        sid = add(c, "f5_rest", name="bigip", host=host, username="auditor", password="pw-123456789")
        page = c.post(f"/sources/{sid}/f5/fetch-cert", data={"csrf": csrf(c)}).text
        assert fetched["fingerprint"] in page and "trust this certificate" in page
        bad = c.post(f"/sources/{sid}/f5/trust-cert", data={"csrf": csrf(c), "pem": other.read_text(), "fingerprint": fetched["fingerprint"]})
        assert bad.status_code == 400
        c.post(f"/sources/{sid}/f5/trust-cert", data={"csrf": csrf(c), "pem": fetched["pem"], "fingerprint": fetched["fingerprint"]})
        with connect(c.db) as s:
            assert s.get(SourceConfig, sid).settings["ca_fingerprint"] == fetched["fingerprint"]
    finally:
        srv.shutdown()


def test_errors_in_plain_words():
    f5src = SourceConfig(name="b", type="f5_rest", settings={})

    def status(code, url):
        req = httpx.Request("GET", url)
        return httpx.HTTPStatusError("x", request=req, response=httpx.Response(code, request=req))
    assert "check the username and password" in sources.explain(status(401, "https://bigip/mgmt/shared/authn/login"), f5src)
    assert "Reader role" in sources.explain(status(403, "https://management.azure.com/subscriptions/x/providers"))
    assert "Log Analytics Reader" in sources.explain(status(403, "https://api.loganalytics.io/v1/workspaces/w/query"))
    assert "Secret ID" in sources.explain(RuntimeError("AADSTS7000215: Invalid client secret provided."))
    assert "Check the tenant ID" in sources.explain(RuntimeError("Authentication failed: Unable to get authority configuration for x"))


def test_config_toml_sources_are_imported_once(tmp_path, master_key, monkeypatch):
    pem = tmp_path / "bigip.pem"
    tls.ensure_cert(tmp_path / "t")
    shutil.copy(tmp_path / "t" / "cert.pem", pem)
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'''database = "{tmp_path / 'x.db'}"
[[sources]]
name = "bigip"
type = "f5_rest"
host = "192.0.2.1"
username = "auditor"
password_env = "F5_X"
ca_cert = "{pem}"
[[sources]]
name = "logs"
type = "logs"
path = "logs/*.jsonl"
''')
    monkeypatch.setenv("F5_X", "from-the-env-123")
    conf = load_config(str(cfg))
    with connect(str(tmp_path / "x.db")) as s:
        assert sources.import_config(s, conf) == 2 and sources.import_config(s, conf) == 0
        bigip, logs = s.query(SourceConfig).order_by(SourceConfig.name).all()
        assert vault.get(bigip, "password") == "from-the-env-123" and bigip.settings["ca_fingerprint"] == tls.fingerprint(pem)
        assert "password_env" not in bigip.settings and logs.settings["path"] == str(tmp_path / "logs/*.jsonl")
    # with sources in the database, the CLI collects those and records jobs
    assert main(["-c", str(cfg), "collect", "--source", "logs"]) == 1  # no log files there: recorded as a failed job
    with connect(str(tmp_path / "x.db")) as s:
        job = s.query(Job).one()
        assert job.trigger == "cli" and job.status == "error"
