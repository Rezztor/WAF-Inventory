"""Sign-in, sessions, CSRF, back-off, admin bootstrap and the HTTPS certificate."""
import io
from datetime import timedelta

import pytest
from conftest import PASSWORD
from cryptography import x509
from fastapi.testclient import TestClient

from waf_inventory import auth, tls
from waf_inventory.cli import main
from waf_inventory.models import LoginSession, connect
from waf_inventory.web import create_app


def test_everything_needs_sign_in_except_login_and_healthz(client, demo_db):
    anon = TestClient(create_app(demo_db))
    r = anon.get("/t/findings?severity=high", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=/t/findings%3Fseverity%3Dhigh"
    assert anon.get("/export/inventory.xlsx", follow_redirects=False).status_code == 303
    assert anon.post("/logout").status_code == 401
    assert anon.get("/healthz").json() == {"status": "ok"}
    assert "Sign in" in anon.get("/login").text
    r = client.get("/")
    assert r.status_code == 200 and "Sign out" in r.text and "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_login_errors_are_generic_and_next_is_local_only(demo_db, monkeypatch):
    monkeypatch.setattr(auth, "_fails", {})
    c = TestClient(create_app(demo_db))
    with connect(demo_db) as s:
        auth.set_password(s, "admin", PASSWORD)
    wrong = c.post("/login", data={"username": "admin", "password": "nope"})
    unknown = c.post("/login", data={"username": "ghost", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401 and "Wrong username or password." in wrong.text and "Wrong username or password." in unknown.text
    r = c.post("/login", data={"username": "admin", "password": PASSWORD, "next": "//evil.example/x"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_back_off_after_five_failures(demo_db, monkeypatch):
    monkeypatch.setattr(auth, "_fails", {})
    c = TestClient(create_app(demo_db))
    for _ in range(5):
        c.post("/login", data={"username": "admin", "password": "wrong"})
    r = c.post("/login", data={"username": "admin", "password": PASSWORD})
    assert r.status_code == 429 and "Too many failed sign-ins" in r.text  # blocked even with the right password


def test_logout_needs_csrf_and_ends_the_session(client):
    assert client.post("/logout", data={"csrf": "forged"}).status_code == 403
    assert client.post("/logout", data={}, headers={"origin": "https://evil.example"}).status_code == 403
    csrf = client.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    assert client.post("/logout", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_idle_session_expires(client, demo_db):
    with connect(demo_db) as s:
        for ls in s.query(LoginSession):
            ls.last_seen -= auth.IDLE + timedelta(seconds=1)
        s.commit()
    assert client.get("/", follow_redirects=False).status_code == 303


def test_reset_password_and_serve_refuses_without_admin(tmp_path, monkeypatch):
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'database = "{tmp_path / "x.db"}"\n')
    with pytest.raises(SystemExit, match="No admin account"):
        main(["-c", str(cfg), "serve"])
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit, match="at least 12"):
        main(["-c", str(cfg), "reset-password", "admin", "--password-stdin"])
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert main(["-c", str(cfg), "reset-password", "admin", "--password-stdin"]) == 0
    with connect(str(tmp_path / "x.db")) as s:
        assert auth.authenticate(s, "admin", PASSWORD) and not auth.authenticate(s, "admin", "x" * 12)


def test_self_signed_then_internal_ca_certificate(tmp_path):
    cert, key = tls.ensure_cert(tmp_path)
    first = tls.fingerprint(cert)
    assert key.stat().st_mode & 0o077 == 0 and tls.ensure_cert(tmp_path) == (cert, key)
    csr = x509.load_pem_x509_csr(tls.make_csr(tmp_path, ["waf.corp.example"], ["10.0.0.5"]))
    with pytest.raises(ValueError, match="does not match"):
        tls.install_cert(tmp_path, cert.read_bytes())
    # sign the CSR with a throwaway CA, as the internal CA would
    from datetime import datetime, timezone

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Corp CA")])
    t = datetime.now(timezone.utc)
    leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca).public_key(csr.public_key())
            .serial_number(1).not_valid_before(t).not_valid_after(t + timedelta(days=90))
            .add_extension(csr.extensions[0].value, critical=False).sign(ca_key, hashes.SHA256()))
    new = tls.install_cert(tmp_path, leaf.public_bytes(serialization.Encoding.PEM))
    assert new != first and tls.fingerprint(cert) == new and not (tmp_path / "csr-key.pem").exists()
