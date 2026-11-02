import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cryptography.fernet import Fernet

from waf_inventory import auth
from waf_inventory.cli import load_config, main
from waf_inventory.models import connect
from waf_inventory.web import create_app

PASSWORD = "correct horse battery"

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(scope="session")
def demo_db(tmp_path_factory) -> str:
    """The full demo collected once: Azure bundle + F5 offline + sample logs."""
    d = tmp_path_factory.mktemp("demo")
    shutil.copytree(EXAMPLES, d, dirs_exist_ok=True)
    cfg = d / "demo.toml"
    cfg.write_text(cfg.read_text().replace('database = "demo.db"', f'database = "{d / "t.db"}"'))
    assert main(["-c", str(cfg), "collect"]) == 0
    return str(d / "t.db")


@pytest.fixture
def session(demo_db):
    s = connect(demo_db)
    yield s
    s.close()


@pytest.fixture
def client(demo_db) -> TestClient:
    """Dashboard client signed in as admin."""
    with connect(demo_db) as s:
        auth.set_password(s, "admin", PASSWORD)
    c = TestClient(create_app(demo_db))
    assert c.post("/login", data={"username": "admin", "password": PASSWORD}).status_code == 200
    return c


@pytest.fixture
def master_key(tmp_path, monkeypatch):
    key = tmp_path / "master_key"
    key.write_text(Fernet.generate_key().decode() + "\n")
    monkeypatch.setenv("WAF_INV_MASTER_KEY_FILE", str(key))
    return key


@pytest.fixture
def console(tmp_path, master_key, monkeypatch):
    """A fresh signed-in console over a copy of the examples folder (its demo.toml gives discovery settings)."""
    monkeypatch.setattr(auth, "_fails", {})
    d = tmp_path / "site"
    shutil.copytree(EXAMPLES, d)
    cfg = load_config(str(d / "demo.toml"))
    db = str(d / "console.db")
    with connect(db) as s:
        auth.set_password(s, "admin", PASSWORD)
    c = TestClient(create_app(db, cfg))
    c.post("/login", data={"username": "admin", "password": PASSWORD})
    c.db, c.dir = db, d
    return c


def csrf(c: TestClient, url: str = "/sources") -> str:
    return c.get(url).text.split('name="csrf" value="')[1].split('"')[0]


def add(c: TestClient, kind: str, **fields) -> int:
    r = c.post(f"/sources/new/{kind}", data={"csrf": csrf(c), **fields}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].split("/")[2].split("?")[0])


def wait(c: TestClient, job_url: str) -> str:
    for _ in range(200):
        page = c.get(job_url).text
        if "refreshes every 2 seconds" not in page:
            return page
        time.sleep(0.05)
    raise AssertionError("job did not finish")
