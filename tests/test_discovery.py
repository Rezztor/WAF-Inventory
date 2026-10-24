from waf_inventory import discovery as d


def obs(host, method, path, **kw):
    return {"host": host, "method": method, "path": path, **kw}


def templates(eps):
    return {(e["method"], e["template"]) for e in eps}


def test_typed_masks():
    rows = [obs("a.com", "GET", p) for p in ("/orders/123", "/orders/9f0e3c4a-2b1d-4c5e-8f9a-0123456789ab",
                                             "/files/5f2b9c1e8d7a6b5c4d3e2f1a", "/day/2026-10-01", "/u/jane.doe@example.com/x")]
    eps = d.discover(rows)
    assert templates(eps) == {("GET", "/orders/{order_id}"), ("GET", "/files/{file_id}"),
                              ("GET", "/day/{day_id}"), ("GET", "/u/{u_id}/x")}
    types = {e["template"]: e["path_params"] for e in eps}
    assert types["/files/{file_id}"] == {"file_id": "hex"} and types["/day/{day_id}"] == {"day_id": "date"}
    by = {e["template"]: e for e in eps}
    assert by["/orders/{order_id}"]["path_params"] == {"order_id": "string"}  # int + uuid seen: one endpoint, generic type
    assert by["/u/{u_id}/x"]["path_params"] == {"u_id": "email"}


def test_cardinality_collapse_but_not_resource_names():
    rows = [obs("a.com", "GET", f"/sku/AB-{i:04d}X") for i in range(12)]
    rows += [obs("a.com", "GET", f"/api/{r}") for r in ("users", "orders", "products", "carts", "invoices", "payments",
                                                         "refunds", "shipments", "returns", "reviews", "coupons", "stores")]
    eps = d.discover(rows)
    assert ("GET", "/sku/{sku_id}") in templates(eps)
    assert ("GET", "/api/users") in templates(eps) and len(eps) == 13  # 12 word-like names are kept literal
    below = d.discover(rows[:9])  # under the threshold nothing collapses
    assert len(below) == 9


def test_query_values_dropped_and_aggregation():
    rows = [obs("A.com:443", "get", "/api/v1/items?token=SECRET&page=2", hits=3, status=200, first_seen="2026-10-02"),
            obs("a.com", "GET", "/api/v1/items/?page=1&sort=x", hits=4, status=500, last_seen="2026-10-09"),
            obs("a.com", "GET", "/api//v1/items;jsessionid=ABC", hits=1, status=200),
            obs("a.com", "GET", "https://a.com/api/v1/items", hits=0)]  # full URL in the log; hits 0 counts as 1
    (e,) = d.discover(rows)
    assert (e["host"], e["method"], e["template"]) == ("a.com", "GET", "/api/v1/items")
    assert e["hits"] == 9 and e["statuses"] == {"200": 4, "500": 4}
    assert e["query_params"] == ["page", "sort", "token"]
    assert "SECRET" not in str(e) and "ABC" not in str(e)
    assert (e["first_seen"], e["last_seen"]) == ("2026-10-02", "2026-10-09")


def test_overrides_and_evidence_floor():
    rows = [obs("a.com", "GET", f"/users/{n}/profile") for n in ("alice", "bob", "carol")]
    eps = d.discover(rows, d.Config(overrides={"a.com": ["/users/{username}/profile"]}, min_hits=5))
    (e,) = eps
    assert e["template"] == "/users/{username}/profile" and e["hits"] == 3 and e["confirmed"] is False
    assert e["path_params"] == {"username": "string"}


def test_classification():
    c = d.classify
    assert c("a.com", "GET", "/static/app.js", set(), {}, {})[0] == "static"
    assert c("a.com", "GET", "/logo.svg", {"image/svg+xml"}, {}, {})[0] == "static"
    assert c("a.com", "GET", "/x", {"application/json"}, {}, {})[0] == "api"
    assert c("a.com", "POST", "/svc/Billing.asmx", set(), {}, {})[0] == "api"
    assert c("a.com", "GET", "/v2/things", set(), {}, {})[0] == "api"
    assert c("a.com", "GET", "/ws/feed", set(), {"101": 1}, {})[0] == "ws"
    assert c("a.com", "GET", "/about", {"text/html"}, {}, {})[0] == "web"
    assert c("a.com", "POST", "/submit", set(), {}, {"okhttp": 5})[0] == "api"
    assert c("a.com", "GET", "/page", set(), {}, {"Mozilla/5.0": 5}) == ("web", 0.5)


def test_openapi_document():
    eps = d.discover([obs("a.com", "GET", f"/api/orders/{i}?expand=1", status=200, content_type="application/json") for i in range(3)]
                     + [obs("a.com", "GET", "/", content_type="text/html")])
    doc = d.openapi("a.com", eps)
    assert doc["openapi"] == "3.1.0" and doc["servers"] == [{"url": "https://a.com"}]
    assert list(doc["paths"]) == ["/api/orders/{order_id}"]  # web pages excluded by default
    op = doc["paths"]["/api/orders/{order_id}"]["get"]
    assert {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}} in op["parameters"]
    assert {"name": "expand", "in": "query", "required": False, "schema": {"type": "string"}} in op["parameters"]
    assert op["responses"]["200"]["content"] == {"application/json": {}} and op["x-hit-count"] == 3


def test_glob_and_template_regex():
    assert d.glob_rx("/api/v1/employees/*").match("/api/v1/employees/12/x")
    assert not d.glob_rx("/api/v1/employees").match("/api/v1/employees/12")
    assert d.template_rx("/orders/{id}").match("/orders/5") and not d.template_rx("/orders/{id}").match("/orders/5/x")
