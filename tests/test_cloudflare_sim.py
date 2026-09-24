import pytest
from fastapi.testclient import TestClient

from sim.cloudflare_app import app
from sim.fixtures import INDEX

AUTH = {"Authorization": "Bearer demo-token"}
WWW_ZONE = INDEX.cf["www.rbcdemo.ca"]["zone"]["result"]["id"]


@pytest.fixture
def client():
    return TestClient(app)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["provider"] == "cloudflare"


def test_missing_auth_400(client):
    r = client.get("/client/v4/zones")
    assert r.status_code == 400
    body = r.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 6003


def test_wrong_token_403(client):
    r = client.get("/client/v4/zones",
                   headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403
    assert r.json()["errors"][0]["code"] == 9109


def test_list_zones_by_name(client):
    r = client.get("/client/v4/zones", params={"name": "api.rbcdemo.ca"},
                   headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert len(body["result"]) == 1
    assert body["result"][0]["name"] == "api.rbcdemo.ca"
    assert "result_info" in body


def test_list_zones_unknown_name(client):
    r = client.get("/client/v4/zones", params={"name": "nope.example"},
                   headers=AUTH)
    assert r.json()["result"] == []


def test_get_zone(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}", headers=AUTH)
    assert r.json()["result"]["name"] == "www.rbcdemo.ca"


def test_get_zone_404(client):
    r = client.get("/client/v4/zones/" + "0" * 32, headers=AUTH)
    assert r.status_code == 404
    assert r.json()["success"] is False


def test_settings_verbatim(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/settings", headers=AUTH)
    assert r.json() == INDEX.cf["www.rbcdemo.ca"]["settings"]


def test_single_setting(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/settings/min_tls_version",
                   headers=AUTH)
    assert r.status_code == 200
    assert r.json()["result"]["value"] == "1.2"


def test_single_setting_404(client):
    # assets omits http2 entirely (suppression case S-02)
    zid = INDEX.cf["assets.rbcdemo.ca"]["zone"]["result"]["id"]
    r = client.get(f"/client/v4/zones/{zid}/settings/http2", headers=AUTH)
    assert r.status_code == 404
    assert r.json()["success"] is False


def test_rulesets_list_omits_rules(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/rulesets", headers=AUTH)
    body = r.json()
    assert len(body["result"]) == 7
    for rs in body["result"]:
        assert "rules" not in rs
    assert body["result_info"]["total_count"] == 7


def test_ruleset_detail_has_rules(client):
    rsid = INDEX.cf["www.rbcdemo.ca"]["rulesets"]["result"][0]["id"]
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/rulesets/{rsid}", headers=AUTH)
    assert r.status_code == 200
    assert "rules" in r.json()["result"]
    assert len(r.json()["result"]["rules"]) == 2


def test_ruleset_detail_404(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/rulesets/" + "9" * 32,
                   headers=AUTH)
    assert r.status_code == 404


def test_entrypoint(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/rulesets/phases/"
                   "http_request_firewall_managed/entrypoint", headers=AUTH)
    assert r.status_code == 200
    rs = r.json()["result"]
    assert rs["phase"] == "http_request_firewall_managed"
    assert len(rs["rules"]) == 2


def test_entrypoint_404(client):
    r = client.get(f"/client/v4/zones/{WWW_ZONE}/rulesets/phases/"
                   "http_request_late_transform/entrypoint", headers=AUTH)
    assert r.status_code == 404


def test_dns_pagination(client):
    zid = INDEX.cf["online.rbcdemo.ca"]["zone"]["result"]["id"]
    r1 = client.get(f"/client/v4/zones/{zid}/dns_records",
                    params={"page": 1, "per_page": 1}, headers=AUTH)
    b1 = r1.json()
    assert b1["result_info"]["total_count"] == 2
    assert b1["result_info"]["total_pages"] == 2
    r2 = client.get(f"/client/v4/zones/{zid}/dns_records",
                    params={"page": 2, "per_page": 1}, headers=AUTH)
    items = b1["result"] + r2.json()["result"]
    assert len(items) == 2
    names = {i["type"] for i in items}
    assert names == {"CNAME", "TXT"}
