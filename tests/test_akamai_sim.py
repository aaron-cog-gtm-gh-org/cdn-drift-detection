import json

import pytest
from fastapi.testclient import TestClient

from sim.akamai_app import app
from sim.fixtures import INDEX

AUTH = {"Authorization": "EG1-HMAC-SHA256 client_token=ct;access_token=at;"
                         "timestamp=2026-01-01T00:00:00+00:00;nonce=n1;signature=abc123"}
WWW_PROP = "prp_512345"
WWW_VER = 47


@pytest.fixture
def client():
    return TestClient(app)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["provider"] == "akamai"


def test_missing_auth(client):
    r = client.get("/papi/v1/properties")
    assert r.status_code == 401
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["status"] == 401


def test_malformed_auth(client):
    r = client.get("/papi/v1/properties",
                   headers={"Authorization": "Bearer whatever"})
    assert r.status_code == 401


def test_auth_right_scheme_missing_signature(client):
    r = client.get("/papi/v1/properties",
                   headers={"Authorization":
                            "EG1-HMAC-SHA256 client_token=ct;access_token=at;"
                            "timestamp=2026-01-01T00:00:00+00:00;nonce=n1"})
    assert r.status_code == 401


def test_list_properties(client):
    r = client.get("/papi/v1/properties", headers=AUTH)
    assert r.status_code == 200
    items = r.json()["properties"]["items"]
    assert {i["propertyId"] for i in items} == {
        "prp_512345", "prp_523001", "prp_534210", "prp_540077"}


def test_list_properties_filtered(client):
    r = client.get("/papi/v1/properties",
                   params={"contractId": "ctr_C-0N7RAC7", "groupId": "grp_98765"},
                   headers=AUTH)
    assert r.status_code == 200
    assert len(r.json()["properties"]["items"]) == 4
    r = client.get("/papi/v1/properties",
                   params={"contractId": "ctr_NOPE", "groupId": "grp_98765"},
                   headers=AUTH)
    assert r.json()["properties"]["items"] == []


def test_list_properties_partial_query_400(client):
    r = client.get("/papi/v1/properties",
                   params={"contractId": "ctr_C-0N7RAC7"}, headers=AUTH)
    assert r.status_code == 400
    assert r.headers["content-type"] == "application/problem+json"


def test_get_property(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}", headers=AUTH)
    assert r.status_code == 200
    items = r.json()["properties"]["items"]
    assert len(items) == 1
    assert items[0]["propertyName"] == "www.rbcdemo.ca"


def test_get_property_404(client):
    r = client.get("/papi/v1/properties/prp_999999", headers=AUTH)
    assert r.status_code == 404
    assert r.headers["content-type"] == "application/problem+json"


def test_rules_verbatim(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}/versions/{WWW_VER}/rules",
                   headers=AUTH)
    assert r.status_code == 200
    fixture = json.loads(
        open("fixtures/akamai/www.rbcdemo.ca/rules.json").read())
    assert r.json() == fixture
    assert r.headers["etag"] == fixture["etag"]


def test_rules_wrong_version_404(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}/versions/1/rules", headers=AUTH)
    assert r.status_code == 404


def test_rules_etag_304(client):
    etag = INDEX.akamai["www.rbcdemo.ca"]["rules"]["etag"]
    r = client.get(f"/papi/v1/properties/{WWW_PROP}/versions/{WWW_VER}/rules",
                   headers={**AUTH, "If-None-Match": etag})
    assert r.status_code == 304
    assert not r.content


def test_hostnames(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}/versions/{WWW_VER}/hostnames",
                   headers=AUTH)
    assert r.status_code == 200
    item = r.json()["hostnames"]["items"][0]
    assert item["cnameFrom"] == "www.rbcdemo.ca"
    assert item["cnameTo"].endswith(".edgekey.net")


def test_prefix_stripping(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}",
                   headers={**AUTH, "PAPI-Use-Prefixes": "false"})
    item = r.json()["properties"]["items"][0]
    assert item["propertyId"] == "512345"
    assert item["contractId"] == "C-0N7RAC7"
    assert item["groupId"] == "98765"


def test_prefix_default_verbatim(client):
    r = client.get(f"/papi/v1/properties/{WWW_PROP}", headers=AUTH)
    assert r.json()["properties"]["items"][0]["propertyId"] == WWW_PROP


def test_appsec_export(client):
    r = client.get("/appsec/v1/export/configs/90010/versions/17", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["configName"].startswith("www.rbcdemo.ca")


def test_appsec_list_configs(client):
    r = client.get("/appsec/v1/configs", headers=AUTH)
    assert r.status_code == 200
    configs = r.json()["configurations"]
    assert len(configs) == 3
    by_name = {c["name"]: c for c in configs}
    api_cfg = by_name["api.rbcdemo.ca security config"]
    assert api_cfg["id"] == 90012
    assert api_cfg["latestVersion"] == 9
    assert api_cfg["productionHostnames"] == ["api.rbcdemo.ca"]
    assert {"id", "name", "latestVersion", "stagingVersion",
            "productionVersion", "productionHostnames"} <= set(configs[0])


def test_appsec_export_404(client):
    assert client.get("/appsec/v1/export/configs/99999/versions/1",
                      headers=AUTH).status_code == 404
    assert client.get("/appsec/v1/export/configs/90010/versions/999",
                      headers=AUTH).status_code == 404
