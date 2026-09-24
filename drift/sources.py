"""Fixture document sources, shared by the validator and the orchestrator.

`DiskSource` reads the fixture tree; `ApiSource` fetches the same documents
over the phase-02 simulators' HTTP APIs, discovering every identifier
(propertyId/version, zoneId, appsec configId) over the APIs themselves — a
real run has a domain list and nothing else.
"""
import json
import os
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
DOMAINS = [
    "www.rbcdemo.ca",
    "online.rbcdemo.ca",
    "api.rbcdemo.ca",
    "assets.rbcdemo.ca",
]


def load_json(path):
    return json.loads(Path(path).read_text())


def fixture_path(provider, fixture_name, domain, repo=REPO):
    name = {"rules": "rules.json", "appsec": "appsec.json",
            "hostnames": "hostnames.json"}[fixture_name] if provider == "akamai" \
        else {"settings": "settings.json", "rulesets": "rulesets.json",
              "zone": "zone.json", "dns_records": "dns_records.json"}[fixture_name]
    return Path(repo) / "fixtures" / provider / domain / name


class DiskSource:
    def get(self, provider, fixture_name, domain):
        return load_json(fixture_path(provider, fixture_name, domain))


class ApiSource:
    """Fetch fixture documents over the simulators' HTTP APIs.

    Identifiers are discovered over the APIs themselves, once per run: given
    only a domain name, the propertyId/version comes from the PAPI property
    list, the zone id from `GET /zones?name=`, and the App Sec configId from
    `GET /appsec/v1/configs` — nothing is read off disk."""

    AKAMAI_AUTH = ("EG1-HMAC-SHA256 client_token=sim;access_token=sim;"
                   "timestamp=2026-01-01T00:00:00+00:00;nonce=1;signature=sim")

    def __init__(self, akamai_base, cloudflare_base):
        self.ak = httpx.Client(base_url=akamai_base, timeout=10,
                               headers={"Authorization": self.AKAMAI_AUTH})
        token = os.environ.get("CLOUDFLARE_SIM_TOKEN", "demo-token")
        self.cf = httpx.Client(base_url=cloudflare_base, timeout=10,
                               headers={"Authorization": f"Bearer {token}"})
        self._meta = None
        self.last_url = None  # path of the most recent request, for display

    def discover(self):
        """Resolve domain -> propertyId/version, zoneId, appsec configId once."""
        props = self.ak.get("/papi/v1/properties").json()["properties"]["items"]
        configs = self.ak.get("/appsec/v1/configs").json()["configurations"]
        meta = {}
        for d in DOMAINS:
            prop = next(p for p in props if p["propertyName"] == d)
            z = self.cf.get("/client/v4/zones", params={"name": d}).json()
            cfg = next((c for c in configs if d in c.get("productionHostnames", [])), None)
            meta[d] = {
                "property_id": prop["propertyId"],
                "version": prop["latestVersion"],
                "zone_id": z["result"][0]["id"],
                "config_id": cfg["id"] if cfg else None,
                "config_version": cfg["latestVersion"] if cfg else None,
            }
        return meta

    @property
    def meta(self):
        if self._meta is None:
            self._meta = self.discover()
        return self._meta

    def get(self, provider, fixture_name, domain):
        m = self.meta[domain]
        if provider == "akamai":
            if fixture_name == "rules":
                path = (f"/papi/v1/properties/{m['property_id']}"
                        f"/versions/{m['version']}/rules")
            elif fixture_name == "hostnames":
                path = (f"/papi/v1/properties/{m['property_id']}"
                        f"/versions/{m['version']}/hostnames")
            elif fixture_name == "appsec":
                path = (f"/appsec/v1/export/configs/{m['config_id']}"
                        f"/versions/{m['config_version']}")
            else:
                raise KeyError(fixture_name)
            self.last_url = path
            r = self.ak.get(path)
            r.raise_for_status()
            return r.json()
        zid = m["zone_id"]
        if fixture_name == "zone":
            self.last_url = f"/client/v4/zones/{zid}"
            r = self.cf.get(f"/client/v4/zones/{zid}")
            r.raise_for_status()
            return {"success": True, "errors": [], "messages": [], "result": r.json()["result"]}
        if fixture_name == "settings":
            self.last_url = f"/client/v4/zones/{zid}/settings"
            r = self.cf.get(f"/client/v4/zones/{zid}/settings")
            r.raise_for_status()
            return r.json()
        if fixture_name == "rulesets":
            self.last_url = f"/client/v4/zones/{zid}/rulesets"
            r = self.cf.get(f"/client/v4/zones/{zid}/rulesets")
            r.raise_for_status()
            listing = r.json()["result"]
            full = []
            for rs in listing:
                self.last_url = f"/client/v4/zones/{zid}/rulesets/{rs['id']}"
                d = self.cf.get(f"/client/v4/zones/{zid}/rulesets/{rs['id']}")
                d.raise_for_status()
                full.append(d.json()["result"])
            return {"success": True, "errors": [], "messages": [], "result": full}
        if fixture_name == "dns_records":
            page, items, info = 1, [], None
            while True:
                self.last_url = (f"/client/v4/zones/{zid}/dns_records"
                                 f"?page={page}&per_page=100")
                r = self.cf.get(f"/client/v4/zones/{zid}/dns_records",
                                params={"page": page, "per_page": 100})
                r.raise_for_status()
                body = r.json()
                items.extend(body["result"])
                info = body["result_info"]
                if page >= info["total_pages"]:
                    break
                page += 1
            return {"success": True, "errors": [], "messages": [],
                    "result": items, "result_info": info}
        raise KeyError(fixture_name)
