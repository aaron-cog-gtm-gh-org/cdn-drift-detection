"""Load the phase-01 fixtures and index them by the identifiers the provider
APIs actually address: propertyId/propertyVersion/configId/version for Akamai,
zoneId/name for Cloudflare."""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOMAINS = [
    "www.rbcdemo.ca",
    "online.rbcdemo.ca",
    "api.rbcdemo.ca",
    "assets.rbcdemo.ca",
]


def _load(path):
    return json.loads(Path(path).read_text())


class FixtureIndex:
    def __init__(self, repo=REPO):
        self.repo = Path(repo)
        self.properties = _load(self.repo / "fixtures/akamai/properties.json")
        self.by_property = {}       # propertyId -> domain
        self.property_meta = {}     # propertyId -> properties.json item
        for item in self.properties["properties"]["items"]:
            self.by_property[item["propertyId"]] = item["propertyName"]
            self.property_meta[item["propertyId"]] = item

        self.akamai = {}            # domain -> {"rules":doc, "hostnames":doc, "appsec":doc|None}
        self.appsec_by_config = {}  # (configId, version) -> doc
        for d in DOMAINS:
            base = self.repo / "fixtures" / "akamai" / d
            entry = {"rules": _load(base / "rules.json"),
                     "hostnames": _load(base / "hostnames.json"),
                     "appsec": None}
            ap = base / "appsec.json"
            if ap.exists():
                entry["appsec"] = _load(ap)
                v = entry["appsec"]["configVersion"]
                self.appsec_by_config[(entry["appsec"]["configId"], v)] = entry["appsec"]
            self.akamai[d] = entry

        self.cf = {}                # domain -> {"zone":..,"settings":..,"rulesets":..,"dns":..}
        self.zone_by_id = {}
        self.zone_by_name = {}
        for d in DOMAINS:
            base = self.repo / "fixtures" / "cloudflare" / d
            entry = {"zone": _load(base / "zone.json"),
                     "settings": _load(base / "settings.json"),
                     "rulesets": _load(base / "rulesets.json"),
                     "dns_records": _load(base / "dns_records.json")}
            self.cf[d] = entry
            self.zone_by_id[entry["zone"]["result"]["id"]] = d
            self.zone_by_name[d] = d


INDEX = FixtureIndex()
