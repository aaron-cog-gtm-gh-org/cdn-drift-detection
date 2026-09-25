"""Cross-provider classifier tests — unit cases per bucket plus a
regression asserting the real fixtures produce exactly the documented
seven findings."""
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from drift.sources import DiskSource, DOMAINS
import validate_cross_drift as vc

MAPPING = yaml.safe_load(
    (REPO / "mapping" / "akamai-cloudflare-mapping.yaml").read_text())


def field(fid):
    return next(f for f in MAPPING["fields"] if f["id"] == fid)


def classify_field(fid, domain, a_vals=None, c_vals=None,
                   akamai_doc=None, cloudflare_doc=None):
    """Classify one field with canned docs (defaults: empty docs)."""
    f = field(fid)
    a_fn = f.get("akamai", {}).get("fixture", "rules")
    c_fn = f.get("cloudflare", {}).get("fixture", "settings")
    docs = {("akamai", a_fn): akamai_doc or {},
            ("cloudflare", c_fn): cloudflare_doc or {}}
    return vc.classify_field(f, domain, docs, MAPPING)


def test_disagreement_real_fixture():
    src = DiskSource()
    f = field("tls.min_version")
    docs = {("akamai", "rules"): src.get("akamai", "rules",
                                         "online.rbcdemo.ca"),
            ("cloudflare", "settings"): src.get("cloudflare", "settings",
                                                "online.rbcdemo.ca")}
    r = vc.classify_field(f, "online.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "disagreement"
    assert r["severity"] == "critical"


def test_missing_at_cloudflare_real_fixture():
    src = DiskSource()
    f = field("headers.security_static")
    docs = {("akamai", "rules"): src.get("akamai", "rules",
                                         "online.rbcdemo.ca"),
            ("cloudflare", "rulesets"): src.get("cloudflare", "rulesets",
                                                "online.rbcdemo.ca")}
    r = vc.classify_field(f, "online.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "missing_at_cloudflare"
    assert r["cloudflare"] == [] and r["akamai"] == ["nosniff"]


def test_not_comparable_unsupported_side():
    r = classify_field("http.enhanced_protocol", "www.rbcdemo.ca")
    assert r["bucket"] == "not_comparable"
    assert r["reason"] == "unsupported_at_cloudflare"


def test_not_comparable_neither_configured():
    # both paths resolve to nothing on an empty doc -> not_comparable,
    # never a phantom missing finding
    r = classify_field("caching.default_ttl", "www.rbcdemo.ca")
    assert r["bucket"] == "not_comparable"
    assert r["reason"] == "provider_specific"


def test_equivalent_but_different_semantic():
    # Akamai "TLSV1_2" vs Cloudflare "1.2" — different text, same value
    f = field("tls.min_version")
    docs = {("akamai", "rules"): {"rules": {"behaviors": [
        {"name": "origin", "options": {"minTlsVersion": "TLSV1_2"}}]}},
        ("cloudflare", "settings"): {"result": [
            {"id": "min_tls_version", "value": "1.2"}]}}
    r = vc.classify_field(f, "www.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "equivalent" and r["different"] is True


def test_equivalent_textually_identical():
    f = field("waf.managed_ruleset_enabled")
    docs = {("akamai", "rules"): {"rules": {"behaviors": [
        {"name": "webApplicationFirewall", "options": {"enable": True}}]}},
        ("cloudflare", "rulesets"): {"result": [{
            "phase": "http_request_firewall_managed",
            "rules": [{"description": "Execute Cloudflare Managed Ruleset",
                       "enabled": True}]}]}}
    r = vc.classify_field(f, "www.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "equivalent" and r["different"] is False


def test_ordered_comparator_degenerates_to_equality():
    # numeric_ge was "observed >= golden"; as peers, strictness must match
    # in both directions — 86400 vs 31536000 is a disagreement, not ">= ok"
    f = field("tls.hsts_max_age")
    docs = {("akamai", "rules"): {"rules": {"behaviors": [{
        "options": {"customHeaderName": "Strict-Transport-Security",
                    "customHeaderValue": "max-age=86400"}}]}},
        ("cloudflare", "rulesets"): {"result": [{
            "phase": "http_response_headers_transform",
            "rules": [{"description": "HSTS", "action_parameters": {
                "headers": {"Strict-Transport-Security": {
                    "value": "max-age=31536000"}}}}]}]}}
    r = vc.classify_field(f, "www.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "disagreement"


def test_cloudflare_default_counts_as_present_not_missing():
    # assets omits http2; defaults.cloudflare_settings supplies "on" and
    # Akamai's True is bool-equal — neither missing nor disagreement
    src = DiskSource()
    f = field("http.http2")
    docs = {("akamai", "rules"): src.get("akamai", "rules",
                                         "assets.rbcdemo.ca"),
            ("cloudflare", "settings"): src.get("cloudflare", "settings",
                                                "assets.rbcdemo.ca")}
    r = vc.classify_field(f, "assets.rbcdemo.ca", docs, MAPPING)
    assert r["bucket"] == "equivalent" and r["different"] is True


def test_expected_seven_findings_on_real_fixtures():
    results = vc.classify(DOMAINS, DiskSource(), MAPPING)
    findings = [r for r in results if r["bucket"] in vc.FINDING_BUCKETS]
    got = {(r["domain"], r["field"], r["bucket"], r["severity"])
           for r in findings}
    want = {(e["domain"], e["field"], e["bucket"], e["severity"])
            for e in vc.EXPECTED}
    assert got == want
