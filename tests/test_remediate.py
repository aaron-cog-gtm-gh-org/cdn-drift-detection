"""remediate.py tests — route grouping, deferral, skips, findings_block."""
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator import remediate


def finding(field, route, provider="akamai", severity="high", note=None):
    return {
        "field": field, "provider": provider, "severity": severity,
        "equivalence": "semantically_different",
        "golden_value": "gold", "observed_value": "obs",
        "locator": {"provider_path": "$.x", "golden_path": "$.g"},
        "explanation": "they differ",
        "impact": "it matters",
        "remediation_route": route,
        "remediation_note": note,
        "confidence": "high",
    }


def report(domain="online.rbcdemo.ca", verdict="drift_detected", findings=()):
    return {"domain": domain, "golden_sha": "abc123",
            "mapping_version": "2026.09.1", "verdict": verdict,
            "summary": {"fields_compared": 10, "findings_total": len(findings),
                        "by_severity": {}, "by_provider": {}},
            "findings": list(findings)}


def test_grouping_by_route():
    r = report(findings=[
        finding("tls.min_version", "iac_pr"),
        finding("waf.managed", "iac_pr"),
        finding("cors.x", "provider_api"),
        finding("auth.y", "human_review"),
    ])
    plan = remediate.plan_remediation(r, "run-1", "golden-branch")
    routes = {s["route"] for s in plan["sessions"]}
    assert routes == {"iac_pr", "human_review"}
    iac = next(s for s in plan["sessions"] if s["route"] == "iac_pr")
    assert "Findings routed to you (2)" in iac["prompt"]
    assert "golden-branch" in iac["prompt"]
    human = next(s for s in plan["sessions"] if s["route"] == "human_review")
    assert "needing human judgment (1)" in human["prompt"]
    assert "route:iac_pr" in iac["tags"] and "route:human_review" in human["tags"]
    assert "domain:online.rbcdemo.ca" in iac["tags"]
    # provider_api produces NO session — deferred instead
    assert [d["field"] for d in plan["deferred"]] == ["cors.x"]
    assert "out of scope until phase 04" in plan["deferred"][0]["note"]


def test_zero_finding_route_no_session():
    r = report(findings=[finding("a", "iac_pr")])
    plan = remediate.plan_remediation(r, "r", "b")
    assert {s["route"] for s in plan["sessions"]} == {"iac_pr"}
    assert plan["deferred"] == []


def test_inconclusive_domain_skipped():
    r = report(verdict="inconclusive",
               findings=[finding("a", "iac_pr")])
    plan = remediate.plan_remediation(r, "r", "b")
    assert plan["skipped"] is True
    assert plan["sessions"] == []


def test_findings_block_readable_not_json():
    block = remediate.findings_block([
        finding("tls.min_version", "iac_pr", note="set to 1.2")])
    assert "`tls.min_version`" in block
    assert "golden   : gold" in block
    assert "observed : obs" in block
    assert "$.x" in block and "$.g" in block
    assert "severity high" in block
    assert "set to 1.2" in block
    assert not block.lstrip().startswith("{")  # not raw JSON


def test_execute_creates_child_sessions():
    requests = []

    def h(req):
        requests.append(req)
        return httpx.Response(200, json={"session_id": f"c{len(requests)}"})
    from orchestrator.devin_client import DevinClient
    client = DevinClient("https://x/api", "org", "tok",
                         http_client=httpx.Client(transport=httpx.MockTransport(h)))
    r = report(findings=[finding("a", "iac_pr"), finding("b", "human_review")])
    plan = remediate.plan_remediation(r, "run-9", "golden-branch")
    created = remediate.execute_remediation(
        [plan], client, repo="org/repo", max_acu_limit=5, devin_mode="normal",
        parent_ids={"online.rbcdemo.ca": "parent-1"})
    assert len(created) == 2
    for req in requests:
        assert req.url.params.get("devin_id") == "parent-1"
    assert {c["route"] for c in created} == {"iac_pr", "human_review"}
