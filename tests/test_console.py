"""console.py — PlainReporter must emit the exact legacy strings; DemoReporter
must render every method without raising."""
import sys
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator.console import DemoReporter, PlainReporter, make_reporter

REPORT = {
    "domain": "www.rbcdemo.ca", "golden_sha": "abc", "mapping_version": "v",
    "verdict": "drift_detected",
    "summary": {"fields_compared": 12, "findings_total": 2,
                "by_severity": {"critical": 1, "high": 1},
                "by_provider": {"akamai": 1, "cloudflare": 1}},
    "findings": [
        {"field": "tls.min_version", "provider": "cloudflare",
         "severity": "critical", "equivalence": "semantically_different",
         "golden_value": "1.2", "observed_value": "1.0",
         "locator": {"provider_path": "$.x"},
         "explanation": "e", "impact": "i",
         "remediation_route": "iac_pr", "confidence": "high"},
        {"field": "origins.hostname_set", "provider": "akamai",
         "severity": "high", "equivalence": "semantically_different",
         "golden_value": "g", "observed_value": "o",
         "locator": {"provider_path": "$.y"},
         "explanation": "e", "impact": "i",
         "remediation_route": "human_review", "confidence": "high"},
    ],
    "equivalent_but_different": [
        {"field": "tls.hsts_max_age", "provider": "akamai",
         "why_equivalent": "31536000s == 1y"},
    ],
}


def _plain_stdout(fn):
    buf = StringIO()
    with redirect_stdout(buf):
        fn(PlainReporter())
    return buf.getvalue()


def test_plain_session_created_exact():
    out = _plain_stdout(lambda r: r.session_created(
        "www.rbcdemo.ca", "devin-42", "https://x/sessions/devin-42"))
    assert out == "  created www.rbcdemo.ca: devin-42\n"


def test_plain_findings_exact():
    out = _plain_stdout(lambda r: r.findings("www.rbcdemo.ca", REPORT))
    lines = out.splitlines()
    assert lines[0] == ""
    assert lines[1] == ("== www.rbcdemo.ca — verdict: drift_detected "
                        "(2 findings, 12 fields compared) ==")
    f0, f1 = REPORT["findings"]
    assert lines[2] == (f"  {f0['severity']:9s} {f0['provider']:10s} "
                        f"{f0['field']:36s} {f0['equivalence']:22s} -> "
                        f"{f0['remediation_route']}")
    assert lines[3] == (f"  {f1['severity']:9s} {f1['provider']:10s} "
                        f"{f1['field']:36s} {f1['equivalence']:22s} -> "
                        f"{f1['remediation_route']}")


def test_plain_equivalences_exact():
    out = _plain_stdout(lambda r: r.equivalences("www.rbcdemo.ca", REPORT))
    assert out == "  ~equiv    akamai     tls.hsts_max_age\n"


def test_plain_remediation_and_deferred_exact():
    out = _plain_stdout(lambda r: (
        r.remediation("iac_pr", "api.rbcdemo.ca", "devin-9"),
        r.deferred("api.rbcdemo.ca", "cors.x", "provider writes are out of scope")))
    assert out == ("  remediation iac_pr for api.rbcdemo.ca: devin-9\n"
                   "  deferred (provider writes are out of scope): "
                   "api.rbcdemo.ca cors.x\n")


def test_plain_status_and_error_go_to_stderr():
    err = StringIO()
    with redirect_stderr(err):
        PlainReporter().session_status("www.rbcdemo.ca", "running")
        PlainReporter().error("SCHEMA: x")
    assert "    www.rbcdemo.ca: running" in err.getvalue()
    assert "SCHEMA: x" in err.getvalue()


def test_plain_phase_and_artifact_silent():
    out = _plain_stdout(lambda r: (
        r.phase(1, 9, "Golden state"),
        r.artifact("f.json", "/tmp/f.json", sha="abc", nbytes=3),
        r.summary("run", {}, "/tmp")))
    assert out == ""


def _demo():
    from rich.console import Console
    return DemoReporter(console=Console(file=StringIO(), force_terminal=True,
                                        width=100))


def test_demo_every_method_renders():
    r = _demo()
    r.phase(1, 9, "Golden state", subtitle="sub")
    r.step("line")
    r.artifact("www.akamai.json", "/tmp/x.json", sha="abc", nbytes=5)
    r.kv("mapping_version", "v")
    r.fetch("akamai", "rules", "www.rbcdemo.ca", "/papi/v1/properties/x/rules")
    r.session_created("www.rbcdemo.ca", "devin-1",
                      "https://x/sessions/devin-1")
    with r.sessions_live():
        r.session_status("www.rbcdemo.ca", "running", 1.5)
        r.session_status("www.rbcdemo.ca", "exit", 2.0)
    r.findings("www.rbcdemo.ca", REPORT)
    r.equivalences("www.rbcdemo.ca", REPORT)
    r.remediation("iac_pr", "www.rbcdemo.ca", "devin-2",
                  "https://x/sessions/devin-2")
    r.deferred("www.rbcdemo.ca", "cors.x", "note")
    r.summary("run-1", {"www.rbcdemo.ca": REPORT}, "/tmp/art")
    r.warn("w")
    r.error("e")
    r.schema_block({"type": "object"})
    r.prompt_block("www.rbcdemo.ca", "PROMPT BODY")
    text = r.console.file.getvalue()
    assert "Golden state" in text and "PROMPT BODY" in text
    assert "critical" in text and "tls.min_version" in text
    assert "equivalent" in text and "31536000s" in text


def test_make_reporter_selection(monkeypatch):
    assert isinstance(make_reporter(plain=True), PlainReporter)
    assert isinstance(make_reporter(demo=True), DemoReporter)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert isinstance(make_reporter(), PlainReporter)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert isinstance(make_reporter(), DemoReporter)
