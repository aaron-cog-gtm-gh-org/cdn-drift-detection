"""console.py — both reporters must render the cross-provider report shape;
the run_detection seams are exercised with a fake DevinClient."""
import json
import sys
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator.console import DemoReporter, PlainReporter, make_reporter

REPORT = {
    "domain": "www.rbcdemo.ca", "iac_sha": "abc", "mapping_version": "v",
    "verdict": "drift_detected",
    "summary": {"fields_compared": 12, "findings_total": 2,
                "by_severity": {"critical": 1, "medium": 1}},
    "findings": [
        {"field": "waf.managed_ruleset_enabled", "severity": "critical",
         "disagreement": "value_mismatch",
         "akamai_value": "true", "cloudflare_value": "false",
         "locator": {"akamai_path": "$.a", "cloudflare_path": "$.c"},
         "explanation": "e", "impact": "i",
         "recommended_authority": "akamai",
         "recommendation_rationale": "r", "confidence": "high"},
        {"field": "tls.hsts_max_age", "severity": "medium",
         "disagreement": "value_mismatch",
         "akamai_value": "86400", "cloudflare_value": "31536000",
         "locator": {"akamai_path": "$.a2", "cloudflare_path": "$.c2"},
         "explanation": "e", "impact": "i",
         "recommended_authority": "cloudflare",
         "recommendation_rationale": "r", "confidence": "high"},
    ],
    "equivalent_but_different": [
        {"field": "tls.min_version", "akamai_value": "TLSV1_2",
         "cloudflare_value": "1.2",
         "why_equivalent": "value table maps TLSV1_2 -> 1.2"},
    ],
    "not_comparable": [{"field": "bot.edge_layer",
                        "reason": "unsupported_at_cloudflare"}],
    "decisions": [{"field": "waf.managed_ruleset_enabled",
                   "authority": "akamai", "source": "user"}],
    "remediation": {
        "pull_request_url": "https://github.com/x/y/pull/7",
        "changes": [{"field": "waf.managed_ruleset_enabled",
                     "provider_changed": "cloudflare",
                     "file": "terraform/www.rbcdemo.ca/cloudflare/rulesets.json",
                     "from_value": "enabled: false", "to_value": "enabled: true"}],
        "unresolved": []},
    "fields_reviewed": ["waf.managed_ruleset_enabled", "tls.hsts_max_age",
                        "tls.min_version", "bot.edge_layer"],
}


def _plain_stdout(fn):
    buf = StringIO()
    with redirect_stdout(buf):
        fn(PlainReporter())
    return buf.getvalue()


def test_plain_session_created_exact():
    out = _plain_stdout(lambda r: r.session_created(
        "www.rbcdemo.ca", "devin-42", "https://x/sessions/devin-42"))
    assert out == ("  created www.rbcdemo.ca: devin-42 "
                   "https://x/sessions/devin-42\n")


def test_plain_findings_renders_both_providers():
    out = _plain_stdout(lambda r: r.findings("www.rbcdemo.ca", REPORT))
    assert "verdict: drift_detected" in out
    assert "akamai=true" in out and "cloudflare=false" in out
    assert "recommend akamai" in out
    assert "recommend cloudflare" in out


def test_plain_equivalences_both_values():
    out = _plain_stdout(lambda r: r.equivalences("www.rbcdemo.ca", REPORT))
    assert "TLSV1_2" in out and "1.2" in out


def test_plain_waiting_block_carries_url_and_question():
    out = _plain_stdout(lambda r: r.waiting_for_decision(
        "api.rbcdemo.ca", "https://x/sessions/devin-9",
        "1. ratelimit.partner_api: akamai=1000 cf=100 — which is right?"))
    assert "https://x/sessions/devin-9" in out
    assert "ratelimit.partner_api" in out
    assert "WAITING ON OPERATOR — api.rbcdemo.ca" in out


def test_plain_remediation_renders_pr_and_changes():
    out = _plain_stdout(lambda r: r.remediation("www.rbcdemo.ca", REPORT))
    assert "https://github.com/x/y/pull/7" in out
    assert "enabled: false -> enabled: true" in out
    assert "terraform/www.rbcdemo.ca/cloudflare/rulesets.json" in out


def test_plain_status_and_error_go_to_stderr():
    err = StringIO()
    with redirect_stderr(err):
        PlainReporter().session_status("www.rbcdemo.ca", "waiting")
        PlainReporter().error("SCHEMA: x")
    assert "    www.rbcdemo.ca: waiting" in err.getvalue()
    assert "SCHEMA: x" in err.getvalue()


def _demo():
    from rich.console import Console
    return DemoReporter(console=Console(file=StringIO(), force_terminal=True,
                                        width=100))


def test_demo_every_method_renders():
    r = _demo()
    r.phase(1, 8, "IaC state", subtitle="sub")
    r.iac_state(["www.rbcdemo.ca"], {"www.rbcdemo.ca": "role"},
                {"www.rbcdemo.ca": "abc123"}, "v")
    r.step("line")
    r.artifact("www.akamai.json", "/tmp/x.json", sha="abc", nbytes=5)
    r.artifact_table([("f.json", "/tmp/f.json", "abc", 5)])
    r.kv("mapping_version", "v")
    r.fetch_table([("www.rbcdemo.ca", "rules", "/papi/x")])
    r.fetch("akamai", "rules", "www.rbcdemo.ca", "/papi/v1/properties/x/rules")
    r.session_created("www.rbcdemo.ca", "devin-1",
                      "https://x/sessions/devin-1")
    with r.sessions_live():
        r.session_status("www.rbcdemo.ca", "running", 1.5)
        r.session_status("www.rbcdemo.ca", "waiting", 2.0)
        r.session_status("www.rbcdemo.ca", "exit", 3.0)
    r.findings("www.rbcdemo.ca", REPORT)
    r.equivalences("www.rbcdemo.ca", REPORT)
    r.waiting_for_decision("www.rbcdemo.ca", "https://x/sessions/devin-1",
                           "which side?")
    r.decision_prompt("www.rbcdemo.ca")
    r.decision_sent("www.rbcdemo.ca", "1: akamai")
    r.decision_external("www.rbcdemo.ca", "https://x/sessions/devin-1")
    r.remediation("www.rbcdemo.ca", REPORT)
    r.deferred("www.rbcdemo.ca", "cors.x", "note")
    r.coverage_warning("www.rbcdemo.ca", ["f.x"], [], [])
    r.summary("run-1", {"www.rbcdemo.ca": REPORT}, "/tmp/art")
    r.warn("w")
    r.error("e")
    r.schema_summary({
        "required": ["domain"],
        "properties": {
            "verdict": {"enum": ["in_sync"]},
            "findings": {"items": {
                "required": ["field"],
                "properties": {
                    "severity": {"enum": ["high"]},
                    "disagreement": {"enum": ["value_mismatch"]},
                    "recommended_authority": {"enum": ["akamai"]},
                },
            }},
        },
    })
    r.schema_block({"type": "object"})
    r.prompt_block("www.rbcdemo.ca", "PROMPT BODY")
    text = r.console.file.getvalue()
    assert "IaC state" in text and "PROMPT BODY" in text
    assert "critical" in text and "waf.managed_ruleset_enabled" in text
    assert "pull/7" in text and "waiting" in text


def test_demo_inconclusive_renders_red_reason():
    rep = dict(REPORT, verdict="inconclusive", findings=[],
               notes="input missing")
    r = _demo()
    r.findings("www.rbcdemo.ca", rep)
    r.summary("run", {"www.rbcdemo.ca": rep}, "/tmp")
    text = r.console.file.getvalue()
    assert "INCONCLUSIVE" in text and "input missing" in text
    out = _plain_stdout(lambda p: (
        p.findings("www.rbcdemo.ca", rep)))
    assert "INCONCLUSIVE: input missing" in out


# ---------------- run_detection seams ----------------


def _wire_main(tmp_path, monkeypatch, report, mapping_fields=None):
    """Wire every seam of run_detection.main; returns (rd, created, Fake)."""
    import json as _json
    import orchestrator.run_detection as rd

    if mapping_fields is None:
        mapping_fields = tuple(report.get("fields_reviewed") or ())

    d = "www.rbcdemo.ca"
    (tmp_path / "f.json").write_text("{}")
    manifest = {"files": {d: {
        s: {"path": str(tmp_path / "f.json"), "sha256": "s"}
        for s in ("akamai", "cloudflare", "mapping")}}}
    monkeypatch.setattr(rd, "iac_info",
                        lambda doms, root=None: ({x: "a" * 64 for x in doms},
                                                 "v"))
    monkeypatch.setattr(rd.collect, "collect_akamai", lambda *a, **k: {})
    monkeypatch.setattr(rd.collect, "collect_cloudflare", lambda *a, **k: {})
    monkeypatch.setattr(rd.collect, "mapping_bundle",
                        lambda dom, doc: {"mapping": {
                            "fields": [{"id": i} for i in mapping_fields]}})

    def _write_bundles(rid, b, shas, mv, adir):
        run_dir = adir / rid
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(
            _json.dumps(manifest) + "\n")
        return manifest

    monkeypatch.setattr(rd.collect, "write_bundles", _write_bundles)
    monkeypatch.setattr(rd, "render_prompts", lambda *a, **k: {d: "prompt"})
    monkeypatch.setattr(rd.config, "get_token", lambda: "t")
    monkeypatch.setattr(rd.config, "ARTIFACTS_DIR", tmp_path)
    monkeypatch.setattr(rd, "validate_report", lambda d_, r: [])
    return rd, d


def test_main_creates_session_with_repo_and_relay(tmp_path, monkeypatch):
    rd, d = _wire_main(tmp_path, monkeypatch, REPORT)
    sent = []
    poll_kwargs = {}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def upload_attachment(self, path):
            return "att-url"

        def create_session(self, *a, **k):
            created.append(k)
            return {"session_id": "sess-1",
                    "url": "https://x/sessions/sess-1"}

        def list_messages(self, sid):
            return [{"source": "devin", "message": "which side?"}]

        def send_message(self, sid, message):
            sent.append((sid, message))

        def poll_session(self, sid, **k):
            poll_kwargs.update(k)
            k["on_tick"]({"status": "running", "acus_consumed": 1})
            k["on_waiting"]({"status": "running",
                            "status_detail": "waiting_for_user",
                            "acus_consumed": 1})
            return {"status": "exit", "structured_output": REPORT}

    created = []
    monkeypatch.setattr(rd, "DevinClient", FakeClient)
    monkeypatch.setattr(rd, "_stdin_line", lambda timeout: "1: akamai\n")
    buf = StringIO()
    with redirect_stdout(buf):
        rc = rd.main(["--plain", "--domain", d])
    assert rc == 0
    text = buf.getvalue()
    assert "https://x/sessions/sess-1" in text      # clickable session link
    assert "which side?" in text                    # the question rendered
    assert sent == [("sess-1", "1: akamai")]        # the answer was relayed
    assert "https://github.com/x/y/pull/7" in text  # the PR that came out
    assert created[0]["repos"] == [rd.config.REPO_SLUG]
    assert "on_waiting" in poll_kwargs


def test_main_report_only(tmp_path, monkeypatch):
    clean = dict(REPORT, verdict="in_sync", findings=[],
                 equivalent_but_different=[], not_comparable=[],
                 remediation=None, decisions=[], fields_reviewed=["f.a"])
    rd, d = _wire_main(tmp_path, monkeypatch, clean)
    seen = {}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def upload_attachment(self, path):
            return "att-url"

        def create_session(self, *a, **k):
            return {"session_id": "sess-1"}

        def poll_session(self, sid, **k):
            seen.update(k)
            return {"status": "exit", "structured_output": clean}

    monkeypatch.setattr(rd, "DevinClient", FakeClient)
    calls = []
    monkeypatch.setattr(rd, "render_prompts",
                        lambda *a, **k: calls.append((a, k)) or {d: "p"})
    rc = rd.main(["--plain", "--report-only", "--domain", d])
    assert rc == 0
    a, k = calls[0]
    assert (k.get("report_only") if k else a[5]) is True


def test_main_answers_file_relays_without_stdin(tmp_path, monkeypatch):
    rd, d = _wire_main(tmp_path, monkeypatch, REPORT)
    answers = tmp_path / "answers.yaml"
    answers.write_text("www.rbcdemo.ca:\n"
                       "  waf.managed_ruleset_enabled: akamai\n"
                       "  tls.hsts_max_age: cloudflare\n")
    sent = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def upload_attachment(self, path):
            return "att-url"

        def create_session(self, *a, **k):
            return {"session_id": "sess-1"}

        def list_messages(self, sid):
            return [{"source": "devin", "message": "which side?"}]

        def send_message(self, sid, message):
            sent.append(message)

        def poll_session(self, sid, **k):
            k["on_waiting"]({"status": "suspended",
                            "status_detail": "inactivity"})
            return {"status": "exit", "structured_output": REPORT}

    monkeypatch.setattr(rd, "DevinClient", FakeClient)
    monkeypatch.setattr(rd, "_stdin_line",
                        lambda timeout: pytest.fail("stdin must not be read"))
    buf = StringIO()
    with redirect_stdout(buf):
        rc = rd.main(["--plain", "--domain", d, "--answers", str(answers)])
    assert rc == 0
    assert sent == ["waf.managed_ruleset_enabled: akamai, "
                    "tls.hsts_max_age: cloudflare"]
    assert "waf.managed_ruleset_enabled: akamai" in buf.getvalue()
    # the exchange landed in the run dir for later reconstruction
    log = (tmp_path.glob("*/detection/www.rbcdemo.ca.messages.jsonl"))
    lines = [json.loads(l) for l in next(iter(log)).read_text().splitlines()]
    assert lines[0]["from"] == "devin" and lines[1]["via"] == "answers_file"


def test_inconclusive_domain_exits_2(tmp_path, monkeypatch):
    rd, d = _wire_main(tmp_path, monkeypatch,
                       dict(REPORT, verdict="inconclusive", findings=[],
                            equivalent_but_different=[], decisions=[],
                            remediation=None,
                            notes="input missing — could not compare"))

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def upload_attachment(self, path):
            return "att-url"

        def create_session(self, *a, **k):
            return {"session_id": "sess-1"}

        def poll_session(self, sid, **k):
            return {"status": "exit", "structured_output":
                    dict(REPORT, verdict="inconclusive", findings=[],
                         notes="input missing")}

    monkeypatch.setattr(rd, "DevinClient", FakeClient)
    monkeypatch.setattr(rd, "make_reporter", lambda **k: _demo())
    assert rd.main(["--plain", "--domain", d]) == 2


def test_replay_renders_saved_reports(tmp_path):
    import json as _json
    from orchestrator.run_detection import replay
    det = tmp_path / "run-x" / "detection"
    det.mkdir(parents=True)
    (det / "www.rbcdemo.ca.json").write_text(_json.dumps(REPORT))
    rc = replay(str(det), PlainReporter(), 8)
    assert rc == 0
    rc = replay(str(det), _demo(), 8)


def test_replay_missing_dir_exits():
    from orchestrator.run_detection import replay
    with pytest.raises(SystemExit):
        replay("/nonexistent/run", PlainReporter(), 8)


def test_make_reporter_selection(monkeypatch):
    assert isinstance(make_reporter(plain=True), PlainReporter)
    assert isinstance(make_reporter(demo=True), DemoReporter)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert isinstance(make_reporter(), PlainReporter)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert isinstance(make_reporter(), DemoReporter)
