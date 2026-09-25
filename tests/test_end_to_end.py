"""End-to-end run_detection against a fake DevinClient that plays out the
full live flow: session created -> compares -> asks the operator which
side is right and waits -> CLI relays the answer -> session remediates,
opens the PR, and finishes with structured_output."""
import json
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPORT = {
    "domain": "api.rbcdemo.ca", "iac_sha": "a" * 64, "mapping_version": "v",
    "verdict": "drift_detected",
    "summary": {"fields_compared": 11, "findings_total": 2,
                "by_severity": {"high": 2}},
    "findings": [
        {"field": "ratelimit.partner_api", "severity": "high",
         "disagreement": "value_mismatch",
         "akamai_value": "1000", "cloudflare_value": "100",
         "locator": {"akamai_path": "$.ratePolicies.items[?(@.id==9101)]",
                     "cloudflare_path": "$.result[...].ratelimit"},
         "explanation": "thresholds differ tenfold", "impact": "i",
         "recommended_authority": "cloudflare",
         "recommendation_rationale": "100 is the approved limit",
         "confidence": "high"},
        {"field": "cors.allowed_origins", "severity": "high",
         "disagreement": "value_mismatch",
         "akamai_value": "{online, www}",
         "cloudflare_value": "{online, www, partners}",
         "locator": {"akamai_path": "$.a", "cloudflare_path": "$.c"},
         "explanation": "extra origin", "impact": "i",
         "recommended_authority": "akamai",
         "recommendation_rationale": "unapproved origin", "confidence": "high"},
    ],
    "equivalent_but_different": [],
    "not_comparable": [],
    "decisions": [{"field": "ratelimit.partner_api", "authority": "cloudflare",
                   "source": "user"},
                  {"field": "cors.allowed_origins", "authority": "akamai",
                   "source": "user"}],
    "remediation": {
        "pull_request_url": "https://github.com/aaron-cog-gtm-gh-org/"
                            "cdn-drift-detection/pull/42",
        "changes": [
            {"field": "ratelimit.partner_api", "provider_changed": "akamai",
             "file": "terraform/api.rbcdemo.ca/akamai/appsec.json",
             "from_value": "averageThreshold 1000",
             "to_value": "averageThreshold 100"},
            {"field": "cors.allowed_origins", "provider_changed": "cloudflare",
             "file": "terraform/api.rbcdemo.ca/cloudflare/rulesets.json",
             "from_value": "three origins", "to_value": "two origins"}],
        "unresolved": []},
    "fields_reviewed": ["ratelimit.partner_api", "cors.allowed_origins"],
}

QUESTION = ("I found 2 disagreements on api.rbcdemo.ca:\n"
            "1. ratelimit.partner_api: akamai=1000, cloudflare=100 "
            "(recommend cloudflare)\n"
            "2. cors.allowed_origins: akamai={online,www}, "
            "cloudflare adds partners (recommend akamai)\n"
            "Reply with e.g. `1: cloudflare, 2: akamai` or `skip`.")


class FakeSession:
    """One domain's session lifecycle: created -> waiting -> answered ->
    finished. `get_session` consumes the state queue; `send_message`
    (or an answer arriving 'in the UI') advances it."""

    def __init__(self, states, client):
        self.states = list(states)
        self.client = client
        self.id = f"sess-{id(self) % 997}"

    def poll_body(self):
        st = self.states[0]
        if st == "waiting":
            # waiting only ends when the answer arrives — via send_message
            # (CLI) or the operator answering in the Devin UI; either way
            # the waiting state is observed at least once first
            if self.client.ui_answered and getattr(self, "_w", 0):
                self.states = ["finished"]
                st = "finished"
            else:
                self._w = getattr(self, "_w", 0) + 1
        elif len(self.states) > 1:
            self.states.pop(0)
        return self.body(st)

    def body(self, st):
        base = {"session_id": self.id,
                "url": f"https://devin.test/sessions/{self.id}",
                "acus_consumed": 1.5, "structured_output": None}
        if st == "waiting":
            return {**base, "status": "running",
                    "status_detail": "waiting_for_user"}
        if st == "finished":
            return {**base, "status": "exit", "status_detail": "finished",
                    "acus_consumed": 3.0, "structured_output": REPORT}
        return {**base, "status": "running", "status_detail": None}


class FakeClient:
    """The seam run_detection calls; plays the session lifecycle and
    records every message the CLI relayed."""

    def __init__(self, *a, ui_answered=False, **k):
        self.sessions = {}
        self.sent = []
        self.created = []
        self.ui_answered = ui_answered

    def upload_attachment(self, path):
        return f"att://{Path(path).name}"

    def create_session(self, prompt, **kw):
        self.created.append(kw)
        sess = FakeSession(["running", "waiting", "running", "finished"],
                           self)
        self.sessions[sess.id] = sess
        return {"session_id": sess.id,
                "url": f"https://devin.test/sessions/{sess.id}"}

    def get_session(self, session_id):
        return self.sessions[session_id].poll_body()

    def list_messages(self, session_id):
        return [{"source": "devin", "message": QUESTION}]

    def send_message(self, session_id, message):
        self.sent.append((session_id, message))
        self.sessions[session_id].states = ["running", "finished"]
        return {"ok": True}

    def poll_session(self, session_id, *, interval=0, timeout=60,
                     on_tick=None, on_waiting=None, done_when=None):
        from orchestrator.devin_client import DevinClient
        waiting_armed = True
        while True:
            body = self.get_session(session_id)
            if DevinClient._terminal(body):
                return body
            if done_when and not DevinClient.waiting(body) \
                    and done_when(body):
                return body
            if on_tick:
                on_tick(body)
            if on_waiting:
                if DevinClient.waiting(body) and waiting_armed:
                    on_waiting(body)
                    waiting_armed = False
                elif not DevinClient.waiting(body):
                    waiting_armed = True


def _wire(tmp_path, monkeypatch, client_holder):
    import json as _json
    import orchestrator.run_detection as rd

    d = "api.rbcdemo.ca"
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
                        lambda dom, doc: {"mapping": {"fields": [
                            {"id": "ratelimit.partner_api"},
                            {"id": "cors.allowed_origins"}]}})

    def _write_bundles(rid, b, shas, mv, adir):
        run_dir = adir / rid
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(_json.dumps(manifest) + "\n")
        return manifest

    monkeypatch.setattr(rd.collect, "write_bundles", _write_bundles)
    monkeypatch.setattr(rd, "render_prompts", lambda *a, **k: {d: "prompt"})
    monkeypatch.setattr(rd.config, "get_token", lambda: "t")
    monkeypatch.setattr(rd.config, "ARTIFACTS_DIR", tmp_path)
    monkeypatch.setattr(rd, "DevinClient",
                        lambda *a, **k: client_holder[0])
    return rd, d


def test_e2e_waits_asks_relays_answer_and_prints_pr(tmp_path, monkeypatch):
    """create -> waiting -> URL + question rendered -> operator's stdin
    answer relayed via send_message -> finish -> PR printed."""
    holder = [FakeClient()]
    rd, d = _wire(tmp_path, monkeypatch, holder)
    monkeypatch.setattr(rd, "_stdin_line",
                        lambda timeout: "1: cloudflare, 2: akamai\n")

    buf = StringIO()
    with redirect_stdout(buf):
        rc = rd.main(["--plain", "--domain", d, "--poll-interval", "0"])
    text = buf.getvalue()
    assert rc == 0
    assert "WAITING ON OPERATOR — api.rbcdemo.ca" in text
    assert "https://devin.test/sessions/" in text        # clickable link
    assert "ratelimit.partner_api" in text               # the question
    assert holder[0].sent == [(next(iter(holder[0].sessions)),
                               "1: cloudflare, 2: akamai")]
    assert "cdn-drift-detection/pull/42" in text         # the PR
    assert "averageThreshold 1000 -> averageThreshold 100" in text
    assert holder[0].created[0]["repos"] == [rd.config.REPO_SLUG]
    assert holder[0].created[0]["structured_output_schema"] is \
        rd.DETECTION_SCHEMA
    # the exchange is persisted with the run for reconstruction
    log = next(tmp_path.glob("*/detection/*.messages.jsonl"))
    entries = [json.loads(l) for l in log.read_text().splitlines()]
    assert entries[0]["message"] == QUESTION
    assert entries[1]["message"] == "1: cloudflare, 2: akamai"
    # and the report landed too
    assert next(tmp_path.glob("*/detection/api.rbcdemo.ca.json"))


def test_e2e_answered_in_ui_gracefully(tmp_path, monkeypatch):
    """The operator answered in the Devin UI: stdin yields nothing usable,
    the session leaves the waiting state, no message is sent, no hang."""
    holder = [FakeClient(ui_answered=True)]
    rd, d = _wire(tmp_path, monkeypatch, holder)
    # stdin gives EOF — nobody typed anything
    monkeypatch.setattr(rd, "_stdin_line", lambda timeout: "")
    buf = StringIO()
    with redirect_stdout(buf):
        rc = rd.main(["--plain", "--domain", d, "--poll-interval", "0"])
    assert rc == 0
    assert holder[0].sent == []                    # nothing sent
    assert "answered in the Devin UI" in buf.getvalue()


def test_report_only_prompt_variant_renders_without_holes():
    from orchestrator.prompts import build_detection_prompt
    for ro in (False, True):
        p = build_detection_prompt(
            "www.rbcdemo.ca", mapping_version="2026.09.4", iac_sha="abc123",
            attachment_manifest="- a\n- b", pytest_cmd="pytest -q",
            base_branch="devin/x", report_only=ro)
        assert "{" not in p  # every hole filled
        assert "www.rbcdemo.ca" in p and "2026.09.4" in p
        assert "abc123" in p and "terraform/www.rbcdemo.ca/" in p
    full = build_detection_prompt(
        "www.rbcdemo.ca", mapping_version="v", iac_sha="s",
        attachment_manifest="m", pytest_cmd="pytest -q",
        base_branch="devin/x")
    assert "wait for their reply" in full
    assert "devin/x" in full and "pytest -q" in full
    ro = build_detection_prompt(
        "www.rbcdemo.ca", mapping_version="v", iac_sha="s",
        attachment_manifest="m", pytest_cmd="pytest -q",
        base_branch="devin/x", report_only=True)
    assert "report-only" in ro and "wait for their reply" not in ro


def test_sample_report_conforms_to_schema():
    import orchestrator.run_detection as rd
    assert rd.validate_report("api.rbcdemo.ca", REPORT) == []


def test_compose_answer_and_load_answers(tmp_path):
    from orchestrator.run_detection import compose_answer, load_answers
    f = tmp_path / "a.yaml"
    f.write_text("api.rbcdemo.ca:\n  ratelimit.partner_api: cloudflare\n"
                 "  cors.allowed_origins: skip\n")
    answers = load_answers(f)
    assert compose_answer(answers["api.rbcdemo.ca"]) == (
        "Answering by field id: ratelimit.partner_api: cloudflare, "
        "cors.allowed_origins: skip")


def test_blank_enter_reprompts_instead_of_aborting(tmp_path, monkeypatch):
    """A bare Enter is not an answer: stdin yields '\n' (blank), then the
    real answer — the real answer is what gets relayed."""
    holder = [FakeClient()]
    rd, d = _wire(tmp_path, monkeypatch, holder)
    lines = iter(["\n", "1: akamai\n"])
    monkeypatch.setattr(rd, "_stdin_line", lambda timeout: next(lines))
    buf = StringIO()
    with redirect_stdout(buf):
        rc = rd.main(["--plain", "--domain", d, "--poll-interval", "0"])
    assert rc == 0
    assert holder[0].sent == [(next(iter(holder[0].sessions)), "1: akamai")]


def test_answers_file_missing_domain_warns_and_falls_through(
        tmp_path, monkeypatch):
    """--answers given but no entry for the waiting domain: the CLI warns
    visibly (naming the asked fields) instead of silently blocking."""
    holder = [FakeClient(ui_answered=True)]
    rd, d = _wire(tmp_path, monkeypatch, holder)
    answers = tmp_path / "a.yaml"
    answers.write_text("other.example.com:\n  f: akamai\n")
    monkeypatch.setattr(rd, "_stdin_line", lambda timeout: "")
    buf, err = StringIO(), StringIO()
    with redirect_stdout(buf):
        from contextlib import redirect_stderr
        with redirect_stderr(err):
            rc = rd.main(["--plain", "--domain", d, "--answers",
                          str(answers), "--poll-interval", "0"])
    assert rc == 0
    out = buf.getvalue() + err.getvalue()
    assert "--answers has no entry for api.rbcdemo.ca" in out
    assert "ratelimit.partner_api" in out  # the asked fields are named


# ---------------- the split-question regression ---------------------------
#
# Third live run: sessions split the question across several messages —
# findings in one, the bare "reply in the form ..." instruction in another.
# The relay used to render only the last Devin message.

from orchestrator.run_detection import OperatorRelay, latest_question


def _m(source, message):
    return {"source": source, "message": message}


def test_latest_question_aggregates_the_devin_run():
    msgs = [_m("devin", "1. tls.min_version: akamai=TLSV1_2 cf=1.0\n"
                        "2. waf: on vs off"),
            _m("devin", "I'm waiting for your decision on the 2 findings "
                        "above. Reply `1: cloudflare, 2: akamai`.")]
    q = latest_question(msgs)
    assert "tls.min_version" in q and "Reply" in q
    assert q.index("tls.min_version") < q.index("Reply")  # order preserved


def test_latest_question_stops_at_operator_boundary():
    """Second episode: operator answered, then two new Devin messages —
    only the newest run is the question."""
    msgs = [_m("devin", "old question"), _m("user", "1: akamai"),
            _m("devin", "new findings"), _m("devin", "new instruction")]
    q = latest_question(msgs)
    assert "new findings" in q and "new instruction" in q
    assert "old question" not in q and "akamai" not in q


def test_latest_question_non_user_source_is_also_a_boundary():
    """Any non-devin source — tool, system — ends the run, same as an
    operator reply (documented in the helper's docstring)."""
    msgs = [_m("devin", "older"), _m("system", "checkpoint"),
            _m("devin", "newer")]
    assert latest_question(msgs) == "newer"


def test_latest_question_single_message_unchanged():
    assert latest_question([_m("devin", "the question")]) == "the question"
    assert latest_question([_m("user", "hi")]) == ""


class _RefetchClient:
    """list_messages returns nothing until the re-fetch."""

    def __init__(self, msgs_on_first=(), msgs_on_retry=()):
        self.calls = 0
        self.first = list(msgs_on_first)
        self.retry = list(msgs_on_retry)
        self.sent = []

    def list_messages(self, sid):
        self.calls += 1
        return self.first if self.calls == 1 else self.retry

    def get_session(self, sid):
        return {"status": "running", "status_detail": "waiting_for_user"}

    def send_message(self, sid, message):
        self.sent.append(message)


class _Out:
    def __init__(self):
        self.questions, self.warns, self.prompts = [], [], []

    def waiting_for_decision(self, domain, url, question):
        self.questions.append((domain, url, question))

    def warn(self, text):
        self.warns.append(text)

    def decision_prompt(self, domain):
        self.prompts.append(domain)

    def decision_sent(self, domain, answer):
        pass

    def decision_external(self, domain, url):
        pass


def test_relay_empty_question_refetches_once_then_falls_back(tmp_path):
    import orchestrator.run_detection as rd
    client = _RefetchClient()  # nothing on either fetch
    out = _Out()
    relay = OperatorRelay(client, out, log_dir=tmp_path, recheck_interval=0,
                          stdin_line=lambda timeout: "")
    relay.relay("www.rbcdemo.ca", "s1", {"url": "https://x/s1"})
    assert client.calls == 2                        # one re-fetch attempted
    assert any("no question text" in w for w in out.warns)
    assert "https://x/s1" in out.questions[0][2]    # fallback points at URL
    entries = [json.loads(l) for l in
               (tmp_path / "www.rbcdemo.ca.messages.jsonl")
               .read_text().splitlines()]
    assert "unavailable" in entries[0]["message"]


def test_relay_aggregated_question_is_printed_and_logged(tmp_path):
    client = _RefetchClient(
        msgs_on_first=[_m("devin", "finding 1"), _m("devin", "reply form")])
    out = _Out()
    relay = OperatorRelay(client, out, log_dir=tmp_path, recheck_interval=0,
                          stdin_line=lambda timeout: "")
    relay.relay("www.rbcdemo.ca", "s1", {"url": "https://x/s1"})
    domain, url, question = out.questions[0]
    assert "finding 1" in question and "reply form" in question
    entries = [json.loads(l) for l in
               (tmp_path / "www.rbcdemo.ca.messages.jsonl")
               .read_text().splitlines()]
    assert "finding 1" in entries[0]["message"]
    assert "reply form" in entries[0]["message"]  # full text in transcript
