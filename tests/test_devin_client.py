"""DevinClient tests — httpx.MockTransport only, never the real API."""
import itertools
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator.devin_client import DevinClient

BASE = "https://test-aaron.devinenterprise.com/api"
ORG = "org-test"


def make_client(handler):
    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    return DevinClient(BASE, ORG, "tok-test", http_client=http)


def capture(handler):
    seen = []

    def wrapped(request):
        seen.append(request)
        return handler(request)
    return seen, wrapped


def test_create_session_request_shape():
    seen, h = capture(lambda r: httpx.Response(
        200, json={"session_id": "devin-1", "status": "new"}))
    c = make_client(h)
    out = c.create_session(
        "PROMPT", title="t", tags=["a", "b"], repos=["org/repo"],
        attachment_urls=["https://x/1"], structured_output_schema={"type": "object"},
        max_acu_limit=10, devin_mode="normal")
    req = seen[0]
    assert req.method == "POST"
    assert req.url.path == f"/api/v3/organizations/{ORG}/sessions"
    assert req.headers["authorization"] == "Bearer tok-test"
    body = json.loads(req.content)
    assert body["prompt"] == "PROMPT"
    assert body["tags"] == ["a", "b"]
    assert body["repos"] == ["org/repo"]
    assert body["attachment_urls"] == ["https://x/1"]
    assert body["structured_output_schema"] == {"type": "object"}
    assert body["structured_output_required"] is True
    assert body["max_acu_limit"] == 10
    assert body["devin_mode"] == "normal"
    assert out["session_id"] == "devin-1"


def test_create_session_sends_no_query_params():
    seen, h = capture(lambda r: httpx.Response(200, json={"session_id": "s"}))
    make_client(h).create_session("P")
    assert not dict(seen[0].url.params)  # v3 has no parent linkage to pass


def test_upload_attachment_multipart(tmp_path):
    p = tmp_path / "b.json"
    p.write_text('{"a": 1}')
    seen, h = capture(lambda r: httpx.Response(
        200, json={"url": "https://attach/url-1"}))
    url = make_client(h).upload_attachment(p)
    req = seen[0]
    assert req.method == "POST"
    assert req.url.path == f"/api/v3/organizations/{ORG}/attachments"
    assert b'name="file"' in req.content
    assert b'{"a": 1}' in req.content
    assert url == "https://attach/url-1"


def _sess_response(status="running", detail=None, so=None):
    return httpx.Response(200, json={
        "session_id": "s1", "status": status,
        "status_detail": detail, "structured_output": so})


def test_poll_terminal_on_exit_status():
    calls = []

    def h(r):
        calls.append(1)
        return _sess_response("running") if len(calls) == 1 \
            else _sess_response("exit", "finished", {"verdict": "in_sync"})
    out = make_client(h).poll_session("s1", interval=0)
    assert out["structured_output"]["verdict"] == "in_sync"
    assert len(calls) == 2


def test_poll_terminal_on_finished_detail():
    def h(r):
        return _sess_response("running", "finished")
    out = make_client(h).poll_session("s1", interval=0)
    assert out["status_detail"] == "finished"


def test_poll_terminal_on_done_when_report_ready():
    """A bare structured_output is NOT terminal — a session can publish a
    partial report mid-task. `done_when` (the caller's completeness rule)
    is what ends polling on a report."""
    def h(r):
        return _sess_response("running", None, {"verdict": "drift_detected"})
    client = make_client(h)
    with pytest.raises(TimeoutError):
        client.poll_session("s1", interval=0, timeout=0)
    out = client.poll_session(
        "s1", interval=0, timeout=60,
        done_when=lambda b: b.get("structured_output") is not None)
    assert out["structured_output"]["verdict"] == "drift_detected"


def test_poll_timeout():
    calls = []

    def h(r):
        calls.append(1)
        return _sess_response("running")
    with pytest.raises(TimeoutError):
        make_client(h).poll_session("s1", interval=0, timeout=0)
    assert calls


def test_retry_on_429_then_success():
    calls = []

    def h(r):
        calls.append(1)
        return httpx.Response(429) if len(calls) == 1 \
            else httpx.Response(200, json={"session_id": "s"})
    out = make_client(h).get_session("s")
    assert len(calls) == 2
    assert out["session_id"] == "s"


def test_retry_on_500():
    calls = []

    def h(r):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 \
            else httpx.Response(200, json={"ok": True})
    out = make_client(h).get_session("s")
    assert len(calls) == 3


def test_no_retry_on_4xx():
    calls = []

    def h(r):
        calls.append(1)
        return httpx.Response(404, json={"error": "nope"})
    with pytest.raises(httpx.HTTPStatusError):
        make_client(h).get_session("s")
    assert len(calls) == 1


def test_missing_token_exits(monkeypatch):
    monkeypatch.delenv("DEVIN_ENTERPRISE_SERVICE_USER", raising=False)
    from orchestrator import config
    with pytest.raises(SystemExit):
        config.get_token()


def _msg_response(items, end=None, has_next=False, total=None):
    return httpx.Response(200, json={
        "items": items, "end_cursor": end, "has_next_page": has_next,
        "total": total if total is not None else len(items)})


def test_list_messages_paginates_until_no_next_page():
    seen = []

    def h(r):
        seen.append(r)
        if "cursor" not in dict(r.url.params):
            return _msg_response(
                [{"created_at": "t1", "event_id": "e1", "message": "q",
                  "source": "devin", "origin": "x", "user_id": "u",
                  "username": "devin"}],
                end="cur-1", has_next=True)
        assert dict(r.url.params)["cursor"] == "cur-1"
        return _msg_response(
            [{"created_at": "t2", "event_id": "e2", "message": "a",
              "source": "user", "origin": "x", "user_id": "u",
              "username": "op"}], has_next=False)

    msgs = make_client(h).list_messages("s1")
    assert [m["message"] for m in msgs] == ["q", "a"]
    assert len(seen) == 2
    assert seen[0].url.path.endswith("/sessions/s1/messages")


def test_send_message_posts_message_body():
    seen, h = capture(lambda r: httpx.Response(200, json={"ok": True}))
    make_client(h).send_message("s1", "1: akamai")
    req = seen[0]
    assert req.method == "POST"
    assert req.url.path.endswith("/sessions/s1/messages")
    assert json.loads(req.content) == {"message": "1: akamai"}


def test_waiting_covers_running_and_suspended_waiting_states():
    assert DevinClient.waiting({"status": "running",
                                "status_detail": "waiting_for_user"})
    assert DevinClient.waiting({"status": "suspended",
                                "status_detail": "inactivity"})
    assert not DevinClient.waiting({"status": "running",
                                    "status_detail": None})
    assert not DevinClient.waiting({"status": "suspended",
                                    "status_detail": "blocked"})
    assert not DevinClient.waiting({"status": "exit",
                                    "status_detail": "finished"})


def test_waiting_is_not_terminal():
    for body in ({"status": "running", "status_detail": "waiting_for_user"},
                 {"status": "suspended", "status_detail": "inactivity"}):
        assert not DevinClient._terminal(body)


def test_on_waiting_fires_once_per_episode_and_rearms():
    bodies = [
        {"status": "running", "status_detail": None},           # working
        {"status": "running", "status_detail": "waiting_for_user"},  # ep1
        {"status": "suspended", "status_detail": "inactivity"},  # ep1, still
        {"status": "running", "status_detail": None},           # working again
        {"status": "running", "status_detail": "waiting_for_user"},  # ep2
        {"status": "exit", "status_detail": "finished"},
    ]
    it = iter(bodies)
    fired = []

    def h(r):
        b = next(it)
        return httpx.Response(200, json=b)

    out = make_client(h).poll_session(
        "s1", interval=0, on_waiting=lambda b: fired.append(b))
    assert len(fired) == 2  # one per episode, not per tick
    assert out["status_detail"] == "finished"


def test_poll_deadline_excludes_time_spent_waiting(monkeypatch):
    """The timeout bounds Devin's work, not the human's: a session that
    sits waiting well past the nominal timeout must not raise."""
    import orchestrator.devin_client as dc

    class FakeClock:
        def __init__(self):
            self.t = 0.0

        def monotonic(self):
            return self.t

        def sleep(self, s):
            self.t += s

    clock = FakeClock()
    monkeypatch.setattr(dc, "time", clock)

    bodies = ([{"status": "running", "status_detail": "waiting_for_user"}]
              * 10  # 10 ticks * 10s sleep = 100s of human thinking time
              + [{"status": "exit", "status_detail": "finished"}])
    it = iter(bodies)
    client = make_client(lambda r: httpx.Response(200, json=next(it)))
    # timeout=5 but ~100s elapse on the clock — all of it waiting
    out = client.poll_session("s1", interval=10, timeout=5)
    assert out["status_detail"] == "finished"


def test_poll_deadline_still_fires_on_real_work(monkeypatch):
    """Working (non-waiting) time still counts against the timeout."""
    import orchestrator.devin_client as dc

    class FakeClock:
        def __init__(self):
            self.t = 0.0

        def monotonic(self):
            return self.t

        def sleep(self, s):
            self.t += s

    monkeypatch.setattr(dc, "time", FakeClock())
    bodies = itertools.chain(
        [{"status": "running", "status_detail": "waiting_for_user"}] * 3,
        itertools.repeat({"status": "running", "status_detail": None}))
    client = make_client(lambda r: httpx.Response(200, json=next(bodies)))
    with pytest.raises(TimeoutError):
        client.poll_session("s1", interval=10, timeout=25)


# ---------------- the partial-report regression ---------------------------
#
# PR #17's live failure: sessions publish a partial structured_output
# (findings, no remediation) BEFORE asking the operator, and _terminal used
# to treat any non-null structured_output as done — poll returned while the
# session was sitting waiting, and on_waiting never fired.

from orchestrator.run_detection import report_complete

PARTIAL = {"findings": [{"field": "tls.min_version"}],
           "remediation": None}
FINAL = {"findings": [{"field": "tls.min_version"}],
         "remediation": {"pull_request_url": "https://github.com/x/y/pull/1"}}


def _bodies(*states):
    out = []
    for st in states:
        if st == "working":
            out.append({"status": "running", "status_detail": None})
        elif st == "waiting":
            out.append({"status": "running",
                        "status_detail": "waiting_for_user",
                        "structured_output": dict(PARTIAL)})
        elif st == "suspended":
            out.append({"status": "suspended",
                        "status_detail": "inactivity",
                        "structured_output": dict(PARTIAL)})
        elif st == "done":
            out.append({"status": "exit", "status_detail": "finished",
                        "structured_output": dict(FINAL)})
    return out


def _client_for(bodies):
    it = iter(bodies)
    return make_client(lambda r: httpx.Response(200, json=next(it)))


def test_partial_report_while_waiting_does_not_terminate():
    """running/waiting_for_user carrying a partial report: fires on_waiting,
    keeps polling, returns only on the completed (PR-carrying) report."""
    fired = []
    out = _client_for(_bodies("working", "waiting", "waiting", "done")) \
        .poll_session("s1", interval=0,
                      on_waiting=lambda b: fired.append(b),
                      done_when=lambda b: report_complete(b, False))
    assert len(fired) == 1
    assert out["structured_output"]["remediation"]["pull_request_url"]


def test_partial_report_while_suspended_does_not_terminate():
    """suspended/inactivity with a partial report is the same: still
    waiting, still resumable."""
    fired = []
    out = _client_for(_bodies("working", "suspended", "done")) \
        .poll_session("s1", interval=0,
                      on_waiting=lambda b: fired.append(b),
                      done_when=lambda b: report_complete(b, False))
    assert len(fired) == 1
    assert out["status_detail"] == "finished"


def test_report_complete_predicate_variants():
    # report_only: any dict report is the whole job
    assert report_complete({"structured_output": PARTIAL}, True)
    # no findings -> nothing to decide or remediate
    assert report_complete({"structured_output":
                            {"findings": [], "remediation": None}}, False)
    # findings but no remediation yet -> NOT done (the regression case)
    assert not report_complete({"structured_output": PARTIAL}, False)
    # PR opened -> done
    assert report_complete({"structured_output": FINAL}, False)
    # every finding recorded unresolved -> also done
    assert report_complete({"structured_output":
                            {"findings": [{"field": "f"}],
                             "remediation": {"unresolved":
                                             [{"field": "f"}]}}}, False)
    # no report at all -> not done
    assert not report_complete({"structured_output": None}, False)
    assert not report_complete({}, True)


def test_exit_while_waiting_is_still_not_terminal():
    """A terminal-looking status while waiting keeps polling (the relay
    can still answer it); exit without a waiting state is terminal."""
    assert not DevinClient._terminal(
        {"status": "suspended", "status_detail": "inactivity"})
    assert DevinClient._terminal(
        {"status": "exit", "status_detail": "finished"})
    assert DevinClient._terminal({"status": "error"})


def _waiting_body(so):
    return {"status": "running", "status_detail": "waiting_for_user",
            "structured_output": so}


def test_complete_report_while_waiting_terminates_immediately():
    """Second live failure: a session that opened its PR and published the
    complete report then sits in waiting_for_user telling the operator
    it's done — a completion message is not a question. done_when outranks
    the waiting status: return immediately, never fire on_waiting."""
    fired = []
    out = _client_for([_waiting_body(dict(FINAL))]) \
        .poll_session("s1", interval=0,
                      on_waiting=lambda b: fired.append(b),
                      done_when=lambda b: report_complete(b, False))
    assert fired == []
    assert out["structured_output"]["remediation"]["pull_request_url"]


def test_complete_report_while_suspended_terminates_immediately():
    fired = []
    out = _client_for([{"status": "suspended",
                        "status_detail": "inactivity",
                        "structured_output": dict(FINAL)}]) \
        .poll_session("s1", interval=0,
                      on_waiting=lambda b: fired.append(b),
                      done_when=lambda b: report_complete(b, False))
    assert fired == []
    assert out["structured_output"]["remediation"]["pull_request_url"]


def test_report_only_report_while_waiting_terminates():
    """--report-only: any report is the whole job, even while waiting."""
    out = _client_for([_waiting_body(dict(PARTIAL))]) \
        .poll_session("s1", interval=0,
                      done_when=lambda b: report_complete(b, True))
    assert out["structured_output"]["findings"]


def test_all_unresolved_report_while_waiting_terminates():
    """A complete report is every finding consciously left alone too."""
    rep = {"findings": [{"field": "f"}], "remediation":
           {"unresolved": [{"field": "f", "reason": "not expressible"}]}}
    fired = []
    out = _client_for([_waiting_body(rep)]) \
        .poll_session("s1", interval=0,
                      on_waiting=lambda b: fired.append(b),
                      done_when=lambda b: report_complete(b, False))
    assert fired == []
    assert out["structured_output"]["remediation"]["unresolved"]
