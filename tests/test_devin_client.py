"""DevinClient tests — httpx.MockTransport only, never the real API."""
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


def test_poll_terminal_on_structured_output():
    def h(r):
        return _sess_response("running", None, {"verdict": "drift_detected"})
    out = make_client(h).poll_session("s1", interval=0)
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
