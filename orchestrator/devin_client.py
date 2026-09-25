"""Thin client for the Devin v3 organizations API.

v3 is the only API version that accepts service-user auth, which is how this
demo's sessions are created. The client covers exactly what the orchestrator
uses: attachment upload, session create/get, and polling to a terminal state.
It retries transient failures (429 and 5xx) with backoff and gives up fast on
other 4xx — a bad request will not fix itself.
"""
import time
from pathlib import Path

import httpx


class DevinClient:
    def __init__(self, base_url, org_id, token, timeout=60, http_client=None):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.timeout = timeout
        self._client = http_client or httpx.Client(timeout=timeout)
        self._client.headers.update({"Authorization": f"Bearer {token}"})

    # -- transport ------------------------------------------------------------

    def _request(self, method, path, *, params=None, json=None, files=None,
                 retries=4):
        url = f"{self.base_url}{path}"
        delay = 1.0
        for attempt in range(retries):
            r = self._client.request(method, url, params=params, json=json,
                                     files=files)
            if r.status_code == 429 or r.status_code >= 500:
                if attempt == retries - 1:
                    r.raise_for_status()
                time.sleep(delay)
                delay *= 2
                continue
            r.raise_for_status()
            return r.json() if r.content else {}
        return {}

    def _org(self, path):
        return f"/v3/organizations/{self.org_id}{path}"

    # -- endpoints (v3 contract, verified live) --------------------------------

    def upload_attachment(self, path):
        """Upload one file; returns the attachment URL for session create."""
        with open(path, "rb") as fh:
            body = self._request(
                "POST", self._org("/attachments"),
                files={"file": (Path(path).name, fh, "application/json")})
        return body["url"]

    def create_session(self, prompt, *, title=None, tags=None, repos=None,
                       attachment_urls=None, structured_output_schema=None,
                       structured_output_required=True, max_acu_limit=None,
                       devin_mode=None):
        """Create a session; returns the v3 session object.

        v3 exposes no parent/child linkage — `devin_id` was tried live and the
        parent's `child_session_ids` stayed empty. Sessions are linked by
        convention instead: the caller tags them (e.g. `parent:<id>`).
        """
        payload = {"prompt": prompt,
                   "structured_output_required": structured_output_required}
        if title:
            payload["title"] = title
        if tags:
            payload["tags"] = list(tags)
        if repos:
            payload["repos"] = list(repos)
        if attachment_urls:
            payload["attachment_urls"] = list(attachment_urls)
        if structured_output_schema:
            payload["structured_output_schema"] = structured_output_schema
        if max_acu_limit is not None:
            payload["max_acu_limit"] = max_acu_limit
        if devin_mode:
            payload["devin_mode"] = devin_mode
        return self._request("POST", self._org("/sessions"), json=payload)

    def get_session(self, session_id):
        return self._request("GET", self._org(f"/sessions/{session_id}"))

    # -- messages --------------------------------------------------------------

    def list_messages(self, session_id):
        """All session messages, chronological — follows `end_cursor`
        until `has_next_page` is false."""
        items, cursor = [], None
        while True:
            params = {"cursor": cursor} if cursor else None
            body = self._request(
                "GET", self._org(f"/sessions/{session_id}/messages"),
                params=params)
            items.extend(body.get("items", []))
            if not body.get("has_next_page"):
                return items
            cursor = body.get("end_cursor")

    def send_message(self, session_id, message):
        """Post an operator message; also resumes a suspended session."""
        return self._request(
            "POST", self._org(f"/sessions/{session_id}/messages"),
            json={"message": message})

    # -- polling ---------------------------------------------------------------

    TERMINAL_STATUSES = {"exit", "error"}
    # a session waiting on the operator: asked a question and paused, or
    # suspended after idling while waiting — resumable via send_message,
    # and in neither case terminal
    WAITING = (("running", "waiting_for_user"), ("suspended", "inactivity"))

    @staticmethod
    def waiting(body):
        return (body.get("status"), body.get("status_detail")) in \
            DevinClient.WAITING

    @staticmethod
    def _terminal(body):
        # a waiting session is mid-task by definition — never terminal,
        # whatever the status fields say (a suspended/inactivity body must
        # keep polling so the relay can resume it with send_message)
        if DevinClient.waiting(body):
            return False
        return (body.get("status") in DevinClient.TERMINAL_STATUSES
                or body.get("status_detail") == "finished")

    def poll_session(self, session_id, *, interval=20, timeout=2700,
                     on_tick=None, on_waiting=None, done_when=None):
        """Poll until the session terminates or `timeout` seconds elapse.

        Terminal precedence: `done_when` FIRST — an optional
        callable(body) -> bool giving the caller's completeness rule; a
        complete report ends polling however the session's status reads
        (a session can publish its finished report and then sit in
        waiting_for_user telling the operator it's done). Then `status` in
        {exit, error} or `status_detail == "finished"` — but a session
        reporting a waiting state is NEVER terminal on status alone: it is
        mid-task, holding a question for the operator. A non-null
        `structured_output` is deliberately NOT a terminal signal either:
        a session may publish a partial report before it asks the operator
        anything, and the caller's `done_when` decides what complete looks
        like. Raises TimeoutError past the deadline.

        `on_waiting(body)` fires once per waiting *episode* — the first tick
        the session reports a waiting state — then re-arms once the session
        goes back to working, so a session may ask the operator more than
        once. The callback may answer via send_message and polling resumes.

        The timeout bounds *Devin's* work, not the human's: time spent in a
        waiting state (running/waiting_for_user, suspended/inactivity) does
        not count against the deadline — an unanswered question can hold a
        session open indefinitely without raising TimeoutError.
        """
        start = time.monotonic()
        waited = 0.0          # completed waiting episodes
        waiting_since = None  # open waiting episode, if any
        waiting_armed = True
        while True:
            now = time.monotonic()
            body = self.get_session(session_id)
            if done_when is not None and done_when(body):
                return body
            if self._terminal(body):
                return body
            if on_tick:
                on_tick(body)
            is_waiting = self.waiting(body)
            if is_waiting and waiting_since is None:
                waiting_since = now
            elif not is_waiting and waiting_since is not None:
                waited += now - waiting_since
                waiting_since = None
            if on_waiting:
                if is_waiting and waiting_armed:
                    on_waiting(body)
                    waiting_armed = False
                elif not is_waiting:
                    waiting_armed = True
            open_wait = (now - waiting_since) if waiting_since is not None else 0.0
            if now - start - waited - open_wait >= timeout:
                raise TimeoutError(
                    f"session {session_id} did not terminate within {timeout}s "
                    f"of working time (last status={body.get('status')!r})")
            time.sleep(interval)
