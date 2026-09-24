"""Thin client for the Devin v3 organizations API.

v3 is the only API version that accepts service-user auth, which is how this
demo's sessions are created. The client covers exactly what the orchestrator
uses: attachment upload, session create/get, and polling to a terminal state.
It retries transient failures (429 and 5xx) with backoff and gives up fast on
other 4xx — a bad request will not fix itself.
"""
import time

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
            body = self._request("POST", self._org("/attachments"),
                                 files={"file": fh})
        return body["url"]

    def create_session(self, prompt, *, title=None, tags=None, repos=None,
                       attachment_urls=None, structured_output_schema=None,
                       structured_output_required=True, max_acu_limit=None,
                       devin_mode=None, parent_session_id=None):
        """Create a session; returns the v3 session object.

        `parent_session_id` is passed as the `devin_id` query parameter — the
        v3 mechanism for attaching a session to a parent. Whether the parent's
        `child_session_ids` actually populates is verified in the E2E run, not
        assumed here.
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
            payload["attachments"] = list(attachment_urls)
        if structured_output_schema:
            payload["structured_output_schema"] = structured_output_schema
        if max_acu_limit is not None:
            payload["max_acu_limit"] = max_acu_limit
        if devin_mode:
            payload["devin_mode"] = devin_mode
        params = {"devin_id": parent_session_id} if parent_session_id else None
        return self._request("POST", self._org("/sessions"), params=params,
                             json=payload)

    def get_session(self, session_id):
        return self._request("GET", self._org(f"/sessions/{session_id}"))

    # -- polling ---------------------------------------------------------------

    TERMINAL_STATUSES = {"exit", "error"}

    @staticmethod
    def _terminal(body):
        return (body.get("status") in DevinClient.TERMINAL_STATUSES
                or body.get("status_detail") == "finished"
                or body.get("structured_output") is not None)

    def poll_session(self, session_id, *, interval=20, timeout=2700,
                     on_tick=None):
        """Poll until the session terminates or `timeout` seconds elapse.

        Terminal: status in {exit, error}, status_detail == "finished", or a
        non-null structured_output. Raises TimeoutError past the deadline.
        """
        deadline = time.monotonic() + timeout
        while True:
            body = self.get_session(session_id)
            if self._terminal(body):
                return body
            if on_tick:
                on_tick(body)
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"session {session_id} did not terminate within {timeout}s "
                    f"(last status={body.get('status')!r})")
            time.sleep(interval)
