"""Runtime configuration for the orchestrator.

The demo runs entirely against the phase-02 simulators; the only live service
it touches is the Devin v3 API, authenticated as the enterprise service user.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = REPO / "artifacts"

# --- Devin v3 API (verified live for this org) ---
DEVIN_BASE_URL = "https://test-aaron.devinenterprise.com/api"
DEVIN_ORG_ID = "org-eb1f5152ec0e4d93a0a2ee0339f9828c"
TOKEN_ENV = "DEVIN_ENTERPRISE_SERVICE_USER"

# --- simulators ---
SIM_AKAMAI_BASE = "http://127.0.0.1:8081"
SIM_CLOUDFLARE_BASE = "http://127.0.0.1:8082"

# --- what the detection sessions are pointed at ---
REPO_SLUG = "aaron-cog-gtm-gh-org/cdn-drift-detection"
GOLDEN_BRANCH = "devin/1790214592-cdn-drift-fixtures"
GOLDEN_DB = REPO / "store" / "golden.db"

# --- session defaults ---
POLL_INTERVAL_S = 20
POLL_TIMEOUT_S = 2700          # 45 min ceiling per detection session
MAX_ACU_LIMIT = 10
DEVIN_MODE = "normal"


def session_url(session_id):
    """The URL an audience member can open to watch a session."""
    return f"https://test-aaron.devinenterprise.com/sessions/{session_id}"


def get_token():
    """The service-user token, from the environment only. Never printed."""
    token = os.environ.get(TOKEN_ENV)
    if not token:
        sys.exit(f"{TOKEN_ENV} is not set — the service-user token is required "
                 "to call the Devin v3 API.")
    return token


def run_id():
    """`<UTC timestamp>-<short git sha>`, e.g. 20260524T142233Z-055483a."""
    import subprocess
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sha = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    return f"{ts}-{sha}"
