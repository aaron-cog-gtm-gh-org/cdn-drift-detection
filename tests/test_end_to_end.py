"""End-to-end: --source api --golden store must produce the same finding set
as --source disk --golden files."""
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def sims(tmp_path_factory):
    ak_port, cf_port = free_port(), free_port()
    db = tmp_path_factory.mktemp("db") / "golden.db"
    r = subprocess.run([sys.executable, str(REPO / "scripts/load_golden_store.py"),
                        "--db", str(db)], cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    servers = []
    for app_path, port in (("sim.akamai_app:app", ak_port),
                           ("sim.cloudflare_app:app", cf_port)):
        cfg = uvicorn.Config(app_path, host="127.0.0.1", port=port,
                             log_level="warning")
        srv = uvicorn.Server(cfg)
        t = threading.Thread(target=srv.run, daemon=True)
        t.start()
        servers.append(srv)
    for base in (f"http://127.0.0.1:{ak_port}", f"http://127.0.0.1:{cf_port}"):
        import httpx
        for _ in range(50):
            try:
                if httpx.get(f"{base}/healthz", timeout=0.5).status_code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            pytest.fail("simulator did not start")
    yield ak_port, cf_port, db
    for s in servers:
        s.should_exit = True


def run_validator(*extra):
    r = subprocess.run([sys.executable, str(REPO / "scripts/validate_fixtures.py"),
                        *extra], cwd=REPO, capture_output=True, text=True)
    return r


def findings_block(out):
    m = re.search(r"FINDINGS:\n(.*?)\n\nSCENARIO CHECK:", out, re.S)
    return m.group(1) if m else None


def test_discovery_resolves_identifiers_over_api(sims):
    ak_port, cf_port, db = sims
    sys.path.insert(0, str(REPO / "scripts"))
    import validate_fixtures as vf
    src = vf.ApiSource(f"http://127.0.0.1:{ak_port}",
                       f"http://127.0.0.1:{cf_port}")
    meta = src.meta
    assert meta["www.rbcdemo.ca"]["property_id"] == "prp_512345"
    assert meta["www.rbcdemo.ca"]["version"] == 47
    assert meta["online.rbcdemo.ca"]["zone_id"] == \
        "2b3c4d5e6f708192a3b4c5d6e7f8091a"
    assert meta["api.rbcdemo.ca"]["config_id"] == "waf_90012"
    assert meta["api.rbcdemo.ca"]["config_version"] == 9
    # second access is cached — no repeated discovery
    assert src.meta is meta


def test_api_store_matches_disk_files(sims):
    ak_port, cf_port, db = sims
    disk = run_validator()
    api = run_validator("--source", "api", "--golden", "store",
                        "--akamai-base", f"http://127.0.0.1:{ak_port}",
                        "--cloudflare-base", f"http://127.0.0.1:{cf_port}",
                        "--db", str(db))
    assert disk.returncode == 0, disk.stdout + disk.stderr
    assert api.returncode == 0, api.stdout + api.stderr
    assert findings_block(disk.stdout) == findings_block(api.stdout)
    assert disk.stdout.count("\n  PASS ") == 10
