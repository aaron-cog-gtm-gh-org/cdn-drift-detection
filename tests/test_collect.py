"""collect.py tests — bundles built against live simulators on free ports."""
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from drift.iac import iac_sha
from drift.sources import ApiSource, DOMAINS
from orchestrator import collect


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def sims():
    ak_port, cf_port = free_port(), free_port()
    servers = []
    for app_path, port in (("sim.akamai_app:app", ak_port),
                           ("sim.cloudflare_app:app", cf_port)):
        cfg = uvicorn.Config(app_path, host="127.0.0.1", port=port,
                             log_level="warning")
        srv = uvicorn.Server(cfg)
        threading.Thread(target=srv.run, daemon=True).start()
        servers.append(srv)
    for base in (f"http://127.0.0.1:{ak_port}", f"http://127.0.0.1:{cf_port}"):
        for _ in range(50):
            try:
                if httpx.get(f"{base}/healthz", timeout=0.5).status_code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            pytest.fail("simulator did not start")
    yield ak_port, cf_port
    for s in servers:
        s.should_exit = True


def test_bundle_shape(sims):
    ak, cf = sims
    src = ApiSource(f"http://127.0.0.1:{ak}", f"http://127.0.0.1:{cf}")
    b = collect.collect_domain(src, "online.rbcdemo.ca")
    assert set(b) == {"akamai", "cloudflare"}
    assert set(b["akamai"]) == {"property", "rules", "hostnames", "appsec"}
    assert set(b["cloudflare"]) == {"zone", "settings", "rulesets", "dns_records"}
    assert b["akamai"]["appsec"] is not None      # online has an appsec config
    assert b["akamai"]["rules"]["rules"]          # PAPI rule tree payload
    assert b["cloudflare"]["rulesets"][0]["rules"]  # detail-fetched, not listing


def test_no_appsec_is_none(sims):
    ak, cf = sims
    src = ApiSource(f"http://127.0.0.1:{ak}", f"http://127.0.0.1:{cf}")
    b = collect.collect_domain(src, "assets.rbcdemo.ca")
    assert b["akamai"]["appsec"] is None


def test_write_bundles_stable_and_manifest(sims, tmp_path):
    ak, cf = sims
    src = ApiSource(f"http://127.0.0.1:{ak}", f"http://127.0.0.1:{cf}")
    bundles = collect.collect_all(source=src)
    shas = {d: f"sha-{d}" for d in DOMAINS}
    m1 = collect.write_bundles("run-1", bundles, shas, "v",
                               tmp_path / "a")
    m2 = collect.write_bundles("run-1", bundles, shas, "v",
                               tmp_path / "b")
    for domain in DOMAINS:
        for side in ("akamai", "cloudflare"):
            pa = Path(m1["files"][domain][side]["path"])
            pb = Path(m2["files"][domain][side]["path"])
            assert pa.read_bytes() == pb.read_bytes()  # byte-stable output
            expect = hashlib.sha256(pa.read_bytes()).hexdigest()
            assert m1["files"][domain][side]["sha256"] == expect
    manifest = json.loads((tmp_path / "a" / "run-1" / "manifest.json").read_text())
    assert manifest["mapping_version"] == "v"
    assert len(manifest["files"]) == 4
    for d in DOMAINS:  # per-domain provenance, not a single global sha
        assert manifest["files"][d]["golden_sha"] == f"sha-{d}"


def test_attachment_manifest_names_files(tmp_path):
    manifest = {"files": {"www.rbcdemo.ca": {
        "akamai": {"path": "/x/www.rbcdemo.ca.akamai.json"},
        "cloudflare": {"path": "/x/www.rbcdemo.ca.cloudflare.json"},
        "golden": {"path": "/x/www.rbcdemo.ca.golden.json"}}}}
    text = collect.attachment_manifest("www.rbcdemo.ca", manifest)
    assert "www.rbcdemo.ca.akamai.json" in text
    assert "www.rbcdemo.ca.cloudflare.json" in text
    assert "www.rbcdemo.ca.golden.json" in text


def test_golden_bundle_contents(tmp_path):
    mod = tmp_path / "api.rbcdemo.ca"
    (mod / "akamai").mkdir(parents=True)
    (mod / "providers.tf").write_text("resource {}")
    (mod / "akamai" / "rules.json").write_text('{"rules": []}')
    (mod / "akamai" / "appsec.json").write_text('{"sec": true}')
    mapping = {
        "version": "v9",
        "defaults": {"cloudflare_settings": {"http2": "on"}},
        "value_tables": {"tls_min_version": {"akamai": {}}},
        "fields": [
            {"id": "tls.min_version"},                        # unscoped -> all
            {"id": "only.api", "domains": ["api.rbcdemo.ca"]},
            {"id": "only.www", "domains": ["www.rbcdemo.ca"]},
        ],
    }
    b = collect.golden_bundle("api.rbcdemo.ca", mapping, root=tmp_path)
    assert b["domain"] == "api.rbcdemo.ca"
    assert b["golden_sha"] == iac_sha("api.rbcdemo.ca", tmp_path)
    assert b["mapping_version"] == "v9"
    assert b["files"]["providers.tf"] == "resource {}"
    assert b["files"]["akamai/rules.json"] == {"rules": []}
    assert b["files"]["akamai/appsec.json"] == {"sec": True}
    ids = [f["id"] for f in b["mapping"]["fields"]]
    assert ids == ["tls.min_version", "only.api"]  # domain-scoped
    assert b["mapping"]["version"] == "v9"
    assert "tls_min_version" in b["mapping"]["value_tables"]
    # no appsec -> the file is omitted, not null
    (mod / "akamai" / "appsec.json").unlink()
    b2 = collect.golden_bundle("api.rbcdemo.ca", mapping, root=tmp_path)
    assert "akamai/appsec.json" not in b2["files"]
