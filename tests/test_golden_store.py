import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from store.golden_store import (GoldenRecord, connect, get_golden, get_mapping,
                                init_schema, list_domains, upsert_golden)


def make_record(**kw):
    base = dict(domain="x.rbcdemo.ca", akamai_property_id="prp_1",
                cloudflare_zone_id="z" * 32, main_tf="tf", rules_json="{}",
                appsec_json=None, golden_sha="sha", mapping_version="2026.09.3",
                git_commit="abc", source_path="golden/x", updated_at="now")
    base.update(kw)
    return GoldenRecord(**base)


def test_schema_and_upsert(tmp_path):
    conn = connect(tmp_path / "g.db")
    init_schema(conn)
    upsert_golden(conn, make_record())
    rec = get_golden(conn, "x.rbcdemo.ca")
    assert rec.golden_sha == "sha"
    upsert_golden(conn, make_record(golden_sha="sha2"))
    rec = get_golden(conn, "x.rbcdemo.ca")
    assert rec.golden_sha == "sha2"
    assert conn.execute("SELECT COUNT(*) c FROM golden_config").fetchone()["c"] == 1
    assert list_domains(conn) == ["x.rbcdemo.ca"]
    init_schema(conn)  # idempotent
    assert get_golden(conn, "x.rbcdemo.ca").golden_sha == "sha2"


def test_get_mapping_latest(tmp_path):
    conn = connect(tmp_path / "g.db")
    init_schema(conn)
    conn.execute("INSERT INTO mapping_registry VALUES (?,?,?,?,?)",
                 ("v1", "yaml", "s1", 10, "2026-01-01"))
    conn.execute("INSERT INTO mapping_registry VALUES (?,?,?,?,?)",
                 ("v2", "yaml2", "s2", 11, "2026-01-02"))
    conn.commit()
    assert get_mapping(conn)["version"] == "v2"
    assert get_mapping(conn, "v1")["sha256"] == "s1"


def test_loader_idempotent(tmp_path):
    db = tmp_path / "golden.db"
    env = dict(**__import__("os").environ)
    cmd = [sys.executable, str(REPO / "scripts/load_golden_store.py"),
           "--db", str(db)]
    r1 = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env)
    assert r1.returncode == 0, r1.stderr
    conn = connect(db)
    shas1 = {r["domain"]: r["golden_sha"] for r in
             conn.execute("SELECT domain, golden_sha FROM golden_config")}
    assert len(shas1) == 4
    runs1 = conn.execute("SELECT COUNT(*) c FROM load_run").fetchone()["c"]
    conn.close()
    r2 = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env)
    assert r2.returncode == 0, r2.stderr
    conn = connect(db)
    shas2 = {r["domain"]: r["golden_sha"] for r in
             conn.execute("SELECT domain, golden_sha FROM golden_config")}
    runs2 = conn.execute("SELECT COUNT(*) c FROM load_run").fetchone()["c"]
    assert shas1 == shas2
    assert runs2 == runs1 + 1
    rec = get_golden(conn, "api.rbcdemo.ca")
    assert rec.appsec_json is not None
    rec = get_golden(conn, "assets.rbcdemo.ca")
    assert rec.appsec_json is None
    assert get_mapping(conn)["version"] == "2026.09.3"
