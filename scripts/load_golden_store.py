#!/usr/bin/env python3
"""Seed store/golden.db from golden/ and mapping/. Idempotent: re-running
produces the same golden_sha values, no duplicate golden_config rows, and one
new load_run row."""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from store.golden_store import (DEFAULT_DB, GoldenRecord, connect, init_schema,
                                upsert_golden)

DOMAINS = [
    "www.rbcdemo.ca",
    "online.rbcdemo.ca",
    "api.rbcdemo.ca",
    "assets.rbcdemo.ca",
]


def git_head():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=str(DEFAULT_DB))
    args = p.parse_args()

    mapping_text = (REPO / "mapping/akamai-cloudflare-mapping.yaml").read_text()
    mapping = yaml.safe_load(mapping_text)
    mver = mapping["version"]

    conn = connect(args.db)
    init_schema(conn)
    now = datetime.now(timezone.utc).isoformat()
    commit = git_head()

    properties = json.loads((REPO / "fixtures/akamai/properties.json").read_text())
    prop_id = {i["propertyName"]: i["propertyId"]
               for i in properties["properties"]["items"]}

    for d in DOMAINS:
        gdir = REPO / "golden" / d
        main_tf = (gdir / "main.tf").read_text()
        rules_json = (gdir / "rules/rules.json").read_text()
        appsec_path = gdir / "appsec/security-config.json"
        appsec_json = appsec_path.read_text() if appsec_path.exists() else ""
        zone_id = json.loads(
            (REPO / "fixtures/cloudflare" / d / "zone.json").read_text()
        )["result"]["id"]
        sha = hashlib.sha256(
            (main_tf + rules_json + (appsec_json or "")).encode()).hexdigest()
        upsert_golden(conn, GoldenRecord(
            domain=d, akamai_property_id=prop_id[d], cloudflare_zone_id=zone_id,
            main_tf=main_tf, rules_json=rules_json,
            appsec_json=appsec_json or None, golden_sha=sha,
            mapping_version=mver, git_commit=commit,
            source_path=str(gdir.relative_to(REPO)), updated_at=now))

    conn.execute(
        """INSERT INTO mapping_registry (version, yaml_text, sha256, field_count, loaded_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(version) DO UPDATE SET
             yaml_text=excluded.yaml_text, sha256=excluded.sha256,
             field_count=excluded.field_count, loaded_at=excluded.loaded_at""",
        (mver, mapping_text,
         hashlib.sha256(mapping_text.encode()).hexdigest(),
         len(mapping["fields"]), now))
    conn.execute(
        "INSERT INTO load_run (started_at, git_commit, domains_loaded, mapping_version)"
        " VALUES (?,?,?,?)", (now, commit, len(DOMAINS), mver))
    conn.commit()
    print(f"loaded {len(DOMAINS)} domains into {args.db} (mapping v{mver})")


if __name__ == "__main__":
    main()
