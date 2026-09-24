"""SQLite golden-state store. golden.db is generated — see .gitignore."""
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent.parent
DEFAULT_DB = REPO / "store" / "golden.db"
SCHEMA = Path(__file__).resolve().parent / "schema.sql"


@dataclass
class GoldenRecord:
    domain: str
    akamai_property_id: str
    cloudflare_zone_id: str
    main_tf: str
    rules_json: str
    appsec_json: Optional[str]
    golden_sha: str
    mapping_version: str
    git_commit: Optional[str]
    source_path: str
    updated_at: str


def connect(db_path=DEFAULT_DB):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn):
    conn.executescript(SCHEMA.read_text())
    conn.commit()


def upsert_golden(conn, record: GoldenRecord):
    conn.execute(
        """INSERT INTO golden_config
           (domain, akamai_property_id, cloudflare_zone_id, main_tf, rules_json,
            appsec_json, golden_sha, mapping_version, git_commit, source_path,
            updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(domain) DO UPDATE SET
             akamai_property_id=excluded.akamai_property_id,
             cloudflare_zone_id=excluded.cloudflare_zone_id,
             main_tf=excluded.main_tf, rules_json=excluded.rules_json,
             appsec_json=excluded.appsec_json, golden_sha=excluded.golden_sha,
             mapping_version=excluded.mapping_version,
             git_commit=excluded.git_commit, source_path=excluded.source_path,
             updated_at=excluded.updated_at""",
        (record.domain, record.akamai_property_id, record.cloudflare_zone_id,
         record.main_tf, record.rules_json, record.appsec_json,
         record.golden_sha, record.mapping_version, record.git_commit,
         record.source_path, record.updated_at))
    conn.commit()


def get_golden(conn, domain) -> Optional[GoldenRecord]:
    row = conn.execute("SELECT * FROM golden_config WHERE domain=?",
                       (domain,)).fetchone()
    return GoldenRecord(**dict(row)) if row else None


def list_domains(conn):
    return [r["domain"] for r in
            conn.execute("SELECT domain FROM golden_config ORDER BY domain")]


def get_mapping(conn, version=None):
    if version is None:
        row = conn.execute(
            "SELECT * FROM mapping_registry ORDER BY loaded_at DESC LIMIT 1"
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM mapping_registry WHERE version=?",
            (version,)).fetchone()
    return dict(row) if row else None
