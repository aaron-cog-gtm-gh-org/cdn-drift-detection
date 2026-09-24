CREATE TABLE IF NOT EXISTS golden_config (
  domain             TEXT PRIMARY KEY,
  akamai_property_id TEXT NOT NULL,
  cloudflare_zone_id TEXT NOT NULL,
  main_tf            TEXT NOT NULL,
  rules_json         TEXT NOT NULL,
  appsec_json        TEXT,
  golden_sha         TEXT NOT NULL,
  mapping_version    TEXT NOT NULL,
  git_commit         TEXT,
  source_path        TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mapping_registry (
  version     TEXT PRIMARY KEY,
  yaml_text   TEXT NOT NULL,
  sha256      TEXT NOT NULL,
  field_count INTEGER NOT NULL,
  loaded_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS load_run (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at      TEXT NOT NULL,
  git_commit      TEXT,
  domains_loaded  INTEGER NOT NULL,
  mapping_version TEXT NOT NULL
);
