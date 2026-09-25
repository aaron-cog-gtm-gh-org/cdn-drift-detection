"""Terraform IaC projection, shaped like the fixture documents.

Each domain under `terraform/` is that provider's desired state: the JSON
files hold every remediable value and the .tf files wire them in. `load_iac`
reads those files back and re-wraps the Cloudflare projections into the API
envelopes the fixtures use, so the same mapping JSONPaths resolve against
IaC exactly as they resolve against live documents:

  terraform/<domain>/cloudflare/zone-settings.json  -> {"result": [{"id":..,"value":..}]}
  terraform/<domain>/cloudflare/rulesets.json       -> {"result": [...]}
  terraform/<domain>/cloudflare/dns-records.json    -> {"result": [...]}
  terraform/<domain>/akamai/*.json                  -> passed through unchanged

`iac_sha` is the per-domain content hash used as report provenance (the
`golden_sha` slot) — a finding must trace to the exact IaC bytes it was
judged against.
"""
import hashlib
import json
from pathlib import Path

from drift.sources import DOMAINS, load_json

REPO = Path(__file__).resolve().parent.parent
IAC_ROOT = REPO / "terraform"

_AKAMAI_FILES = {
    "rules": "akamai/rules.json",
    "appsec": "akamai/appsec.json",
    "hostnames": "akamai/hostnames.json",
}
_CLOUDFLARE_FILES = {
    "settings": "cloudflare/zone-settings.json",
    "rulesets": "cloudflare/rulesets.json",
    "dns_records": "cloudflare/dns-records.json",
}


def iac_root(root=None):
    return Path(root) if root is not None else IAC_ROOT


def load_iac(domain, root=None):
    """{provider: {fixture_name: doc}} for one domain, API-shaped.

    Keys whose file does not exist are omitted (e.g. assets.rbcdemo.ca has
    no appsec.json), matching what a live fetch would return for a domain
    without that capability.
    """
    base = iac_root(root) / domain
    akamai = {}
    for name, rel in _AKAMAI_FILES.items():
        p = base / rel
        if p.exists():
            akamai[name] = load_json(p)
    cloudflare = {}
    settings_p = base / _CLOUDFLARE_FILES["settings"]
    if settings_p.exists():
        flat = load_json(settings_p)
        cloudflare["settings"] = {
            "result": [{"id": k, "value": v} for k, v in flat.items()]}
    for name in ("rulesets", "dns_records"):
        p = base / _CLOUDFLARE_FILES[name]
        if p.exists():
            cloudflare[name] = {"result": load_json(p)}
    return {"akamai": akamai, "cloudflare": cloudflare}


def iac_sha(domain, root=None):
    """sha256 over the domain's IaC files: sorted relative paths + contents."""
    base = iac_root(root) / domain
    h = hashlib.sha256()
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        h.update(p.relative_to(base).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def load_all(root=None, domains=None):
    return {d: load_iac(d, root) for d in (domains or DOMAINS)}
