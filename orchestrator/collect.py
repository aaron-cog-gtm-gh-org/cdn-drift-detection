"""Collect per-domain provider bundles through the simulator HTTP APIs.

A bundle is everything a detection session sees about the *live* estate for
one domain — the same documents the validator compares, fetched over the APIs
(`ApiSource`), never read from the fixture tree. Bundles are written under
`artifacts/<run_id>/` as pretty-printed, stable-ordered JSON so a run is
reproducible and diffable, plus a `manifest.json` recording provenance.
"""
import hashlib
import json
from pathlib import Path

from drift.sources import ApiSource, DOMAINS


def _result(doc):
    """Unwrap the Cloudflare envelope; pass Akamai docs through."""
    return doc["result"] if isinstance(doc, dict) and "result" in doc else doc


def _fetch(source, provider, kind, domain, on_fetch):
    doc = source.get(provider, kind, domain)
    if on_fetch:
        on_fetch(provider, kind, domain, getattr(source, "last_url", None))
    return _result(doc)


def collect_akamai(source, domain, on_fetch=None):
    """Akamai side of a domain bundle — property, rules, hostnames, appsec."""
    rules = _fetch(source, "akamai", "rules", domain, on_fetch)
    hostnames = _fetch(source, "akamai", "hostnames", domain, on_fetch)
    appsec = None
    if source.meta[domain].get("config_id") is not None:
        appsec = _fetch(source, "akamai", "appsec", domain, on_fetch)
    return {
        "property": {
            "propertyId": source.meta[domain]["property_id"],
            "latestVersion": source.meta[domain]["version"],
            "propertyName": domain,
        },
        "rules": rules,
        "hostnames": hostnames,
        "appsec": appsec,
    }


def collect_cloudflare(source, domain, on_fetch=None):
    """Cloudflare side of a domain bundle — zone, settings, rulesets, DNS."""
    return {
        "zone": _fetch(source, "cloudflare", "zone", domain, on_fetch),
        "settings": _fetch(source, "cloudflare", "settings", domain, on_fetch),
        "rulesets": _fetch(source, "cloudflare", "rulesets", domain, on_fetch),
        "dns_records": _fetch(source, "cloudflare", "dns_records", domain,
                              on_fetch),
    }


def collect_domain(source, domain, on_fetch=None):
    """Fetch the full provider bundle for one domain via the simulator APIs."""
    return {
        "akamai": collect_akamai(source, domain, on_fetch),
        "cloudflare": collect_cloudflare(source, domain, on_fetch),
    }


def collect_all(source=None, domains=None, akamai_base=None,
                cloudflare_base=None, on_fetch=None):
    source = source or ApiSource(akamai_base, cloudflare_base)
    domains = domains or DOMAINS
    return {d: collect_domain(source, d, on_fetch) for d in domains}


def golden_bundle(domain, mapping_doc, root=None):
    """The third per-domain artifact: everything a detection session needs
    to judge, sourced from the same IaC tree `golden_info` reads — the
    terraform/<domain> module in full.

    `mapping_doc` is the parsed mapping YAML; only the fields scoped to this
    domain are carried (a field with no `domains:` list applies to every
    domain).
    """
    from drift.iac import iac_root, iac_sha
    d = domain
    files = {}
    for p in sorted(iac_root(root).joinpath(d).rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(iac_root(root) / d).as_posix()
        files[rel] = json.loads(p.read_text()) if p.suffix == ".json" \
            else p.read_text()
    scoped = [f for f in mapping_doc.get("fields", [])
              if f.get("domains") is None or d in f["domains"]]
    return {
        "domain": d,
        "golden_sha": iac_sha(d, root),
        "mapping_version": mapping_doc.get("version"),
        "files": files,
        "mapping": {
            "version": mapping_doc.get("version"),
            "defaults": mapping_doc.get("defaults", {}),
            "value_tables": mapping_doc.get("value_tables", {}),
            # the vocabulary this domain's fields actually use — semantics
            # as data, since YAML comments do not survive parsing
            "flag_definitions": {
                k: v for k, v in
                mapping_doc.get("flag_definitions", {}).items()
                if any(f.get("akamai", {}).get(k) or f.get("cloudflare",
                       {}).get(k) for f in scoped)},
            "comparator_definitions": {
                k: v for k, v in
                mapping_doc.get("comparator_definitions", {}).items()
                if k in {f.get("comparator") for f in scoped}},
            # every key's meaning, shipped whole — bare data is how the
            # http2-as-drift misreading happened
            "key_definitions": mapping_doc.get("key_definitions", {}),
            "fields": scoped,
        },
    }


def _dump(path, obj, sort_keys=True):
    text = json.dumps(obj, indent=2, sort_keys=sort_keys) + "\n"
    Path(path).write_text(text)
    return hashlib.sha256(text.encode()).hexdigest()


def write_bundles(run_id, bundles, golden_shas, mapping_version, outdir,
                  attachment_urls=None):
    """Write per-domain bundles + manifest; returns the manifest dict.

    `golden_shas` maps domain -> sha256 of that domain's golden tree — the
    provenance is per-domain because the content differs per domain.
    """
    outdir = Path(outdir) / run_id
    outdir.mkdir(parents=True, exist_ok=True)
    attachment_urls = attachment_urls or {}
    manifest = {
        "run_id": run_id,
        "mapping_version": mapping_version,
        "sim_bases": None,
        "files": {},
    }
    for domain, bundle in bundles.items():
        entry = {"golden_sha": golden_shas[domain]}
        for side in ("akamai", "cloudflare", "golden"):
            if side not in bundle:
                continue
            fname = f"{domain}.{side}.json"
            path = outdir / fname
            entry[side] = {
                "path": str(path),
                # the parsed mapping carries YAML-bool keys (on/off) that
                # sort_keys cannot order against strings; insertion order
                # is deterministic either way
                "sha256": _dump(path, bundle[side],
                                sort_keys=(side != "golden")),
                "attachment_url": attachment_urls.get(fname),
            }
        manifest["files"][domain] = entry
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def attachment_manifest(domain, manifest):
    """The short rendered list the detection prompt embeds, naming each
    attachment and what it holds."""
    entry = manifest["files"][domain]
    return "\n".join([
        f"- `{Path(entry['akamai']['path']).name}` — the domain's live Akamai "
        "state: property rule tree, hostname bindings, and (where the property "
        "carries one) its App Sec security configuration export.",
        f"- `{Path(entry['cloudflare']['path']).name}` — the domain's live "
        "Cloudflare state: zone settings, every ruleset in full, and DNS "
        "records for the zone.",
        f"- `{Path(entry['golden']['path']).name}` — the intended state this "
        "domain is judged against: golden_sha, main.tf, the golden rule tree "
        "and App Sec config, and the field mapping scoped to this domain.",
    ])
