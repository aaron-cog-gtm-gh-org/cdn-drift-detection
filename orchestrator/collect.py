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


def _dump(path, obj):
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
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
        for side in ("akamai", "cloudflare"):
            fname = f"{domain}.{side}.json"
            path = outdir / fname
            entry[side] = {
                "path": str(path),
                "sha256": _dump(path, bundle[side]),
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
    ])
