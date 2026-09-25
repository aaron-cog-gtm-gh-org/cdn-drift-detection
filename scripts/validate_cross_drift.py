#!/usr/bin/env python3
"""Cross-provider validator for the CDN drift-detection demo.

Premise: each provider's Terraform is in sync with that provider's own live
state (scripts/check_iac_sync.py certifies the baseline), so the only defect
worth reporting is that the two providers disagree *with each other*.

For each domain and each mapped field, the Akamai path and the Cloudflare
path are resolved against the live documents and the pair is classified
into exactly one bucket:

  not_comparable      one side cannot express the field (`unsupported: true`)
                      or is not applicable; reason: unsupported_at_akamai /
                      unsupported_at_cloudflare / provider_specific
  missing_at_akamai /
  missing_at_cloudflare
                      both providers CAN express it; one side is configured
                      and the other's path resolves to nothing. A Cloudflare
                      zone setting absent from the response but listed in
                      `defaults.cloudflare_settings` counts as present at
                      its default value, not as missing.
  disagreement        both sides resolve; the comparator says not equivalent
  equivalent          both sides resolve; the comparator says equivalent —
                      `equivalent_but_different` marks the subset whose raw
                      renderings differed textually (the semantic-comparison
                      evidence the demo leans on)

Ordered comparators (`numeric_ge`, `semantic_enum_ge`) were "provider vs
golden floor". In a peer comparison there is no baseline, so they degenerate
to equality: two sides are equivalent only if neither is strictly weaker
than the other.

Usage: scripts/validate_cross_drift.py [--source disk|api] [--check]
(run from repo root; requires pyyaml and jsonpath-ng). `--check` asserts the
classified findings equal the documented scenario set and exits non-zero on
any mismatch.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml
from jsonpath_ng.ext import parse as jparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from drift.sources import ApiSource, DiskSource, DOMAINS, fixture_path, load_json

REPO = Path(__file__).resolve().parent.parent

# The settled scenario set (docs/drift-scenarios.md): exactly these seven
# findings — six disagreements and one migration gap.
EXPECTED = [
    {"domain": "online.rbcdemo.ca", "field": "tls.min_version",
     "bucket": "disagreement", "severity": "critical"},
    {"domain": "www.rbcdemo.ca", "field": "waf.managed_ruleset_enabled",
     "bucket": "disagreement", "severity": "critical"},
    {"domain": "api.rbcdemo.ca", "field": "ratelimit.partner_api",
     "bucket": "disagreement", "severity": "high"},
    {"domain": "api.rbcdemo.ca", "field": "cors.allowed_origins",
     "bucket": "disagreement", "severity": "high"},
    {"domain": "www.rbcdemo.ca", "field": "tls.hsts_max_age",
     "bucket": "disagreement", "severity": "medium"},
    {"domain": "assets.rbcdemo.ca", "field": "caching.default_ttl",
     "bucket": "disagreement", "severity": "medium"},
    {"domain": "online.rbcdemo.ca", "field": "headers.security_static",
     "bucket": "missing_at_cloudflare", "severity": "medium"},
]

# ---------------- comparators ----------------

TRUTHY = {True, 1, "1", "on", "true", "yes", "enabled", "ON", "TRUE"}
FALSY = {False, 0, "0", "off", "false", "no", "disabled", "OFF", "FALSE"}


def to_bool(v):
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    raise ValueError(f"cannot coerce {v!r} to bool")


def to_num(v):
    if isinstance(v, (int, float)):
        return float(v)
    return float(str(v).strip())


def to_seconds(v):
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().lower()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(s|m|h|d|w)?", s)
    if not m:
        raise ValueError(f"cannot parse duration {v!r}")
    n = float(m.group(1))
    unit = m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


def to_set(v):
    if v is None:
        return set()
    if isinstance(v, (list, tuple, set)):
        out = set()
        for i in v:
            out |= to_set(i)
        return out
    return {str(v).strip()}


def normalize_expr(v):
    return re.sub(r"[\s'\"]+", "", str(v)).lower()


# ---------------- value resolution ----------------


def resolve(path, doc, domain):
    """Return list of matched values (may be empty)."""
    expr = jparse(path.replace("{domain}", domain))
    return [m.value for m in expr.find(doc)]


def apply_extract(values, pattern):
    out = []
    for v in values:
        m = re.search(pattern, str(v))
        out.append(m.group(1) if m else v)
    return out


def apply_side_transforms(values, side, domain, field):
    vt = field.get("value_translate", {})
    out = []
    for v in values:
        if isinstance(v, (list, tuple)):
            sub = apply_side_transforms(list(v), side, domain, field)
            out.extend(sub if sub else ["[]"])  # empty list = explicit "none" marker
            continue
        if isinstance(v, str) and v in vt:
            v = vt[v].format(domain=domain)
        if side.get("strip_prefix") and isinstance(v, str):
            if v.startswith(side["strip_prefix"]):
                v = v[len(side["strip_prefix"]):]
        if side.get("split") and isinstance(v, str):
            out.extend(s.strip() for s in v.split(side["split"]) if s.strip())
            continue
        if side.get("extract_all") and isinstance(v, str):
            out.extend(re.findall(side["extract_all"], v))
            continue
        out.append(v)
    if field.get("extract"):
        out = apply_extract(out, field["extract"])
    return out


def get_default(mapping, provider, fixture_name, path):
    """Provider-default suppression: settings fixture absent => default value."""
    if provider != "cloudflare" or fixture_name != "settings":
        return None, False
    m = re.search(r"@\.id=='([^']+)'", path)
    if not m:
        return None, False
    sid = m.group(1)
    defaults = (mapping.get("defaults") or {}).get("cloudflare_settings", {})
    if sid in defaults:
        return [defaults[sid]], True
    return None, False


# ---------------- canonicalization ----------------


def canon(value, provider_key, field, mapping):
    table = (mapping.get("value_tables") or {}).get(field.get("value_table") or "", {})
    if not table:
        return value
    col = table.get(provider_key)
    if col is None:
        return value
    key = value if not isinstance(value, list) else ("[]" if not value else "*")
    return col.get(str(key), col.get(key, value))


# ---------------- symmetric comparison ----------------

UNORDERED = {"set_equal", "semantic_enum", "regex_equivalent"}


def compare_pair(field, akamai_vals, cloudflare_vals, mapping):
    """Symmetric equivalence: each side is canonicalized through its own
    provider vocabulary, then the comparator decides. Ordered comparators
    degenerate to equality — with no baseline, equivalence requires that
    neither side be strictly weaker than the other."""
    comp = field["comparator"]
    av = [canon(v, "akamai", field, mapping) for v in akamai_vals]
    cv = [canon(v, "cloudflare", field, mapping) for v in cloudflare_vals]

    if comp == "presence":
        return all(v not in (None, "", False) for v in av + cv)
    if comp == "exact":
        return [str(v) for v in av] == [str(v) for v in cv]
    if comp == "bool_eq":
        return [to_bool(v) for v in av] == [to_bool(v) for v in cv]
    if comp in ("numeric_eq", "numeric_ge"):
        return [to_num(v) for v in av] == [to_num(v) for v in cv]
    if comp == "duration_eq":
        return [to_seconds(v) for v in av] == [to_seconds(v) for v in cv]
    if comp == "set_equal":
        return set().union(*[to_set(v) for v in av]) == \
            set().union(*[to_set(v) for v in cv])
    if comp == "semantic_enum":
        return sorted(str(v) for v in av) == sorted(str(v) for v in cv)
    if comp == "semantic_enum_ge":
        try:
            return sorted(float(v) for v in av) == sorted(float(v) for v in cv)
        except (TypeError, ValueError):
            return sorted(str(v) for v in av) == sorted(str(v) for v in cv)
    if comp == "regex_equivalent":
        return sorted(normalize_expr(v) for v in av) == \
            sorted(normalize_expr(v) for v in cv)
    raise ValueError(f"unknown comparator {comp}")


def _raw_equal(field, akamai_vals, cloudflare_vals):
    """Textual equality of the raw (transformed, un-canonicalized) values —
    used only to flag `equivalent_but_different`."""
    if field["comparator"] in UNORDERED:
        return sorted(str(v) for v in akamai_vals) == \
            sorted(str(v) for v in cloudflare_vals)
    return [str(v) for v in akamai_vals] == [str(v) for v in cloudflare_vals]


# ---------------- classification ----------------


def classify_field(field, domain, docs, mapping):
    """Classify one (field, domain) pair. `docs` maps
    (provider, fixture_name) -> document. Returns a dict with bucket,
    reason, and the resolved values per side."""
    out = {"domain": domain, "field": field["id"],
           "severity": field["severity"]}
    sides = {}
    reasons = []
    for provider in ("akamai", "cloudflare"):
        side = field.get(provider)
        if side is None:
            reasons.append("provider_specific")
            continue
        if side.get("unsupported"):
            reasons.append(f"unsupported_at_{provider}")
            continue
        fixture_name = side.get(
            "fixture", "rules" if provider == "akamai" else "settings")
        doc = docs.get((provider, fixture_name))
        vals = resolve(side["path"], doc, domain) if doc is not None else []
        if not vals:
            defaults, defaulted = get_default(
                mapping, provider, fixture_name, side["path"])
            vals = (apply_side_transforms(defaults, side, domain, field)
                    if defaulted else [])
        else:
            vals = apply_side_transforms(vals, side, domain, field)
        sides[provider] = vals
    if reasons:
        out.update(bucket="not_comparable", reason="+".join(reasons))
        return out
    a_vals, c_vals = sides["akamai"], sides["cloudflare"]
    out["akamai"] = a_vals
    out["cloudflare"] = c_vals
    if not a_vals and not c_vals:
        out.update(bucket="not_comparable", reason="provider_specific")
    elif not a_vals:
        out.update(bucket="missing_at_akamai")
    elif not c_vals:
        out.update(bucket="missing_at_cloudflare")
    elif compare_pair(field, a_vals, c_vals, mapping):
        out.update(bucket="equivalent",
                   different=not _raw_equal(field, a_vals, c_vals))
    else:
        out.update(bucket="disagreement")
    return out


def classify(domains, source, mapping):
    """Run the full classification; returns list of per-(domain, field)
    result dicts."""
    doc_cache = {}

    def doc(provider, fixture_name, domain):
        key = (provider, fixture_name, domain)
        if key not in doc_cache:
            try:
                doc_cache[key] = source.get(provider, fixture_name, domain)
            except Exception:
                doc_cache[key] = None
        return doc_cache[key]

    results = []
    for field in mapping["fields"]:
        for d in field.get("domains", domains):
            docs = {}
            for provider in ("akamai", "cloudflare"):
                side = field.get(provider)
                if side and not side.get("unsupported"):
                    fn = side.get("fixture", "rules" if provider == "akamai"
                                  else "settings")
                    docs[(provider, fn)] = doc(provider, fn, d)
            results.append(classify_field(field, d, docs, mapping))
    return results


# ---------------- report ----------------

FINDING_BUCKETS = {"disagreement", "missing_at_akamai", "missing_at_cloudflare"}


def _fmt(vals):
    return ", ".join(str(v) for v in vals) if vals else "(absent)"


def report(results, domains):
    for d in domains:
        rows = [r for r in results if r["domain"] == d]
        counts = {}
        for r in rows:
            counts[r["bucket"]] = counts.get(r["bucket"], 0) + 1
        diff = sum(1 for r in rows if r["bucket"] == "equivalent"
                   and r.get("different"))
        print(f"{d}: {len(rows)} fields — "
              + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
              + f" (of which equivalent_but_different={diff})")
    print("\nDETAIL (findings and textually-different equivalences):")
    for r in sorted(results, key=lambda x: (x["domain"], x["field"])):
        if r["bucket"] in FINDING_BUCKETS:
            print(f"  {r['bucket']:22s} {r['domain']:22s} {r['field']:36s} "
                  f"akamai={_fmt(r.get('akamai'))} "
                  f"cloudflare={_fmt(r.get('cloudflare'))} "
                  f"severity={r['severity']}")
        elif r["bucket"] == "equivalent" and r.get("different"):
            print(f"  {'equivalent_but_different':22s} {r['domain']:22s} "
                  f"{r['field']:36s} akamai={_fmt(r.get('akamai'))} "
                  f"cloudflare={_fmt(r.get('cloudflare'))}")


def check(results):
    findings = [r for r in results if r["bucket"] in FINDING_BUCKETS]
    got = {(r["domain"], r["field"], r["bucket"], r["severity"])
           for r in findings}
    want = {(e["domain"], e["field"], e["bucket"], e["severity"])
            for e in EXPECTED}
    missing, extra = want - got, got - want
    print("\nSCENARIO CHECK:")
    for e in EXPECTED:
        key = (e["domain"], e["field"], e["bucket"], e["severity"])
        mark = "PASS" if key in got else "MISS"
        print(f"  {mark} {e['domain']:22s} {e['field']:36s} "
              f"{e['bucket']:22s} {e['severity']}")
    if extra:
        print("  UNEXPECTED FINDINGS:")
        for x in sorted(extra):
            print("   ", x)
    if missing or extra:
        print(f"\nVALIDATION FAILED ({len(missing)} missing, "
              f"{len(extra)} unexpected)")
        return 1
    print(f"\nVALIDATION PASSED: {len(want)} expected findings produced")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["disk", "api"], default="disk")
    ap.add_argument("--akamai-base", default="http://127.0.0.1:8081")
    ap.add_argument("--cloudflare-base", default="http://127.0.0.1:8082")
    ap.add_argument("--check", action="store_true",
                    help="assert the classified findings equal the "
                         "documented scenario set; exit non-zero otherwise")
    args = ap.parse_args()

    mapping = yaml.safe_load(
        (REPO / "mapping" / "akamai-cloudflare-mapping.yaml").read_text())

    if args.source == "api":
        source = ApiSource(args.akamai_base, args.cloudflare_base)
    else:
        source = DiskSource()
        for d in DOMAINS:
            for p in REPO.glob(f"fixtures/*/{d}/*.json"):
                try:
                    load_json(p)
                except Exception as e:
                    sys.exit(f"unparseable JSON {p}: {e}")
        load_json(REPO / "fixtures/akamai/properties.json")

    results = classify(DOMAINS, source, mapping)
    report(results, DOMAINS)
    if args.check:
        sys.exit(check(results))


if __name__ == "__main__":
    main()
