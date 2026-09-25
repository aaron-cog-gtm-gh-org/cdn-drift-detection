#!/usr/bin/env python3
"""Phase-01 fixture validator for the CDN drift-detection demo.

Checks:
  1. every JSON fixture parses;
  2. every mapping path resolves against the fixture it claims to address
     (fails loudly on paths that resolve to nothing);
  3. every comparator is applied to fixture vs. golden and findings printed;
  4. the resulting findings equal the set documented in
     docs/drift-scenarios.md (`expected_findings` yaml block) - no more, no
     less, which covers both suppression cases by requiring no extra findings.

Usage: scripts/validate_fixtures.py  (run from repo root; requires pyyaml and
jsonpath-ng, e.g. in the phase-01 venv)
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from jsonpath_ng.ext import parse as jparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from drift.sources import ApiSource, DiskSource, DOMAINS, fixture_path, load_json

REPO = Path(__file__).resolve().parent.parent

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
        return value  # literal goldens are already canonical
    key = value if not isinstance(value, list) else ("[]" if not value else "*")
    return col.get(str(key), col.get(key, value))


def compare_values(field, provider, values, golden, golden_key, mapping):
    """Return True if values are semantically equal to golden."""
    comp = field["comparator"]
    vs = [canon(v, provider, field, mapping) for v in values]
    gs = [canon(g, golden_key, field, mapping) for g in golden]

    if comp == "presence":
        return bool(vs) and all(v not in (None, "", False) for v in vs)
    if comp == "exact":
        return [str(v) for v in vs] == [str(g) for g in gs]
    if comp == "bool_eq":
        return [to_bool(v) for v in vs] == [to_bool(g) for g in gs]
    if comp == "numeric_eq":
        return [to_num(v) for v in vs] == [to_num(g) for g in gs]
    if comp == "numeric_ge":
        return all(to_num(v) >= to_num(gs[0]) for v in vs)
    if comp == "duration_eq":
        return [to_seconds(v) for v in vs] == [to_seconds(g) for g in gs]
    if comp == "set_equal":
        return set().union(*[to_set(v) for v in vs]) == set().union(*[to_set(g) for g in gs])
    if comp == "semantic_enum":
        return sorted(str(v) for v in vs) == sorted(str(g) for g in gs)
    if comp == "semantic_enum_ge":
        try:
            return all(float(v) >= float(gs[0]) for v in vs)
        except ValueError:
            return vs == gs
    if comp == "regex_equivalent":
        return sorted(normalize_expr(v) for v in vs) == sorted(normalize_expr(g) for g in gs)
    raise ValueError(f"unknown comparator {comp}")


# ---------------- expected findings ----------------


def load_expected():
    doc = (REPO / "docs" / "drift-scenarios.md").read_text()
    m = re.search(r"```expected_findings\n(.*?)```", doc, re.S)
    if not m:
        sys.exit("docs/drift-scenarios.md is missing the expected_findings block")
    return yaml.safe_load(m.group(1))


# ---------------- main ----------------


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["disk", "api"], default="disk")
    ap.add_argument("--akamai-base", default="http://127.0.0.1:8081")
    ap.add_argument("--cloudflare-base", default="http://127.0.0.1:8082")
    args = ap.parse_args()

    mapping = yaml.safe_load((REPO / "mapping" / "akamai-cloudflare-mapping.yaml").read_text())
    fields = mapping["fields"]

    # 1. fixture source
    errors = []
    if args.source == "api":
        source = ApiSource(args.akamai_base, args.cloudflare_base)
    else:
        source = DiskSource()
        for d in DOMAINS:
            for p in REPO.glob(f"fixtures/*/{d}/*.json"):
                try:
                    load_json(p)
                except Exception as e:
                    errors.append(f"unparseable JSON {p}: {e}")
        load_json(REPO / "fixtures/akamai/properties.json")
    fixture_cache = {}

    def fixture_doc(provider, fixture_name, domain):
        key = (provider, fixture_name, domain)
        if key not in fixture_cache:
            fixture_cache[key] = source.get(provider, fixture_name, domain)
        return fixture_cache[key]

    # 2. golden source (the terraform/ IaC tree — Akamai-shaped docs)
    golden_cache = {}

    def golden_doc(domain, fixture_name):
        rel = {"rules": "akamai/rules.json",
               "appsec": "akamai/appsec.json"}[fixture_name]
        key = (domain, fixture_name)
        if key not in golden_cache:
            golden_cache[key] = load_json(REPO / "terraform" / domain / rel)
        return golden_cache[key]

    findings = []
    path_report = []

    for field in fields:
        fid = field["id"]
        domains = field.get("domains", DOMAINS)
        for d in domains:
            # golden value
            g = field["golden"]
            if "path" in g:
                golden_vals = apply_side_transforms(
                    resolve(g["path"], golden_doc(d, g.get("fixture", "rules")), d), {}, d, field)
                golden_key = "akamai"  # golden docs are Akamai-shaped
                if not golden_vals:
                    errors.append(f"{fid}: golden path resolves to nothing on {d}")
                    continue
            elif "values" in g:
                golden_vals = [g["values"][d]]
                golden_key = "literal"
            else:
                golden_vals = [g["literal"]]
                golden_key = "literal"

            for provider in ("akamai", "cloudflare"):
                side = field.get(provider)
                if not side or side.get("unsupported"):
                    continue
                fixture_name = side.get("fixture", "rules" if provider == "akamai" else "settings")
                if args.source == "disk" and not fixture_path(provider, fixture_name, d).exists():
                    errors.append(f"{fid}: fixture {fixture_path(provider, fixture_name, d)} missing")
                    continue
                try:
                    doc = fixture_doc(provider, fixture_name, d)
                except Exception as e:
                    errors.append(f"{fid}: cannot fetch {provider}/{fixture_name}/{d}: {e}")
                    continue
                vals = resolve(side["path"], doc, d)
                defaulted = False
                if not vals:
                    vals, defaulted = get_default(mapping, provider, fixture_name, side["path"])
                if not vals:
                    if side.get("allow_absent"):
                        findings.append({"domain": d, "provider": provider,
                                         "field": fid, "severity": field["severity"],
                                         "route": "human", "kind": "migration_gap"})
                        continue
                    errors.append(f"{fid}: {provider} path resolves to nothing on {d}")
                    continue
                vals = apply_side_transforms(vals, side, d, field)
                path_report.append(f"  ok {fid:38s} {provider:10s} {d}")
                if compare_values(field, provider, vals, golden_vals, golden_key, mapping):
                    continue
                findings.append({"domain": d, "provider": provider, "field": fid,
                                 "severity": field["severity"], "route": "iac_pr",
                                 "kind": "drift"})

    # report
    print(f"resolved {len(path_report)} path bindings across {len(fields)} mapped fields")
    if errors:
        print("\nPATH RESOLUTION ERRORS:")
        for e in errors:
            print("  FAIL", e)

    print("\nFINDINGS:")
    for f in sorted(findings, key=lambda x: (x["domain"], x["provider"], x["field"])):
        print(f"  {f['kind']:14s} {f['domain']:22s} {f['provider']:10s} "
              f"{f['field']:36s} severity={f['severity']}")

    expected = load_expected()
    got = {(f["domain"], f["provider"], f["field"], f["severity"])
           for f in findings}
    want = {(e["domain"], e["provider"], e["field"], e["severity"])
            for e in expected}
    missing = want - got
    extra = got - want
    ok = not errors and not missing and not extra
    print("\nSCENARIO CHECK:")
    for e in expected:
        key = (e["domain"], e["provider"], e["field"], e["severity"])
        mark = "PASS" if key in got else "MISS"
        print(f"  {mark} {e['id']:5s} {e['domain']:22s} {e['provider']:10s} {e['field']:36s} {e['severity']}")
    if extra:
        print("  UNEXPECTED FINDINGS:")
        for x in sorted(extra):
            print("   ", x)
    if errors or missing or extra:
        print(f"\nVALIDATION FAILED ({len(errors)} path errors, "
              f"{len(missing)} missing, {len(extra)} unexpected)")
        sys.exit(1)
    print(f"\nVALIDATION PASSED: {len(expected)} expected findings, "
          f"{len(got)} produced; suppression cases clean")


if __name__ == "__main__":
    main()
