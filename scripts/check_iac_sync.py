#!/usr/bin/env python3
"""Baseline gate: every mapped field's IaC value must equal its live value.

This is a *baseline* gate, deliberately NOT part of pytest: it asserts that
the Terraform tree under `terraform/` is in sync with each provider's live
state (the fixture tree). After a remediation PR, the fixed field will
legitimately differ — the IaC is then the pending-apply desired state — so
this gate can only certify a known-synced starting point.

For each mapped field, each domain, and each provider side, the mapping's
JSONPath is resolved against both the fixture document and the `drift.iac`
projection of the same provider documents, run through the same transforms,
and compared. Exits non-zero on any mismatch.

Usage: scripts/check_iac_sync.py  (run from repo root; requires pyyaml and
jsonpath-ng)
"""
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from drift.iac import load_iac
from drift.sources import DiskSource, DOMAINS
from validate_cross_drift import (apply_side_transforms, canon, get_default,
                                  resolve)

REPO = Path(__file__).resolve().parent.parent

UNORDERED = {"set_equal", "semantic_enum"}


def equal(field, provider, live, iac, mapping):
    """Canonicalized equality — same vocabulary on both sides, so the
    provider column of the value table applies to each."""
    lv = [canon(v, provider, field, mapping) for v in live]
    iv = [canon(v, provider, field, mapping) for v in iac]
    if field["comparator"] in UNORDERED:
        return sorted(map(str, lv)) == sorted(map(str, iv))
    return [str(v) for v in lv] == [str(v) for v in iv]


def main():
    mapping = yaml.safe_load(
        (REPO / "mapping" / "akamai-cloudflare-mapping.yaml").read_text())
    source = DiskSource()
    iac = {d: load_iac(d) for d in DOMAINS}
    live_cache, mismatches, skipped, checked = {}, [], [], 0

    def live_doc(provider, fixture_name, domain):
        key = (provider, fixture_name, domain)
        if key not in live_cache:
            live_cache[key] = source.get(provider, fixture_name, domain)
        return live_cache[key]

    for field in mapping["fields"]:
        fid = field["id"]
        for d in field.get("domains", DOMAINS):
            for provider in ("akamai", "cloudflare"):
                side = field.get(provider)
                if not side or side.get("unsupported"):
                    continue
                fixture_name = side.get(
                    "fixture",
                    "rules" if provider == "akamai" else "settings")
                iac_doc = iac[d][provider].get(fixture_name)
                if iac_doc is None:
                    skipped.append(f"{fid}: {provider}/{fixture_name} has no "
                                   f"IaC counterpart on {d}")
                    continue
                live_vals = resolve(side["path"],
                                    live_doc(provider, fixture_name, d), d)
                iac_vals = resolve(side["path"], iac_doc, d)
                if not live_vals:
                    live_vals, _ = get_default(
                        mapping, provider, fixture_name, side["path"])
                if not iac_vals:
                    iac_vals, _ = get_default(
                        mapping, provider, fixture_name, side["path"])
                if not live_vals and not iac_vals:
                    if side.get("allow_absent"):
                        continue  # migration gap, not a sync issue
                    mismatches.append(f"{fid}: {provider} path resolves to "
                                      f"nothing on {d} (live and IaC)")
                    continue
                live_t = apply_side_transforms(live_vals, side, d, field)
                iac_t = apply_side_transforms(iac_vals, side, d, field)
                checked += 1
                if not equal(field, provider, live_t, iac_t, mapping):
                    mismatches.append(
                        f"{fid}: {provider} {d}: live={live_t} iac={iac_t}")

    print(f"checked {checked} provider field bindings across "
          f"{len(mapping['fields'])} mapped fields")
    if skipped:
        print(f"\nskipped {len(skipped)} bindings with no IaC counterpart:")
        for s in skipped:
            print("  SKIP", s)
    if mismatches:
        print("\nIAC/LIVE MISMATCHES:")
        for m in mismatches:
            print("  FAIL", m)
        sys.exit(1)
    print("\nIAC SYNC OK: Terraform tree matches live state on every "
          "resolvable mapped field")


if __name__ == "__main__":
    main()
