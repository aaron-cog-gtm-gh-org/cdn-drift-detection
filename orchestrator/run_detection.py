"""One detection session per domain, end to end.

  python -m orchestrator.run_detection \
      [--domain D ...] [--dry-run] [--max-acu 10] [--devin-mode normal] \
      [--no-remediate] [--poll-interval 20]

Flow: collect provider bundles over the simulator APIs -> write
`artifacts/<run_id>/` -> upload both bundles per domain -> create all
detection sessions up front (so they run in parallel) -> poll them all to a
terminal state -> validate each session's structured output against
DETECTION_SCHEMA locally -> print the findings table, save the reports under
`artifacts/<run_id>/detection/` -> hand findings to `remediate` unless
`--no-remediate`.

`--dry-run` collects and renders everything but uploads nothing and creates
no sessions — it prints the exact prompts and the schema so the substitution
can be eyeballed before spending ACUs.

Tests never call this against the real API; the one live run is manual.
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drift.sources import DOMAINS
from orchestrator import collect, config
from orchestrator.devin_client import DevinClient
from orchestrator.prompts import DETECTION_PROMPT, DOMAIN_ROLES
from orchestrator.remediate import execute_remediation, plan_remediation
from orchestrator.schema import DETECTION_SCHEMA
from store.golden_store import connect, get_golden, get_mapping


def golden_info(db_path=None):
    """golden_sha + mapping_version out of the golden store."""
    conn = connect(db_path or config.GOLDEN_DB)
    try:
        rec = get_golden(conn, DOMAINS[0])
        if rec is None:
            sys.exit(f"golden store is empty — run "
                     f"scripts/load_golden_store.py first.")
        m = get_mapping(conn)
        return rec.golden_sha, (m["version"] if m else "unknown")
    finally:
        conn.close()


def render_prompt(domain, golden_sha, mapping_version, manifest):
    return DETECTION_PROMPT.format(
        domain=domain, domain_role=DOMAIN_ROLES[domain],
        golden_sha=golden_sha, mapping_version=mapping_version,
        golden_branch=config.GOLDEN_BRANCH,
        attachment_manifest=collect.attachment_manifest(domain, manifest))


# ---------------- structured-output validation ----------------


def _err(errors, msg):
    errors.append(msg)


def validate_report(domain, report):
    """Local check of the session's structured output against the contract.

    Not a full JSON Schema engine — it enforces the load-bearing parts:
    required keys, enum membership, and that the identity fields echo what we
    sent. Returns a list of problems; empty means conforming.
    """
    errors = []
    for key in DETECTION_SCHEMA["required"]:
        if key not in report:
            _err(errors, f"{domain}: missing required key {key!r}")
    if errors:
        return errors
    if report["domain"] != domain:
        _err(errors, f"{domain}: report echoes domain {report['domain']!r}")
    if report["verdict"] not in ("in_sync", "drift_detected", "inconclusive"):
        _err(errors, f"{domain}: bad verdict {report['verdict']!r}")
    sev_ok = set(DETECTION_SCHEMA["properties"]["findings"]["items"]
                 ["properties"]["severity"]["enum"])
    eq_ok = set(DETECTION_SCHEMA["properties"]["findings"]["items"]
                ["properties"]["equivalence"]["enum"])
    rt_ok = set(DETECTION_SCHEMA["properties"]["findings"]["items"]
                ["properties"]["remediation_route"]["enum"])
    req_f = DETECTION_SCHEMA["properties"]["findings"]["items"]["required"]
    for i, f in enumerate(report.get("findings", [])):
        for key in req_f:
            if key not in f:
                _err(errors, f"{domain}: finding {i} missing {key!r}")
        if f.get("provider") not in ("akamai", "cloudflare"):
            _err(errors, f"{domain}: finding {i} bad provider {f.get('provider')!r}")
        if f.get("severity") not in sev_ok:
            _err(errors, f"{domain}: finding {i} bad severity {f.get('severity')!r}")
        if f.get("equivalence") not in eq_ok:
            _err(errors, f"{domain}: finding {i} bad equivalence "
                         f"{f.get('equivalence')!r}")
        if f.get("remediation_route") not in rt_ok:
            _err(errors, f"{domain}: finding {i} bad remediation_route "
                         f"{f.get('remediation_route')!r}")
    return errors


# ---------------- findings table ----------------


def print_findings(domain, report):
    print(f"\n== {domain} — verdict: {report['verdict']} "
          f"({report['summary']['findings_total']} findings, "
          f"{report['summary']['fields_compared']} fields compared) ==")
    for f in report["findings"]:
        print(f"  {f['severity']:9s} {f['provider']:10s} {f['field']:36s} "
              f"{f['equivalence']:22s} -> {f['remediation_route']}")
    for e in report.get("equivalent_but_different", []):
        print(f"  ~equiv    {e['provider']:10s} {e['field']}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="orchestrator.run_detection")
    ap.add_argument("--domain", action="append", default=None,
                    help="audit only these domains (default: all four)")
    ap.add_argument("--dry-run", action="store_true",
                    help="collect + render prompts; upload nothing, create no sessions")
    ap.add_argument("--max-acu", type=int, default=config.MAX_ACU_LIMIT)
    ap.add_argument("--devin-mode", default=config.DEVIN_MODE)
    ap.add_argument("--no-remediate", action="store_true")
    ap.add_argument("--poll-interval", type=int, default=config.POLL_INTERVAL_S)
    ap.add_argument("--akamai-base", default=config.SIM_AKAMAI_BASE)
    ap.add_argument("--cloudflare-base", default=config.SIM_CLOUDFLARE_BASE)
    args = ap.parse_args(argv)

    domains = args.domain or DOMAINS
    rid = config.run_id()
    golden_sha, mapping_version = golden_info()
    print(f"run {rid} — domains: {', '.join(domains)}")
    print(f"golden_sha={golden_sha[:12]} mapping_version={mapping_version}")

    bundles = collect.collect_all(domains=domains,
                                  akamai_base=args.akamai_base,
                                  cloudflare_base=args.cloudflare_base)
    manifest = collect.write_bundles(rid, bundles, golden_sha,
                                     mapping_version, config.ARTIFACTS_DIR)
    manifest["sim_bases"] = {"akamai": args.akamai_base,
                             "cloudflare": args.cloudflare_base}
    prompts = {d: render_prompt(d, golden_sha, mapping_version, manifest)
               for d in domains}

    if args.dry_run:
        print("\n--- structured output schema ---")
        print(json.dumps(DETECTION_SCHEMA, indent=2))
        for d in domains:
            print(f"\n--- detection prompt: {d} ---")
            print(prompts[d])
        print("\n(dry run — nothing uploaded, no sessions created)")
        return 0

    client = DevinClient(config.DEVIN_BASE_URL, config.DEVIN_ORG_ID,
                         config.get_token())

    # upload both bundles per domain first; sessions reference the URLs
    urls = {}
    for d in domains:
        urls[d] = []
        for side in ("akamai", "cloudflare"):
            urls[d].append(client.upload_attachment(
                manifest["files"][d][side]["path"]))
    manifest_path = config.ARTIFACTS_DIR / rid / "manifest.json"
    m = json.loads(manifest_path.read_text())
    for d in domains:
        for i, side in enumerate(("akamai", "cloudflare")):
            m["files"][d][side]["attachment_url"] = urls[d][i]
    manifest_path.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

    # create all sessions up front so they run in parallel
    sessions = {}
    for d in domains:
        body = client.create_session(
            prompts[d], title=f"CDN drift detection: {d}",
            tags=["cdn-drift", "detection", f"domain:{d}", f"run:{rid}"],
            repos=[config.REPO_SLUG], attachment_urls=urls[d],
            structured_output_schema=DETECTION_SCHEMA,
            structured_output_required=True,
            max_acu_limit=args.max_acu, devin_mode=args.devin_mode)
        sessions[d] = body["session_id"]
        print(f"  created {d}: {sessions[d]}")

    def poll(d):
        return d, client.poll_session(
            sessions[d], interval=args.poll_interval,
            timeout=config.POLL_TIMEOUT_S,
            on_tick=lambda b: print(f"    {d}: {b.get('status')}",
                                    file=sys.stderr))

    reports = {}
    det_dir = config.ARTIFACTS_DIR / rid / "detection"
    det_dir.mkdir(parents=True, exist_ok=True)
    bad = []
    with ThreadPoolExecutor(max_workers=len(domains)) as ex:
        for d, body in ex.map(poll, domains):
            report = body.get("structured_output")
            if not isinstance(report, dict):
                bad.append(f"{d}: session ended without structured output "
                           f"(status={body.get('status')})")
                continue
            errs = validate_report(d, report)
            bad.extend(errs)
            reports[d] = report
            (det_dir / f"{d}.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n")
            print_findings(d, report)
    for msg in bad:
        print(f"SCHEMA: {msg}", file=sys.stderr)

    if not args.no_remediate:
        parent_ids = {d: sessions[d] for d in reports}
        plans = [plan_remediation(reports[d], rid, config.GOLDEN_BRANCH)
                 for d in reports]
        for created in execute_remediation(
                plans, client, repo=config.REPO_SLUG,
                max_acu_limit=args.max_acu, devin_mode=args.devin_mode,
                parent_ids=parent_ids):
            print(f"  remediation {created['route']} for {created['domain']}: "
                  f"{created['session'].get('session_id')}")
        for plan in plans:
            for df in plan["deferred"]:
                print(f"  deferred ({df['note']}): {plan['domain']} "
                      f"{df['field']}")
            if plan["skipped"]:
                print(f"  remediation skipped for {plan['domain']}: "
                      f"verdict inconclusive")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
