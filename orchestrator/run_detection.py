"""One detection session per domain, end to end.

  python -m orchestrator.run_detection \
      [--domain D ...] [--dry-run] [--demo|--plain] [--max-acu 10] \
      [--devin-mode normal] [--no-remediate] [--poll-interval 20]

Flow: collect provider bundles over the simulator APIs -> write
`artifacts/<run_id>/` -> upload both bundles per domain -> create all
detection sessions up front (so they run in parallel) -> poll them all to a
terminal state -> validate each session's structured output against
DETECTION_SCHEMA locally -> report findings, save the reports under
`artifacts/<run_id>/detection/` -> hand findings to `remediate` unless
`--no-remediate`.

`--dry-run` collects and renders everything but uploads nothing and creates
no sessions — it prints the exact prompts and the schema so the substitution
can be eyeballed before spending ACUs.

Output goes through a reporter (orchestrator/console.py): `--demo` forces the
rich rendering, `--plain` the original flat text, default is rich iff stdout
is a tty. One pipeline either way.

Tests never call this against the real API; the one live run is manual.
"""
import argparse
import json
import os
import sys

import yaml
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drift.sources import ApiSource, DOMAINS
from orchestrator import collect, config
from orchestrator.console import make_reporter
from orchestrator.devin_client import DevinClient
from orchestrator.prompts import DETECTION_PROMPT, DOMAIN_ROLES
from orchestrator.remediate import (execute_remediation, plan_remediation,
                                    route_findings)
from orchestrator.schema import DETECTION_SCHEMA
from store.golden_store import connect, get_golden, get_mapping


def golden_info(domains, db_path=None):
    """({domain -> golden_sha}, mapping_version) out of the golden store.

    golden_sha is per-domain — each domain's golden tree is a distinct row
    with distinct content, and a finding must trace to the exact golden bytes
    it was judged against. Fails loudly naming any requested domain with no
    row, rather than auditing it against another domain's revision.
    """
    conn = connect(db_path or config.GOLDEN_DB)
    try:
        shas = {}
        missing = []
        for d in domains:
            rec = get_golden(conn, d)
            if rec is None:
                missing.append(d)
            else:
                shas[d] = rec.golden_sha
        if missing:
            sys.exit(f"golden store has no row for: {', '.join(missing)} "
                     "— run scripts/load_golden_store.py first.")
        m = get_mapping(conn)
        return shas, (m["version"] if m else "unknown")
    finally:
        conn.close()


def golden_bundles(domains, db_path=None):
    """{domain: golden attachment bundle} from the golden store — the same
    rows `golden_info` reads, so both stay on one golden-resolution path."""
    conn = connect(db_path or config.GOLDEN_DB)
    try:
        m = get_mapping(conn)
        mapping_doc = yaml.safe_load(m["yaml_text"]) if m else {}
        return {d: collect.golden_bundle(get_golden(conn, d), mapping_doc)
                for d in domains}
    finally:
        conn.close()


def render_prompt(domain, golden_sha, mapping_version, manifest):
    return DETECTION_PROMPT.format(
        domain=domain, domain_role=DOMAIN_ROLES[domain],
        golden_sha=golden_sha, mapping_version=mapping_version,
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


# ---------------- main ----------------


def main(argv=None):
    ap = argparse.ArgumentParser(prog="orchestrator.run_detection")
    ap.add_argument("--domain", action="append", default=None,
                    help="audit only these domains (default: all four)")
    ap.add_argument("--dry-run", action="store_true",
                    help="collect + render prompts; upload nothing, create no sessions")
    ap.add_argument("--demo", action="store_true", help="rich output")
    ap.add_argument("--plain", action="store_true", help="plain output")
    ap.add_argument("--show-schema", action="store_true",
                    help="print the full JSON Schema instead of the compact summary")
    ap.add_argument("--full-equivalences", action="store_true",
                    help="render full equivalence reasoning instead of the "
                         "one-line-per-field compact form")
    ap.add_argument("--replay", metavar="RUN_DIR",
                    help="re-render phases 8-9 from an existing "
                         "artifacts/<run_id>/detection/ — no API calls")
    ap.add_argument("--max-acu", type=int, default=config.MAX_ACU_LIMIT)
    ap.add_argument("--devin-mode", default=config.DEVIN_MODE)
    ap.add_argument("--no-remediate", action="store_true")
    ap.add_argument("--poll-interval", type=int, default=config.POLL_INTERVAL_S)
    ap.add_argument("--akamai-base", default=config.SIM_AKAMAI_BASE)
    ap.add_argument("--cloudflare-base", default=config.SIM_CLOUDFLARE_BASE)
    args = ap.parse_args(argv)

    out = make_reporter(demo=args.demo, plain=args.plain)
    total = 9

    if args.replay:
        return replay(args.replay, out, total,
                      full_equivalences=args.full_equivalences)

    domains = args.domain or DOMAINS
    rid = config.run_id()

    # [1/9] golden state
    golden_shas, mapping_version = golden_info(domains)
    out.phase(1, total, "Golden state")
    out.step(f"run {rid} — domains: {', '.join(domains)}")
    out.golden_state(domains, DOMAIN_ROLES, golden_shas, mapping_version)

    # [2/9] + [3/9] pull provider configs (fetch lines via on_fetch)
    source = ApiSource(args.akamai_base, args.cloudflare_base)
    bundles = {}
    out.phase(2, total, "Pulling Akamai configs")
    ak_rows = []
    for d in domains:
        bundles[d] = {"akamai": collect.collect_akamai(
            source, d, lambda p, k, dom, u: ak_rows.append((dom, k, u)))}
    out.fetch_table(ak_rows)
    out.phase(3, total, "Pulling Cloudflare configs")
    cf_rows = []
    for d in domains:
        bundles[d]["cloudflare"] = collect.collect_cloudflare(
            source, d, lambda p, k, dom, u: cf_rows.append((dom, k, u)))
    out.fetch_table(cf_rows)

    # [4/9] write bundles — the golden attachment joins the two provider
    # bundles so detection sessions need no repository at all
    out.phase(4, total, "Writing provider bundles",
              subtitle=str(config.ARTIFACTS_DIR / rid))
    gbundles = golden_bundles(domains)
    for d in domains:
        bundles[d]["golden"] = gbundles[d]
    manifest = collect.write_bundles(rid, bundles, golden_shas,
                                     mapping_version, config.ARTIFACTS_DIR)
    manifest["sim_bases"] = {"akamai": args.akamai_base,
                             "cloudflare": args.cloudflare_base}
    out.artifact_table([
        (Path(manifest["files"][d][side]["path"]).name,
         manifest["files"][d][side]["path"],
         manifest["files"][d][side]["sha256"],
         os.path.getsize(manifest["files"][d][side]["path"]))
        for d in domains for side in ("akamai", "cloudflare", "golden")])
    prompts = {d: render_prompt(d, golden_shas[d], mapping_version, manifest)
               for d in domains}

    if args.dry_run:
        if args.show_schema:
            out.schema_block(DETECTION_SCHEMA)
        else:
            out.schema_summary(DETECTION_SCHEMA)
        for d in domains:
            out.prompt_block(d, prompts[d])
        out.step("\n(dry run — nothing uploaded, no sessions created)")
        return 0

    client = DevinClient(config.DEVIN_BASE_URL, config.DEVIN_ORG_ID,
                         config.get_token())

    # [5/9] upload
    out.phase(5, total, "Uploading to Devin")
    urls = {}
    for d in domains:
        urls[d] = []
        for side in ("akamai", "cloudflare", "golden"):
            path = manifest["files"][d][side]["path"]
            urls[d].append(client.upload_attachment(path))
            out.artifact(f"{Path(path).name} →", urls[d][-1])
    manifest_path = config.ARTIFACTS_DIR / rid / "manifest.json"
    m = json.loads(manifest_path.read_text())
    for d in domains:
        for i, side in enumerate(("akamai", "cloudflare", "golden")):
            m["files"][d][side]["attachment_url"] = urls[d][i]
    manifest_path.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

    # [6/9] create detection sessions
    out.phase(6, total, "Creating detection sessions")
    sessions = {}
    for d in domains:
        body = client.create_session(
            prompts[d], title=f"CDN drift detection: {d}",
            tags=["cdn-drift", "detection", f"domain:{d}", f"run:{rid}"],
            attachment_urls=urls[d],
            structured_output_schema=DETECTION_SCHEMA,
            structured_output_required=True,
            max_acu_limit=args.max_acu, devin_mode=args.devin_mode)
        sessions[d] = body["session_id"]
        out.session_created(d, sessions[d], config.session_url(sessions[d]))

    # [7/9] sessions working — live table in demo mode, stderr ticks in plain
    out.phase(7, total, "Sessions working")
    def poll(d):
        return d, client.poll_session(
            sessions[d], interval=args.poll_interval,
            timeout=config.POLL_TIMEOUT_S,
            on_tick=lambda b: out.session_status(
                d, b.get("status"), b.get("acus_consumed")))

    reports = {}
    det_dir = config.ARTIFACTS_DIR / rid / "detection"
    det_dir.mkdir(parents=True, exist_ok=True)
    bad = []
    # [8/9] findings — reports validated + rendered as polls finish
    polled = {}
    with out.sessions_live():
        with ThreadPoolExecutor(max_workers=len(domains)) as ex:
            for d, body in ex.map(poll, domains):
                polled[d] = body
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
        # repaint once more with each session's terminal state so the live
        # table's last frame doesn't leave stale 'running' rows on screen.
        # A body can terminate on structured_output/status_detail while its
        # status still reads 'running' — poll_session's terminal conditions
        # are the source of truth, not the status field alone.
        for d, body in polled.items():
            st = body.get("status")
            if st not in ("exit", "error") and (
                    body.get("structured_output") is not None
                    or body.get("status_detail") == "finished"):
                st = "exit"
            out.session_status(d, st, body.get("acus_consumed"))
    out.phase(8, total, "Findings")
    coverage_gaps = {}
    for d in domains:
        if d not in reports:
            continue
        rep = reports[d]
        out.findings(d, rep)
        out.equivalences(d, rep, full=args.full_equivalences)
        # mapping coverage — a field absent from fields_reviewed was never
        # examined; a reviewed id not in the scoped mapping is a hallucinated
        # field; a finding/equivalence field unlisted is internally
        # inconsistent. Gaps are not schema violations but are never quiet.
        expected = {f["id"] for f in
                    gbundles.get(d, {}).get("mapping", {}).get("fields", [])}
        reviewed = set(rep.get("fields_reviewed") or [])
        reported = ({f["field"] for f in rep["findings"]} |
                    {e["field"] for e in
                     rep.get("equivalent_but_different", [])})
        gap = {"missing": sorted(expected - reviewed),
               "unknown": sorted(reviewed - expected),
               "unlisted": sorted(reported - reviewed)}
        if any(gap.values()):
            coverage_gaps[d] = gap
            out.coverage_warning(d, gap["missing"], gap["unknown"],
                                 gap["unlisted"])
    for msg in bad:
        out.error(f"SCHEMA: {msg}")

    # [9/9] remediation routing — always rendered; with --no-remediate the
    # pure planning call shows what *would* route, never reaching
    # execute_remediation (no sessions created, no ACU spend)
    if args.no_remediate:
        out.phase(9, total, "Remediation routing "
                            "(disabled — no sessions created)")
        _render_would_route(reports, out)
    else:
        out.phase(9, total, "Remediation routing")
        parent_ids = {d: sessions[d] for d in reports}
        plans = [plan_remediation(reports[d], rid, config.GOLDEN_BRANCH)
                 for d in reports]
        for created in execute_remediation(
                plans, client, repo=config.REPO_SLUG,
                max_acu_limit=args.max_acu, devin_mode=args.devin_mode,
                parent_ids=parent_ids):
            out.remediation(created["route"], created["domain"],
                            created["session"].get("session_id"),
                            config.session_url(
                                created["session"].get("session_id")))
        for plan in plans:
            for df in plan["deferred"]:
                out.deferred(plan["domain"], df["field"], df["note"])
            if plan["skipped"]:
                out.warn(f"  remediation skipped for {plan['domain']}: "
                         f"verdict inconclusive")
    out.summary(rid, reports, str(config.ARTIFACTS_DIR / rid),
                coverage=coverage_gaps)
    if bad:
        return 1
    if coverage_gaps or any(r["verdict"] == "inconclusive"
                            for r in reports.values()):
        return 2  # an incomplete or unverifiable comparison is not a pass
    return 0


def _render_would_route(reports, out):
    """Phase-9 'would route' rendering — pure computation over the reports,
    no sessions created. Shared by --replay and --no-remediate."""
    for d, rep in reports.items():
        if rep["verdict"] == "inconclusive":
            out.deferred(d, "(all)", "verdict inconclusive — skipped")
            continue
        grouped, unknown = route_findings(rep)
        for route, fs in grouped.items():
            if not fs:
                continue
            if route == "provider_api":
                for f in fs:
                    out.deferred(d, f["field"],
                                 "provider writes are out of scope "
                                 "until phase 04")
            else:
                out.step(f"  {d}: {route} -> {len(fs)} finding(s) "
                         "would route to a remediation session")
        for f in unknown:
            out.deferred(d, f["field"],
                         f"unrecognized remediation_route "
                         f"{f.get('remediation_route')!r}")


def replay(run_dir, out, total, full_equivalences=False):
    """Re-render phases 8-9 from a saved detection dir — no API, no ACUs."""
    det_dir = Path(run_dir)
    if not det_dir.is_dir():
        det_dir = config.ARTIFACTS_DIR / run_dir
    if (det_dir / "detection").is_dir():
        det_dir = det_dir / "detection"  # accept the run dir or the detection dir
    files = sorted(det_dir.glob("*.json")) if det_dir.is_dir() else []
    reports = {}
    for p in files:
        rep = json.loads(p.read_text())
        if isinstance(rep, dict) and "domain" in rep and "findings" in rep:
            reports[rep["domain"]] = rep
    if not reports:
        sys.exit(f"no detection reports under {run_dir} "
                 "(expected artifacts/<run_id>/detection/*.json)")
    out.phase(8, total, "Findings",
              subtitle=f"REPLAY of {det_dir} — saved reports, no live sessions")
    for d, rep in reports.items():
        out.findings(d, rep)
        out.equivalences(d, rep, full=full_equivalences)
    out.phase(9, total, "Remediation routing (replay — no sessions created)")
    _render_would_route(reports, out)
    out.summary(det_dir.parent.name, reports, str(det_dir.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
