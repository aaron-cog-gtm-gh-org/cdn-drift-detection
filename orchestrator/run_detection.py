"""One detection-and-remediation session per domain, end to end.

  python -m orchestrator.run_detection \
      [--domain D ...] [--dry-run] [--demo|--plain] [--max-acu 25] \
      [--devin-mode normal] [--report-only] [--answers answers.yaml] \
      [--base-branch BRANCH] [--poll-interval 20]

Flow: collect provider bundles over the simulator APIs -> write
`artifacts/<run_id>/` -> upload the three bundles per domain (akamai,
cloudflare, mapping — no IaC bundle; the session has the repo checked out)
-> create all detection sessions up front (they run in parallel) -> poll
them all to a terminal state, relaying the human decision when a session
blocks -> validate each session's structured output against
DETECTION_SCHEMA locally -> report findings, the decision exchanges, and
the pull request each session opened — all under
`artifacts/<run_id>/detection/`.

The waiting relay is the centrepiece: a session that finds disagreements
asks the operator which provider is right and *blocks*. The CLI prints the
session URL and the question, takes the answer on stdin (or from
`--answers`), posts it via `send_message`, and keeps polling. An answer
given directly in the Devin UI is detected on the next state check — the
session simply leaves the waiting state.

`--dry-run` collects and renders everything but uploads nothing and creates
no sessions. `--report-only` builds the comparison-only prompt variant —
no question, no remediation.

Output goes through a reporter (orchestrator/console.py): `--demo` forces
rich rendering, `--plain` flat text, default is rich iff stdout is a tty.

Tests never call this against the real API; the one live run is manual.
"""
import argparse
import json
import os
import sys
import threading

import yaml
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drift.iac import iac_sha
from drift.sources import ApiSource, DOMAINS
from orchestrator import collect, config
from orchestrator.console import make_reporter
from orchestrator.devin_client import DevinClient
from orchestrator.prompts import DOMAIN_ROLES, build_detection_prompt
from orchestrator.schema import DETECTION_SCHEMA

# bound once so a test can swap out DevinClient wholesale
_waiting = DevinClient.waiting

MAPPING_PATH = Path(__file__).resolve().parent.parent / \
    "mapping" / "akamai-cloudflare-mapping.yaml"

PYTEST_CMD = ".venv/bin/python -m pytest -q"


def _mapping_doc():
    return yaml.safe_load(MAPPING_PATH.read_text())


def iac_info(domains, root=None):
    """({domain -> iac_sha}, mapping_version) out of the IaC tree.

    iac_sha is per-domain — each domain's terraform module is distinct
    content, and a finding must trace to the exact IaC bytes a remediation
    branched from. Fails loudly naming any requested domain with no module.
    """
    base = Path(root) if root is not None else config.IAC_DIR
    shas, missing = {}, []
    for d in domains:
        if not (base / d).is_dir():
            missing.append(d)
        else:
            shas[d] = iac_sha(d, base)
    if missing:
        sys.exit(f"no IaC module under terraform/ for: {', '.join(missing)}")
    return shas, (_mapping_doc().get("version") or "unknown")


def render_prompts(domains, iac_shas, mapping_version, manifest,
                   base_branch, report_only):
    return {d: build_detection_prompt(
                d, mapping_version=mapping_version, iac_sha=iac_shas[d],
                attachment_manifest=collect.attachment_manifest(d, manifest),
                pytest_cmd=PYTEST_CMD, base_branch=base_branch,
                report_only=report_only)
            for d in domains}


# ---------------- the decision relay ----------------


def compose_answer(field_choices):
    """`{field: akamai|cloudflare|skip}` -> the message the session expects
    ('field: choice, ...')."""
    return ", ".join(f"{f}: {c}" for f, c in field_choices.items())


def load_answers(path):
    """--answers FILE: YAML mapping domain -> {field: akamai|cloudflare|skip}."""
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return {str(k): dict(v) for k, v in doc.items()}


def _stdin_line(timeout):
    """One line from stdin, or None on timeout (tty only). '' on EOF."""
    if sys.stdin.isatty():
        import select
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if not ready:
            return None
    return sys.stdin.readline()


class OperatorRelay:
    """Serializes 'session is waiting for the operator' episodes.

    One episode at a time gets the console (arrival order, via the lock);
    the others keep their captured state and are relayed when the console
    frees. `answers` maps domain -> {field: choice} (from --answers);
    `log_dir` receives a <domain>.messages.jsonl transcript of every
    question the session asked and the answer the CLI sent (or the fact
    that it was answered in the UI).
    """

    def __init__(self, client, out, answers=None, log_dir=None,
                 recheck_interval=15, stdin_line=None):
        self.client = client
        self.out = out
        self.answers = answers or {}
        self.log_dir = Path(log_dir) if log_dir else None
        self.recheck_interval = recheck_interval
        self.stdin_line = stdin_line or _stdin_line
        self._lock = threading.Lock()

    def _log(self, domain, entry):
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            with open(self.log_dir / f"{domain}.messages.jsonl", "a") as fh:
                fh.write(json.dumps(entry) + "\n")

    def handler(self, domain, session_id):
        """The poll_session on_waiting callback for one domain."""
        def on_waiting(body):
            with self._lock:
                self.relay(domain, session_id, body)
        return on_waiting

    def relay(self, domain, session_id, body):
        url = body.get("url") or config.session_url(session_id)
        msgs = self.client.list_messages(session_id)
        question = next((m.get("message", "") for m in reversed(msgs)
                         if m.get("source") == "devin"), "")
        self.out.waiting_for_decision(domain, url, question)
        self._log(domain, {"from": "devin", "message": question})
        if domain in self.answers:
            answer = compose_answer(self.answers[domain])
            self.client.send_message(session_id, answer)
            self.out.decision_sent(domain, answer)
            self._log(domain, {"from": "operator", "message": answer,
                               "via": "answers_file"})
            return
        answer = self._read_answer(domain, session_id)
        if answer is None:
            self.out.decision_external(domain, url)
            self._log(domain, {"from": "operator",
                               "message": "(answered in the Devin UI)"})
            return
        self.client.send_message(session_id, answer)
        self.out.decision_sent(domain, answer)
        self._log(domain, {"from": "operator", "message": answer,
                           "via": "stdin"})

    def _read_answer(self, domain, session_id):
        """Take the operator's answer on stdin. Returns None if the session
        left the waiting state first (answered directly in the Devin UI)."""
        self.out.decision_prompt(domain)
        while True:
            line = self.stdin_line(self.recheck_interval)
            if line is not None:
                line = line.strip()
                if line:
                    # the session may have been answered in the UI while we
                    # were reading — don't double-send
                    if not self._still_waiting(session_id):
                        return None
                    return line
                if line == "":  # EOF — stdin closed
                    return None
                continue
            if not self._still_waiting(session_id):
                return None

    def _still_waiting(self, session_id):
        try:
            body = self.client.get_session(session_id)
        except Exception:
            return True  # transient API blip — keep waiting for input
        if _waiting(body):
            return True
        # suspended *while* waiting reads (suspended, inactivity) — already
        # covered by waiting(); anything else means the episode is over
        return False


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
    dg_ok = set(DETECTION_SCHEMA["properties"]["findings"]["items"]
                ["properties"]["disagreement"]["enum"])
    au_ok = set(DETECTION_SCHEMA["properties"]["findings"]["items"]
                ["properties"]["recommended_authority"]["enum"])
    req_f = DETECTION_SCHEMA["properties"]["findings"]["items"]["required"]
    for i, f in enumerate(report.get("findings", [])):
        for key in req_f:
            if key not in f:
                _err(errors, f"{domain}: finding {i} missing {key!r}")
        if f.get("severity") not in sev_ok:
            _err(errors, f"{domain}: finding {i} bad severity {f.get('severity')!r}")
        if f.get("disagreement") not in dg_ok:
            _err(errors, f"{domain}: finding {i} bad disagreement "
                         f"{f.get('disagreement')!r}")
        if f.get("recommended_authority") not in au_ok:
            _err(errors, f"{domain}: finding {i} bad recommended_authority "
                         f"{f.get('recommended_authority')!r}")
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
                    help="re-render findings + remediation from an existing "
                         "artifacts/<run_id>/detection/ — no API calls")
    ap.add_argument("--max-acu", type=int, default=config.MAX_ACU_LIMIT)
    ap.add_argument("--devin-mode", default=config.DEVIN_MODE)
    ap.add_argument("--report-only", action="store_true",
                    help="comparison only — no operator question, no "
                         "remediation, no pull request")
    ap.add_argument("--answers", metavar="FILE",
                    help="YAML domain -> {field: akamai|cloudflare|skip}; "
                         "non-interactive decision relay")
    ap.add_argument("--base-branch", default=config.IAC_BRANCH,
                    help="branch remediation PRs branch off")
    ap.add_argument("--poll-interval", type=int, default=config.POLL_INTERVAL_S)
    ap.add_argument("--akamai-base", default=config.SIM_AKAMAI_BASE)
    ap.add_argument("--cloudflare-base", default=config.SIM_CLOUDFLARE_BASE)
    args = ap.parse_args(argv)

    out = make_reporter(demo=args.demo, plain=args.plain)
    total = 8

    if args.replay:
        return replay(args.replay, out, total,
                      full_equivalences=args.full_equivalences)

    domains = args.domain or DOMAINS
    answers = load_answers(args.answers) if args.answers else {}
    rid = config.run_id()

    # [1/8] IaC provenance
    iac_shas, mapping_version = iac_info(domains)
    out.phase(1, total, "IaC state")
    out.step(f"run {rid} — domains: {', '.join(domains)}")
    out.iac_state(domains, DOMAIN_ROLES, iac_shas, mapping_version)

    # [2/8] + [3/8] pull provider configs (fetch lines via on_fetch)
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

    # [4/8] write bundles — akamai + cloudflare live state plus the scoped
    # mapping; the session has the repo checked out and needs nothing else
    out.phase(4, total, "Writing provider bundles",
              subtitle=str(config.ARTIFACTS_DIR / rid))
    mapping_doc = _mapping_doc()
    for d in domains:
        bundles[d]["mapping"] = collect.mapping_bundle(d, mapping_doc)
    manifest = collect.write_bundles(rid, bundles, iac_shas,
                                   mapping_version, config.ARTIFACTS_DIR)
    manifest["sim_bases"] = {"akamai": args.akamai_base,
                             "cloudflare": args.cloudflare_base}
    out.artifact_table([
        (Path(manifest["files"][d][side]["path"]).name,
         manifest["files"][d][side]["path"],
         manifest["files"][d][side]["sha256"],
         os.path.getsize(manifest["files"][d][side]["path"]))
        for d in domains for side in ("akamai", "cloudflare", "mapping")])
    prompts = render_prompts(domains, iac_shas, mapping_version, manifest,
                             args.base_branch, args.report_only)

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

    # [5/8] upload
    out.phase(5, total, "Uploading to Devin")
    urls = {}
    for d in domains:
        urls[d] = []
        for side in ("akamai", "cloudflare", "mapping"):
            path = manifest["files"][d][side]["path"]
            urls[d].append(client.upload_attachment(path))
            out.artifact(f"{Path(path).name} →", urls[d][-1])
    manifest_path = config.ARTIFACTS_DIR / rid / "manifest.json"
    m = json.loads(manifest_path.read_text())
    for d in domains:
        for i, side in enumerate(("akamai", "cloudflare", "mapping")):
            m["files"][d][side]["attachment_url"] = urls[d][i]
    manifest_path.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

    # [6/8] create detection sessions — the session opens the remediation PR
    # itself, so it needs the repo checked out
    out.phase(6, total, "Creating detection sessions")
    sessions = {}
    session_urls = {}
    for d in domains:
        body = client.create_session(
            prompts[d], title=f"CDN drift detection: {d}",
            tags=["cdn-drift", "detection", f"domain:{d}", f"run:{rid}"],
            repos=[config.REPO_SLUG],
            attachment_urls=urls[d],
            structured_output_schema=DETECTION_SCHEMA,
            structured_output_required=True,
            max_acu_limit=args.max_acu, devin_mode=args.devin_mode)
        sessions[d] = body["session_id"]
        session_urls[d] = body.get("url") or config.session_url(sessions[d])
        out.session_created(d, sessions[d], session_urls[d])

    # [7/8] sessions working — the relay answers "which side is right?"
    out.phase(7, total, "Sessions working "
                        "(decisions relayed to the operator)")
    det_dir = config.ARTIFACTS_DIR / rid / "detection"
    det_dir.mkdir(parents=True, exist_ok=True)
    relay = OperatorRelay(client, out, answers, log_dir=det_dir)

    def poll(d):
        return d, client.poll_session(
            sessions[d], interval=args.poll_interval,
            timeout=config.POLL_TIMEOUT_S,
            on_tick=lambda b: out.session_status(
                d, "waiting" if _waiting(b)
                else b.get("status"), b.get("acus_consumed")),
            on_waiting=relay.handler(d, sessions[d]))

    reports = {}
    bad = []
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

    # [8/8] findings + remediation — each report carries what the session
    # changed: the PR it opened, per-field from->to, and unresolved items
    out.phase(8, total, "Findings and remediation")
    coverage_gaps = {}
    for d in domains:
        if d not in reports:
            continue
        rep = reports[d]
        out.findings(d, rep)
        out.equivalences(d, rep, full=args.full_equivalences)
        out.remediation(d, rep)
        # mapping coverage — a field absent from fields_reviewed was never
        # examined; a reviewed id not in the scoped mapping is a hallucinated
        # field; a finding/equivalence field unlisted is internally
        # inconsistent. Gaps are not schema violations but are never quiet.
        expected = {f["id"] for f in
                    bundles.get(d, {}).get("mapping", {})
                    .get("mapping", {}).get("fields", [])}
        reviewed = set(rep.get("fields_reviewed") or [])
        reported = ({f["field"] for f in rep["findings"]} |
                    {e["field"] for e in
                     rep.get("equivalent_but_different", [])} |
                    {n["field"] for n in rep.get("not_comparable", [])})
        gap = {"missing": sorted(expected - reviewed),
               "unknown": sorted(reviewed - expected),
               "unlisted": sorted(reported - reviewed)}
        if any(gap.values()):
            coverage_gaps[d] = gap
            out.coverage_warning(d, gap["missing"], gap["unknown"],
                                 gap["unlisted"])
    for msg in bad:
        out.error(f"SCHEMA: {msg}")

    out.summary(rid, reports, str(config.ARTIFACTS_DIR / rid),
                coverage=coverage_gaps)
    if bad:
        return 1
    if coverage_gaps or any(r["verdict"] == "inconclusive"
                            for r in reports.values()):
        return 2  # an incomplete or unverifiable comparison is not a pass
    return 0


def replay(run_dir, out, total, full_equivalences=False):
    """Re-render findings + remediation from a saved detection dir —
    no API, no ACUs."""
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
    out.phase(total, total, "Findings and remediation",
              subtitle=f"REPLAY of {det_dir} — saved reports, no live sessions")
    for d, rep in reports.items():
        out.findings(d, rep)
        out.equivalences(d, rep, full=full_equivalences)
        out.remediation(d, rep)
    out.summary(det_dir.parent.name, reports, str(det_dir.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
