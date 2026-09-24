"""Route detection findings to remediation.

Grouping is by `remediation_route` from the structured report:

- `iac_pr`       -> one child session per domain with REMEDIATION_PROMPT_IAC
                    (the findings an IaC PR can close)
- `human_review` -> one child session per domain with REMEDIATION_PROMPT_HUMAN
                    (prepares the escalation briefing; opens no PR)
- `provider_api` -> NO session. Provider writes are out of scope until
                    phase 04; these findings are recorded as `deferred`.

Domains whose verdict is `inconclusive` are skipped entirely — remediating a
comparison that never completed is worse than not remediating at all. A route
with zero findings produces no session.
"""
from .prompts import (REMEDIATION_PROMPT_HUMAN, REMEDIATION_PROMPT_IAC,
                      DOMAIN_ROLES)

PROVIDER_API_NOTE = "provider writes are out of scope until phase 04"


def findings_block(findings):
    """Readable per-finding blocks for the prompt — not raw JSON."""
    blocks = []
    for i, f in enumerate(findings, 1):
        loc = f.get("locator") or {}
        lines = [
            f"{i}. `{f['field']}` ({f['provider']}) — severity {f['severity']}",
            f"   golden   : {f['golden_value']}",
            f"   observed : {f['observed_value'] or '(absent)'}",
            f"   at       : {loc.get('provider_path', '?')}"
            + (f"  (golden: {loc['golden_path']})" if loc.get("golden_path") else ""),
            f"   why      : {f['explanation']}",
        ]
        if f.get("remediation_note"):
            lines.append(f"   fix      : {f['remediation_note']}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def route_findings(report):
    """Split a domain's findings by remediation_route.

    Returns (grouped, unknown): findings with an unrecognized route go to
    `unknown` rather than crashing — this is parsing model output, and the
    detection sessions have already run by the time this executes.
    """
    grouped = {"iac_pr": [], "provider_api": [], "human_review": []}
    unknown = []
    for f in report.get("findings", []):
        route = f.get("remediation_route")
        if route in grouped:
            grouped[route].append(f)
        else:
            unknown.append(f)
    return grouped, unknown


def plan_remediation(report, run_id, golden_branch):
    """Return the remediation plan for one domain's detection report.

    {"domain", "verdict", "sessions": [{route, prompt, tags}],
     "deferred": [findings], "skipped": bool}
    """
    domain = report["domain"]
    plan = {"domain": domain, "verdict": report["verdict"],
            "sessions": [], "deferred": [], "skipped": False}
    if report["verdict"] == "inconclusive":
        plan["skipped"] = True
        return plan
    grouped, unknown = route_findings(report)
    fmt = dict(domain=domain, domain_role=DOMAIN_ROLES[domain],
               golden_sha=report["golden_sha"], golden_branch=golden_branch)
    for route, tpl in (("iac_pr", REMEDIATION_PROMPT_IAC),
                       ("human_review", REMEDIATION_PROMPT_HUMAN)):
        findings = grouped[route]
        if not findings:
            continue
        plan["sessions"].append({
            "route": route,
            "prompt": tpl.format(finding_count=len(findings),
                                 findings_block=findings_block(findings),
                                 **fmt),
            "tags": ["cdn-drift", "remediation", f"route:{route}",
                     f"domain:{domain}", f"run:{run_id}"],
        })
    plan["deferred"] = [
        {"field": f["field"], "provider": f["provider"],
         "remediation_note": f.get("remediation_note"),
         "note": PROVIDER_API_NOTE}
        for f in grouped["provider_api"]
    ] + [
        {"field": f["field"], "provider": f["provider"],
         "remediation_note": f.get("remediation_note"),
         "note": f"unrecognized remediation_route "
                 f"{f.get('remediation_route')!r}"}
        for f in unknown
    ]
    return plan


def execute_remediation(plans, client, *, repo, max_acu_limit, devin_mode,
                        parent_ids=None, on_session=None):
    """Create the remediation child sessions described by `plan_remediation`.

    `parent_ids` maps domain -> detection session id, passed as `devin_id` so
    the children link to their detection session (unverified in v3 — the E2E
    run confirms whether child_session_ids populates).
    Returns the sessions created, annotated with domain/route.
    """
    parent_ids = parent_ids or {}
    created = []
    for plan in plans:
        if plan["skipped"]:
            continue
        for sess in plan["sessions"]:
            body = client.create_session(
                sess["prompt"],
                title=f"CDN drift remediation ({sess['route']}): {plan['domain']}",
                tags=sess["tags"], repos=[repo],
                max_acu_limit=max_acu_limit, devin_mode=devin_mode,
                parent_session_id=parent_ids.get(plan["domain"]))
            created.append({"domain": plan["domain"], "route": sess["route"],
                            "session": body})
            if on_session:
                on_session(created[-1])
    return created
