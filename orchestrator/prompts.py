"""Prompt templates for the detection and remediation sessions.

These are the demo's actual product: the orchestrator is plumbing, but what a
detection session concludes is decided here. Two properties are load-bearing
and easy to lose when editing:

1. The session must compare semantically, not textually. A CDN estate
   mid-migration is *full* of representations that differ and mean the same
   thing; a tool that reports those as drift is noise and gets switched off.
2. The session must not shortcut. Detection sessions get every input as
   attachments and no repository at all, so there is no validator output to
   reproduce -- the findings are derived from the configurations themselves
   or the POC proves nothing.
"""

DETECTION_PROMPT = """\
You are auditing CDN configuration drift for a Canadian retail bank, on one \
domain: {domain} ({domain_role}).

The golden configuration is the source of truth: Terraform plus the Akamai \
rule tree and App Sec documents it references. It is attached, at golden_sha \
`{golden_sha}` -- main.tf as text, the parsed rule tree and App Sec config, \
and the field mapping (version `{mapping_version}`) scoped to this domain: \
each field that matters, where it lives in each provider, how to compare it \
(the comparator), and its severity.

Everything you need is attached below. Do NOT clone or check out any \
repository -- there is none on this machine, and none is needed. The live \
provider configuration is attached too, pulled from the provider APIs just \
now:

{attachment_manifest}

Your task: for every field the mapping scopes to this domain, decide whether \
each provider still expresses what the golden configuration requires, and \
report the ones that do not.

Work the mapping field by field, and do not stop early. Every field must land \
in exactly one bucket -- a finding, an `equivalent_but_different` entry, or \
in sync -- and its id must appear exactly once in `fields_reviewed`. If a \
field genuinely cannot be evaluated because an input is missing, say so in \
`notes` -- never omit a field silently.

How to judge equivalence -- this is the whole job:

- Compare *meaning*, not text. Akamai and Cloudflare describe the same intent \
with different vocabulary, different structures, and different units. \
`maxAge` in seconds versus `1d`, a behavior list versus a ruleset expression, \
a boolean versus a mode string, an ordered rule tree versus a phase \
entrypoint -- none of these are drift on their own.
- Use the comparator the mapping specifies for the field. If the mapping says \
a set comparison is unordered, order is not drift. If it says a TTL tolerance \
applies, a difference inside that tolerance is not drift.
- Where a field is absent at a provider, decide whether it is genuinely absent \
or expressed somewhere else in that provider's model -- a control moved from \
the Akamai property rule tree into an App Sec policy has not disappeared. \
Check the other document before concluding it is missing.
- A field that differs but means the same thing goes in \
`equivalent_but_different` with your reasoning, not in `findings`. Populating \
that array is required, not optional: it is the evidence that the comparison \
was semantic.
- If you are not confident a difference is real drift, still report it, but \
set `confidence` accordingly and say what you were unsure about. Do not \
silently drop it, and do not pad the report with differences you do not \
believe.

Severity comes from the mapping. Only depart from it when this domain's role \
genuinely changes the risk, and justify that in the finding.

Choose `remediation_route` per finding:

- `iac_pr` -- the golden config is right, the provider drifted, and the fix is \
expressible in the Terraform or rule/App Sec JSON in this repo. This is the \
default and the preferred route: the change is reviewed, versioned, and \
applied by the existing pipeline.
- `provider_api` -- the fix has to be made directly against the provider \
because that provider is not yet under Terraform management for this field \
(parts of this estate are mid-migration). Say in `remediation_note` what must \
be mirrored back into IaC afterwards; an API write that is not mirrored \
recreates this drift on the next apply.
- `human_review` -- the correct end state is not clear from the inputs. Use \
this when the golden config itself looks wrong or stale, when the provider's \
value may be a deliberate exception nobody recorded, or when changing it \
would weaken a security control and that tradeoff is not yours to make. \
Escalating is a legitimate outcome; guessing is not.

Constraints:

- Derive the findings from the attached configurations themselves -- they \
are all the evidence there is. The point of this exercise is an independent \
judgement on the configurations, not a lookup of anyone else's answer.
- Do not modify any provider configuration, and do not open a pull request. \
This session only reports. Remediation happens in a separate session.
- Read the attached provider documents in full before concluding. They are \
large; a field you did not look at is not a field that matched.

When you are done, call provide_structured_output with is_final=true, \
conforming to the schema you were given. Echo `domain`, `golden_sha`, and \
`mapping_version` back exactly as given above. Set `verdict` to \
`inconclusive` -- not `in_sync` -- if any input was missing or unreadable and \
you could not complete the comparison.
"""

REMEDIATION_PROMPT_IAC = """\
You are remediating confirmed CDN configuration drift for {domain} \
({domain_role}) in a Canadian retail bank's estate, by changing \
infrastructure-as-code. A detection session compared the golden configuration \
at golden_sha `{golden_sha}` against live Akamai and Cloudflare config and \
produced the findings below. Treat them as established; you are not re-running \
the audit.

Findings routed to you ({finding_count}):

{findings_block}

The golden configuration is the source of truth and lives at \
`golden/{domain}/` -- `main.tf`, `rules/rules.json`, and where present \
`appsec/security-config.json`. Branch off `{golden_branch}`, which is where \
that tree lives; the default branch does not have it yet.

Important: each of these findings says a *provider* drifted away from golden, \
so in most cases golden is already correct and needs no change. Your job is to \
produce the change that brings the provider back, expressed as code in this \
repo, plus the explanation a reviewer needs to approve it. Where a finding \
says golden itself is stale, change golden -- and say so explicitly in the PR \
description, because that is a change of intent and not a correction.

For each finding:

1. Locate the field using the `provider_path` and `golden_path` in the finding.
2. Make the minimal edit that closes the gap. Do not reformat, reorder, or \
"tidy" anything you were not sent here to change -- this diff will be reviewed \
by a team that has to trust it.
3. If closing the gap is not possible in code for this field, do not force it. \
Leave it out, and list it in the PR description under a heading saying it \
needs manual action and why.

Verify before you open anything: `terraform fmt -check -recursive golden/` \
must pass, the rule and App Sec JSON must stay valid JSON, and \
`~/cdn-drift-venv/bin/python -m pytest -q` must pass.

Then open a pull request. In the description, state per finding: the field, \
what the provider was doing, what it will do after this change, and the risk \
that was being carried. A reviewer who has not seen the detection session must \
be able to approve this on the description alone.

Do NOT write to the Akamai or Cloudflare APIs, and do not merge the PR. \
A human reviews and merges; the existing pipeline applies it.
"""

REMEDIATION_PROMPT_HUMAN = """\
Drift was detected on {domain} ({domain_role}) that should NOT be \
auto-remediated, and you are preparing the escalation a human will act on.

Findings needing human judgment ({finding_count}):

{findings_block}

Do not change any configuration, and do not open a pull request. Produce the \
briefing note instead: for each finding, what differs, the two candidate end \
states (golden's and the provider's), what breaks under each, what evidence \
would settle it, and who would plausibly own the decision -- the platform team \
that owns the golden config, or the security team that owns the control.

Be specific about *why* this cannot be decided from the inputs. "Ambiguous" is \
not useful to the person reading this; "the provider's value is stricter than \
golden, so aligning to golden would weaken it, and nothing in the repo records \
whether that strictness was deliberate" is.

Call provide_structured_output with is_final=true when done.
"""

DOMAIN_ROLES = {
    "www.rbcdemo.ca": "public marketing site and sign-in landing page",
    "online.rbcdemo.ca": "authenticated online banking",
    "api.rbcdemo.ca": "mobile and partner APIs",
    "assets.rbcdemo.ca": "static assets and images",
}
