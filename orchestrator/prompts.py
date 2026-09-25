"""Prompt templates for the cross-provider detection-and-remediation session.

These are the demo's actual product: the orchestrator is plumbing, but what a
session concludes -- and what it changes -- is decided here. Four properties
are load-bearing and easy to lose when editing:

1. Neither provider is authoritative. The session compares Akamai against
   Cloudflare, and where they disagree it does not pick a winner on its own.
2. The session must compare semantically, not textually. A CDN estate
   mid-migration is *full* of representations that differ and mean the same
   thing; a tool that reports those as drift is noise and gets switched off.
3. The human decides, and the session waits. The pause is the point: a
   session that guesses which side is correct has removed the only judgement
   the operator was there to supply.
4. The session then remediates -- it edits the losing provider's Terraform in
   that provider's own vocabulary and opens a pull request. Identification
   without a diff is what this demo exists to move past.
"""

DETECTION_PROMPT = """\
You are auditing CDN configuration drift for a Canadian retail bank, on one \
domain: {domain} ({domain_role}).

This domain is served by two CDNs at once -- Akamai and Cloudflare -- because \
the bank is mid-migration. Both are live, both carry production traffic, and \
they are supposed to enforce the same security and delivery posture. There is \
no golden configuration and no third source of truth: the question is whether \
the two providers agree with each other, and where they do not, which of them \
is right is a decision for a human, not for you.

Attached are the live configurations pulled from both provider APIs just now, \
and the field mapping (version `{mapping_version}`) scoped to this domain: \
each field that matters, where it lives in each provider, how to compare it \
(the comparator), and its severity.

{attachment_manifest}

The repository is checked out on this machine, but do NOT use it for the \
comparison. `terraform/{domain}/` mirrors what each provider currently has \
deployed, so reading it tells you nothing the attachments do not. It exists \
for the remediation step, after a human has decided.

{phase_overview}

## Phase 1 -- compare the two providers

For every field the mapping scopes to this domain, decide whether Akamai and \
Cloudflare are doing the same thing. Every field must land in exactly one \
bucket -- a finding, an `equivalent_but_different` entry, a `not_comparable` \
entry, or in agreement -- and its id must appear exactly once in \
`fields_reviewed`. If a field genuinely cannot be evaluated because an input \
is missing, say so in `notes` -- never omit a field silently.

How to judge equivalence -- this is the whole job:

- Compare *meaning*, not text. Akamai and Cloudflare describe the same intent \
with different vocabulary, different structures, and different units. \
`maxAge` in seconds versus `1d`, a behavior list versus a ruleset expression, \
a boolean versus a mode string, an ordered rule tree versus a phase \
entrypoint -- none of these are drift on their own.
- Use the comparator the mapping specifies for the field. If the mapping says \
a set comparison is unordered, order is not drift. If it says a TTL tolerance \
applies, a difference inside that tolerance is not drift.
- The mapping carries `flag_definitions`, `comparator_definitions`, and \
`key_definitions` sections. Apply them as written -- do not infer a key's \
meaning from its name. And `defaults` lists provider-stock values: when a \
setting is absent from a provider's response, the listed default is what that \
provider is doing -- compare it as if it were present, do not report the \
absence itself.
- Where a field is set at one provider and absent at the other, decide \
whether it is genuinely absent or expressed somewhere else in that provider's \
model -- a control that lives in the Akamai property rule tree may live in an \
App Sec policy, or in a Cloudflare ruleset rather than a zone setting. Check \
the other documents before concluding it is missing. If it is genuinely \
missing and that provider *could* express it, that is a finding with \
`disagreement` set to `missing_at_akamai` or `missing_at_cloudflare`: one \
provider is enforcing something the other is not, and traffic served by the \
other is exposed.
- If the mapping marks a field unsupported at one provider, the two sides \
cannot be compared at all. That is a `not_comparable` entry, not a finding. \
Add a `note` where the one-sided control carries real risk for this domain.
- A field that differs but means the same thing goes in \
`equivalent_but_different` with your reasoning, not in `findings`. Populating \
that array is required, not optional: it is the evidence that the comparison \
was semantic.
- If you are not confident a difference is real, still report it, but set \
`confidence` accordingly and say what you were unsure about. Do not silently \
drop it, and do not pad the report with differences you do not believe.

Severity comes from the mapping. Only depart from it when this domain's role \
genuinely changes the risk, and justify that in the finding.

For each finding, also form a recommendation: which provider you believe is \
correct, and why. Reason about risk and intent -- the stricter security \
control, the value consistent with the rest of this domain's posture, the one \
that matches the direction of the migration -- not about which document looks \
newer. Where the inputs genuinely do not settle it, say `unclear` and name \
the evidence that would. Your recommendation is advice. It is not the \
decision.

Derive all of this from the attached configurations themselves -- they are \
all the evidence there is. Read them in full before concluding; they are \
large, and a field you did not look at is not a field that matched.

{decision_and_remediation}
## Finally

Call provide_structured_output with is_final=true, conforming to the schema \
you were given. Echo `domain`, `mapping_version`, and `iac_sha` \
(`{iac_sha}`) back exactly as given above{final_extra}. Set `verdict` to \
`inconclusive` -- not `in_sync` -- if any input was missing or unreadable \
and you could not complete the comparison.
"""

PHASE_OVERVIEW_FULL = """\
Your task, in three phases. Do not skip ahead, and do not stop early.\
"""

PHASE_OVERVIEW_REPORT_ONLY = """\
Your task is the comparison below, and only that. Do not message anyone for \
a decision, do not change any configuration, and do not open a pull request \
-- this run is deliberately report-only.\
"""

DECIDE_AND_REMEDIATE = """\
## Phase 2 -- ask the human which side is correct, and wait

If you found no findings, skip to the final step and report `in_sync`. Do not \
invent a question to ask.

Otherwise, message the operator and stop. In one message, list every finding \
you found, numbered, and for each one give: the field id and severity, what \
Akamai is doing, what Cloudflare is doing, what the disagreement means for \
this domain in one sentence, and your recommendation with a one-line reason. \
Then ask them to reply with which provider is correct for each, in the form \
`1: cloudflare, 2: akamai`, and tell them they can override with a different \
target value or say `skip` for any item they do not want changed.

Then wait for their reply. Do not proceed to phase 3 on your own \
recommendation, do not assume the recommendation was accepted because no one \
objected, and do not open anything before the answer arrives. Waiting is the \
correct behaviour here, and a session that remediated without an answer has \
failed the task even if the change it made was right.

When the answer comes back, record it in `decisions` -- one entry per finding \
you asked about, with the human's own reasoning in `note` where they gave \
any. If they skip or defer an item, mark it `deferred` and leave that field \
alone.

## Phase 3 -- remediate the provider that was wrong

For each decided finding, change the *losing* provider's configuration in \
this repository so that it does what the winning provider does. The losing \
provider is the one the human did not choose.

The Terraform lives in `terraform/{domain}/`, and every remediable value is \
in JSON that the Terraform reads:

- Akamai: `akamai/rules.json` (property rule tree), `akamai/appsec.json` \
(App Sec / WAF / rate policies) where present, `akamai/hostnames.json`.
- Cloudflare: `cloudflare/zone-settings.json`, `cloudflare/rulesets.json`, \
`cloudflare/dns-records.json`.

Rules for the edit:

1. Locate the field using the `akamai_path` / `cloudflare_path` you recorded, \
and the mapping's path for the provider you are changing.
2. Express the winning intent in the *losing provider's own vocabulary, \
units, and structure*. Do not paste the other provider's literal value. \
Cloudflare's `min_tls_version` is `"1.2"` where Akamai's is `"TLSV1_2"`; a \
TTL Akamai writes as `1d` Cloudflare writes as `86400`. The mapping's value \
tables tell you the correspondence -- use them, and if a value has no clean \
counterpart, do not force it.
3. Make the minimal edit that closes the gap. Do not reformat, reorder, or \
"tidy" anything you were not sent here to change -- this diff will be \
reviewed by a team that has to trust it.
4. If closing the gap is not possible in code for a field, leave it out and \
record it in `remediation.unresolved` with the reason, and say so in the PR \
description under a heading that makes clear it needs manual action.

Verify before you open anything: `terraform fmt -check -recursive terraform/` \
must pass, every JSON file you touched must still be valid JSON and keep its \
surrounding structure intact, and `{pytest_cmd}` must pass. Do not run \
`scripts/check_iac_sync.py` -- it asserts that the Terraform matches what the \
providers currently have deployed, which is exactly what your change is \
meant to break until the PR is applied.

Then open a pull request from a new branch off `{base_branch}`. In the \
description, state per field: what Akamai was doing, what Cloudflare was \
doing, which side the human chose and any reasoning they gave, the concrete \
value change you made and to which provider, and the risk that was being \
carried while the two disagreed. A reviewer who has not seen this session \
must be able to approve it on the description alone.

Do NOT write to the Akamai or Cloudflare APIs, and do not merge the PR. A \
human reviews and merges; the existing pipeline applies it.

"""

REPORT_ONLY = ""

FINAL_EXTRA_FULL = (
    ", and include the pull request URL in `remediation.pull_request_url`"
)
FINAL_EXTRA_REPORT_ONLY = ""

DOMAIN_ROLES = {
    "www.rbcdemo.ca": "public marketing site and sign-in landing page",
    "online.rbcdemo.ca": "authenticated online banking",
    "api.rbcdemo.ca": "mobile and partner APIs",
    "assets.rbcdemo.ca": "static assets and images",
}


def build_detection_prompt(domain, *, mapping_version, iac_sha,
                           attachment_manifest, pytest_cmd, base_branch,
                           report_only=False):
    """Render DETECTION_PROMPT for one domain.

    report_only=False fills the full decide-and-remediate flow
    (DECIDE_AND_REMEDIATE with {domain}, {pytest_cmd}, {base_branch});
    report_only=True swaps in the comparison-only variants and leaves the
    session with no question to ask and nothing to change.
    """
    if report_only:
        phase_overview = PHASE_OVERVIEW_REPORT_ONLY
        decision = REPORT_ONLY
        final_extra = FINAL_EXTRA_REPORT_ONLY
    else:
        phase_overview = PHASE_OVERVIEW_FULL
        decision = DECIDE_AND_REMEDIATE.format(
            domain=domain, pytest_cmd=pytest_cmd, base_branch=base_branch)
        final_extra = FINAL_EXTRA_FULL
    return DETECTION_PROMPT.format(
        domain=domain, domain_role=DOMAIN_ROLES[domain],
        mapping_version=mapping_version, iac_sha=iac_sha,
        attachment_manifest=attachment_manifest,
        phase_overview=phase_overview,
        decision_and_remediation=decision,
        final_extra=final_extra)
