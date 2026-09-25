# cdn-drift-detection

Synthetic-but-realistic fixtures for a CDN configuration drift-detection demo,
aimed at a large Canadian bank mid-migration from Akamai to Cloudflare.

The demo's claim: **Devin identifies drift, asks a human, and fixes the wrong
side.** There is no golden state — each provider's Terraform mirrors that
provider's own live configuration, and the defect the demo detects is that the
two providers *disagree with each other*. One Devin session per domain
cross-compares the two providers, asks the operator which side is right, waits
for the answer, then edits the losing provider's Terraform in this repo and
opens the PR itself.

## Domains

| Domain | Role |
| --- | --- |
| `www.rbcdemo.ca` | Public marketing and sign-in landing |
| `online.rbcdemo.ca` | Authenticated banking |
| `api.rbcdemo.ca` | Mobile and partner APIs |
| `assets.rbcdemo.ca` | Static assets and images |

## Layout

- `fixtures/akamai/` — PAPI-shaped exports per domain: `rules.json` (rule-tree
  envelope, rule format `v2023-01-05`), `hostnames.json`, `appsec.json`
  (www + online + api), plus `properties.json` listing all four.
- `fixtures/cloudflare/` — v4 API-shaped exports per zone: `zone.json`,
  `settings.json`, `rulesets.json`, `dns_records.json`.
- `terraform/<domain>/` — per-provider IaC, in sync with that provider's live
  state: `providers.tf` + `akamai.tf` (rules/hostnames/appsec loaded from
  `akamai/*.json`) + `cloudflare.tf` (zone settings, rulesets, DNS records
  loaded from `cloudflare/*.json`). Every remediable value lives in JSON.
- `mapping/akamai-cloudflare-mapping.yaml` — versioned semantic mapping
  (~50 fields, value tables, comparators, provider defaults, unsupported
  markers).
- `docs/drift-scenarios.md` — the seven seeded cross-provider findings and
  the deliberate semantic-equivalence suppressions.
- `docs/fixture-notes.md` — version targets and every schema guess.
- `docs/simulators.md` — simulator endpoints, auth, approximations.
- `docs/orchestrator.md` — the eight phases, the decision relay, v3 API notes.
- `docs/remediation-log.md` — record of remediated findings.
- `sim/` — FastAPI simulators serving fixtures over PAPI/App Sec and
  Cloudflare v4 wire shapes (read-only).
- `drift/iac.py` — projects the `terraform/` tree back into API shapes for
  comparison and hashing.
- `scripts/validate_cross_drift.py` — the exit-gate cross-provider classifier.
- `scripts/check_iac_sync.py` — the baseline gate: IaC == live per provider.

## Run the demo

One command, from the repo root:

```sh
export DEVIN_ENTERPRISE_SERVICE_USER=<service-user token>   # required, never printed
./scripts/demo.sh                # live run: one detection session per domain
./scripts/demo.sh --dry-run      # rehearsal: collect + render prompts,
                                 # no API calls, no ACU spend
```

The script starts the simulators if they aren't already answering on
:8081/:8082, then runs the orchestrator. Each session compares its domain's
Akamai vs Cloudflare state, then — if it finds disagreements — **the CLI
prints a delimited block with the session URL and the session's question**
(numbered findings plus its recommendation). Answer either:

- on stdin, e.g. `1: cloudflare, 2: akamai` or `skip`, or
- directly in the Devin UI at the printed URL — the CLI notices the session
  left the waiting state and stops prompting.

The session then applies the answers, edits `terraform/<domain>/` on the
losing side, opens the PR, and the CLI prints the PR URL plus the per-field
changes. To re-show a finished run offline:

```sh
./scripts/demo.sh --replay artifacts/<run_id>
```

Flags worth knowing on stage: `--demo` / `--plain` (rich output is the
default on a tty, plain when piped), `--full-equivalences`,
`--show-schema`, `--domain` (repeatable subset), `--report-only` (compare
and report — no operator question, no remediation, no PR), `--answers FILE`
(YAML `domain -> {field: akamai|cloudflare|skip}` for a non-interactive or
rehearsal run), `--base-branch` (what remediation PRs branch off; defaults
to the feature branch carrying `terraform/`), `--max-acu`. See
`docs/orchestrator.md` for the eight phases and the API notes.

## Validate

```sh
python3 -m venv .venv && .venv/bin/pip install pyyaml jsonpath-ng
.venv/bin/python scripts/validate_cross_drift.py --check   # asserts the 7 findings
.venv/bin/python scripts/check_iac_sync.py                 # baseline: IaC == live
terraform fmt -check -recursive terraform/
.venv/bin/python -m pytest -q
```

`validate_cross_drift.py` resolves both provider paths per mapped field
against the fixtures and classifies each into `disagreement`,
`missing_at_{akamai,cloudflare}`, `equivalent` (including
textually-different-but-equivalent, the proof the comparison is semantic),
or `not_comparable`; `--check` asserts exactly the seven documented
findings. `check_iac_sync.py` is a *baseline* gate asserting each provider's
Terraform equals its fixture — after a remediation PR merges, the fixed
field legitimately differs until applied, so it is deliberately not part of
`pytest`.

## Simulators

```sh
scripts/run_simulators.sh    # akamai :8081, cloudflare :8082
```

See `docs/simulators.md` for endpoints, auth, and curl examples.
