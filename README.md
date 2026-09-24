# cdn-drift-detection

Synthetic-but-realistic fixtures for a CDN configuration drift-detection demo,
aimed at a large Canadian bank mid-migration from Akamai to Cloudflare. Later
phases add provider simulators, a golden-state store, and a Devin-orchestrated
drift/remediation loop — this repo currently carries the phase-01 inputs:
fixtures, golden Terraform, and the semantic field mapping.

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
- `golden/<domain>/` — intended state: `main.tf` (Akamai `~> 6.2`,
  Cloudflare `~> 5.0`), `rules/rules.json` golden rule tree, and
  `appsec/security-config.json` (www, online, api).
- `mapping/akamai-cloudflare-mapping.yaml` — versioned semantic mapping
  (~50 fields, value tables, comparators, provider-default suppression).
- `docs/drift-scenarios.md` — the 12 seeded drift/suppression scenarios.
- `docs/fixture-notes.md` — version targets and every schema guess.
- `docs/simulators.md` — phase-02 simulator endpoints, auth, approximations.
- `sim/` — FastAPI simulators serving fixtures over PAPI/App Sec and
  Cloudflare v4 wire shapes (read-only).
- `store/` — SQLite golden-state store (`golden.db` is generated, gitignored).
- `scripts/validate_fixtures.py` — the exit-gate validator.

## Run the demo (phase 03)

One command, from the repo root:

```sh
export DEVIN_ENTERPRISE_SERVICE_USER=<service-user token>   # required, never printed
./scripts/demo.sh                # live run: one detection session per domain
./scripts/demo.sh --dry-run      # rehearsal: same output through bundle
                                 # collection + rendered prompts, no ACU spend
```

The script starts the simulators if they aren't already answering on
:8081/:8082, then runs the orchestrator. To re-show a finished run's findings
offline — bad room network, or no time for a live run:

```sh
./scripts/demo.sh --replay artifacts/<run_id>
```

Flags worth knowing on stage: `--demo` / `--plain` (rich output is the
default on a tty, plain when piped so CI and captured output stay stable),
`--full-equivalences` (expand the equivalent-fields reasoning),
`--show-schema` (print the full output contract in a dry run), `--domain`
(repeatable subset), `--no-remediate`, `--max-acu`, `--pace` (demo-step
delay; default 0.35s, `--pace 0` for a fast run). See `docs/orchestrator.md`
for the nine phases and the API notes.

## Validate

```sh
python3 -m venv .venv && .venv/bin/pip install pyyaml jsonpath-ng
.venv/bin/python scripts/validate_fixtures.py   # exits non-zero on any mismatch
terraform fmt -check -recursive golden/
```

The validator resolves every mapping path against its fixture, applies each
comparator against golden, and asserts the findings equal the documented set —
including that both suppression cases produce no finding.

## Simulators and golden store (phase 02)

```sh
scripts/run_simulators.sh                       # akamai :8081, cloudflare :8082
.venv/bin/python scripts/load_golden_store.py   # seeds store/golden.db
.venv/bin/python scripts/validate_fixtures.py --source api --golden store
```

`--source api` pulls fixtures over the simulators' HTTP APIs and `--golden
store` reads intended state from SQLite; the finding set is identical to
`--source disk --golden files`. See `docs/simulators.md` for endpoints and
curl examples.
