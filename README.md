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
- `scripts/validate_fixtures.py` — the exit-gate validator.

## Validate

```sh
python3 -m venv .venv && .venv/bin/pip install pyyaml jsonpath-ng
.venv/bin/python scripts/validate_fixtures.py   # exits non-zero on any mismatch
terraform fmt -check -recursive golden/
```

The validator resolves every mapping path against its fixture, applies each
comparator against golden, and asserts the findings equal the documented set —
including that both suppression cases produce no finding.
