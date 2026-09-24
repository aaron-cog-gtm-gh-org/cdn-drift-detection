# Phase 03 — Devin orchestrator

`orchestrator/` wires the phase-01 fixtures and phase-02 simulators to real
Devin sessions. The flow, in one line: **collect provider state over the
simulator APIs → attach it → one detection session per domain → validate the
structured output → route findings to remediation child sessions.**

Everything is run from the repo root with `~/cdn-drift-venv/bin/python`.

## Layout

| module | role |
|---|---|
| `orchestrator/config.py` | Devin org/base URL, simulator bases, golden branch/db, session defaults, `run_id` (`<UTC ts>-<short sha>`), `get_token()` |
| `orchestrator/devin_client.py` | thin v3 client: `upload_attachment`, `create_session`, `get_session`, `poll_session` |
| `orchestrator/collect.py` | per-domain provider bundles via `ApiSource`, `artifacts/<run_id>/` writer, `manifest.json` |
| `orchestrator/run_detection.py` | the CLI orchestrating collect → upload → sessions → poll → validate → remediate |
| `orchestrator/remediate.py` | groups findings by `remediation_route` and creates remediation child sessions |
| `orchestrator/schema.py` | the structured-output contract (authored; do not edit) |
| `orchestrator/prompts.py` | detection/remediation prompt templates (authored; do not edit) |
| `drift/sources.py` | `DiskSource`/`ApiSource`/`DOMAINS`, shared by the validator and the orchestrator |

## Prerequisites

- Both simulators running: `scripts/run_simulators.sh` (akamai :8081, cloudflare :8082).
- Golden store seeded: `scripts/load_golden_store.py` → `store/golden.db`.
- `DEVIN_ENTERPRISE_SERVICE_USER` in the environment — the service-user token.
  `config.get_token()` exits cleanly if absent; it is never printed or written
  to artifacts.

## Usage

```sh
# render everything without touching the API
python -m orchestrator.run_detection --dry-run

# live run — one detection session per domain, then remediation children
python -m orchestrator.run_detection

# options
--domain online.rbcdemo.ca --domain www.rbcdemo.ca   # subset
--max-acu 10            # per-session ACU ceiling (default 10)
--devin-mode normal     # v3 devin_mode field
--no-remediate          # detection only
--poll-interval 20      # seconds between session polls
```

## What a run does

1. **Collect** — `collect.collect_all` pulls the same documents the validator
   compares, over the simulator HTTP APIs only (no fixture-tree reads):
   Akamai property/rules/hostnames/appsec, Cloudflare zone/settings/
   rulesets/dns_records. Written as pretty, stable-ordered JSON to
   `artifacts/<run_id>/<domain>.{akamai,cloudflare}.json`, plus
   `manifest.json` (paths, sha256, attachment URLs, `golden_sha`,
   `mapping_version`, sim bases). `artifacts/` is gitignored.
2. **Upload** — both files per domain via `POST /v3/organizations/{org}/attachments`.
3. **Detect** — `POST .../sessions` once per domain with the rendered
   `DETECTION_PROMPT`, `DETECTION_SCHEMA` as `structured_output_schema`,
   tags `cdn-drift, detection, domain:<d>, run:<run_id>`. All four sessions
   are created before any polling, so they run in parallel; polling happens on
   a thread pool.
4. **Validate** — the returned `structured_output` is checked locally for the
   contract's load-bearing parts (required keys, enum membership, echoed
   identity fields); violations print as `SCHEMA:` lines and set a nonzero
   exit code. Reports land in `artifacts/<run_id>/detection/<domain>.json`.
5. **Remediate** — findings group by `remediation_route`:
   - `iac_pr` → one child session per domain (`REMEDIATION_PROMPT_IAC`); the
     findings' `provider_path`/`golden_path` locators are rendered as readable
     blocks, not raw JSON.
   - `human_review` → one child session per domain
     (`REMEDIATION_PROMPT_HUMAN`, escalation briefing; opens no PR).
   - `provider_api` → **no session**; recorded as deferred — provider writes
     are out of scope until phase 04.
   - `verdict: inconclusive` domains are skipped entirely; zero-finding
     routes open no session.

## v3 API notes

- Verified live: `POST /v3/organizations/{org}/sessions`,
  `GET .../sessions/{id}`, `GET .../sessions?limit=`,
  `POST .../attachments` (multipart field `file`).
- Session statuses: `new | claimed | running | exit | error | suspended |
  resuming`. `poll_session` also terminates on `status_detail == "finished"`
  or a non-null `structured_output`.
- There is no `idempotent` flag in v3; reruns create new sessions (tagged by
  `run:<run_id>`).
- **Parent/child linking (unverified):** remediation sessions pass the
  detection session id as the `devin_id` query parameter on create. Whether
  the parent's `child_session_ids` actually populates is to be confirmed in
  the first E2E run; if it does not, fall back to a `parent:<session_id>` tag
  and stop calling them children.

## Deliberate constraints

- The detection prompt forbids the session from running
  `scripts/validate_fixtures.py` or reading `docs/drift-scenarios.md` — both
  encode the expected answer; reading them would make the POC prove nothing.
- Tests use `httpx.MockTransport` for all Devin calls and spawn throwaway
  simulators on free ports — nothing hits the real API, ever.
- The orchestrator never writes to a provider API; remediation via IaC opens
  PRs for humans to merge.
