# Devin orchestrator — cross-provider detection, human decision, remediation PR

`orchestrator/` wires the simulators and the `terraform/` IaC tree to real
Devin sessions. The flow, in one line: **collect both providers' state →
attach it → one session per domain cross-compares Akamai vs Cloudflare →
the session asks the operator which side is right and blocks → the CLI
relays the answer → the session edits the losing provider's Terraform and
opens the PR.**

There are no separate remediation sessions: one session does comparison,
decision, remediation, and PR. There is no golden state — each provider's
Terraform mirrors its own live state; the defect is the disagreement.

Everything is run from the repo root.

## Layout

| module | role |
|---|---|
| `orchestrator/config.py` | Devin org/base URL, simulator bases, `IAC_BRANCH` (default base for remediation PRs), session defaults, `run_id` (`<UTC ts>-<short sha>`), `get_token()` |
| `orchestrator/devin_client.py` | thin v3 client: `upload_attachment`, `create_session`, `get_session`, `poll_session(on_waiting=…)`, `list_messages`, `send_message`, `waiting()` |
| `orchestrator/collect.py` | per-domain `akamai`/`cloudflare`/`mapping` bundles via `ApiSource`, `artifacts/<run_id>/` writer, `manifest.json` (with `iac_sha` provenance) |
| `orchestrator/run_detection.py` | the CLI: collect → upload → create sessions → poll with the decision relay → validate → report findings, decisions, PRs |
| `orchestrator/console.py` | `PlainReporter` and `DemoReporter` (rich); one pipeline, injected reporter; findings table is field / severity / akamai / cloudflare / recommendation |
| `orchestrator/schema.py` | the structured-output contract (authored; do not edit) |
| `orchestrator/prompts.py` | detection prompt template + `build_detection_prompt` (authored; do not edit the text) |
| `drift/iac.py` | `load_iac` (terraform tree → API-shaped docs) and `iac_sha` |

## Prerequisites

- Both simulators running: `scripts/run_simulators.sh` (akamai :8081,
  cloudflare :8082). `demo.sh` starts them if down.
- `DEVIN_ENTERPRISE_SERVICE_USER` in the environment — the service-user
  token. `config.get_token()` exits cleanly if absent; it is never printed
  or written to artifacts.
- The `terraform/` tree must exist on `--base-branch` (default
  `devin/1790338896-cross-provider-remediation`) — sessions branch from it
  and open their PRs against `main`.

## Usage

```sh
# the one command — checks sims (starts them if down), requires
# DEVIN_ENTERPRISE_SERVICE_USER, passes extra args through
./scripts/demo.sh

# rehearsal: everything through bundle collection plus the rendered
# prompts and schema summary — no API calls, no ACU spend
./scripts/demo.sh --dry-run

# offline re-show of a finished run's findings/remediation/summary
./scripts/demo.sh --replay artifacts/<run_id>

# options (demo.sh passes them through; run_detection takes them directly)
--domain online.rbcdemo.ca --domain www.rbcdemo.ca   # subset
--max-acu 25            # per-session ACU ceiling (default 25 — one session
                        # now does comparison + remediation)
--devin-mode normal     # v3 devin_mode field
--report-only           # comparison only — no operator question, no
                        # remediation, no PR
--answers FILE          # YAML domain -> {field: akamai|cloudflare|skip};
                        # non-interactive decision relay
--base-branch BRANCH    # what remediation PRs branch off
--poll-interval 20      # seconds between session polls
--demo / --plain        # force rich or plain output; default is rich on a
                        # tty, plain when piped
--full-equivalences     # expand each equivalent field's reasoning
--show-schema           # dry run only: dump the full structured-output schema
```

## The decision relay

When a session finds disagreements it messages the operator (numbered
findings, both values, its recommendation) and enters a waiting state. The
CLI's `OperatorRelay`:

1. Prints a delimited block — the domain, the **clickable session URL**,
   and the session's latest `source == "devin"` message in full.
2. Prompts on stdin (`1: cloudflare, 2: akamai`, or `skip`). Answering
   **directly in the Devin UI** works too: while waiting for a line the
   relay re-checks the session state; if the session left the waiting
   state on its own, the CLI notes it and sends nothing.
3. Posts the answer via `send_message` (which also resumes a suspended
   session) and keeps polling.
4. On finish, prints `remediation.pull_request_url`, the per-field
   `remediation.changes` (field, provider changed, from → to), and any
   `remediation.unresolved` entries.

With `--answers FILE`, step 2's answer is composed from the YAML
(`domain -> {field: akamai|cloudflare|skip}`) instead of stdin — the
non-interactive/rehearsal path.

Multiple domains run concurrently, so several sessions can be waiting at
once; the relay holds a lock and takes them one at a time in arrival
order — a session whose turn hasn't come keeps its captured waiting state
and is prompted as soon as the console frees.

Every question shown and answer sent (or "answered in the UI") is appended
to `artifacts/<run_id>/detection/<domain>.messages.jsonl`, so a run is
reconstructable after the fact; `--replay` re-renders from the same run
dir.

## What the console shows

Eight numbered phases, one pipeline, two renderers (`--demo` / `--plain`,
auto-detected from tty):

1. **IaC state** — domain / role / `iac_sha` table + mapping version.
2. **Pulling Akamai configs** — one row per document fetched.
3. **Pulling Cloudflare configs** — zone, settings, rulesets, DNS records.
4. **Writing bundles** — akamai / cloudflare / mapping files, sha256, size.
5. **Uploading to Devin** — one line per attachment.
6. **Creating detection sessions** — domain → session id → URL.
7. **Sessions working** — live status + ACUs; `waiting` episodes are
   interleaved with the decision blocks above.
8. **Findings + remediation** — per-domain findings table (severity,
   disagreement kind, akamai value, cloudflare value, recommendation),
   equivalences block, then PR URL / changes / unresolved, then summary.

## What a run does

1. **Collect** — `collect_*` pulls the same documents the classifier
   compares, over the simulator HTTP APIs. Written to
   `artifacts/<run_id>/<domain>.{akamai,cloudflare,mapping}.json` plus
   `manifest.json` (paths, sha256, `iac_sha`, `mapping_version`, sim
   bases). `artifacts/` is gitignored.
2. **Upload** — all three bundles per domain via
   `POST /v3/organizations/{org}/attachments`.
3. **Detect** — `POST .../sessions` once per domain with the rendered
   prompt, `repos=[REPO_SLUG]` (the session opens the PR itself),
   `DETECTION_SCHEMA` as `structured_output_schema`, tags
   `cdn-drift, detection, domain:<d>, run:<run_id>`.
4. **Relay** — see above; fires once per waiting episode and re-arms when
   the session goes back to working.
5. **Validate** — `structured_output` is checked locally for the
   contract's load-bearing parts; violations print as `SCHEMA:` lines and
   set exit code 1. Reports land in
   `artifacts/<run_id>/detection/<domain>.json`. An `inconclusive` verdict
   or a `fields_reviewed` coverage gap exits 2.

## v3 API notes

- Verified live: `POST /v3/organizations/{org}/sessions`,
  `GET .../sessions/{id}`, `GET .../sessions/{id}/messages`
  (cursor-paginated via `end_cursor`/`has_next_page`, `source` ∈
  `{devin,user}`), `POST .../sessions/{id}/messages` (`{"message": …}` —
  also resumes a suspended session), `POST .../attachments`.
- Waiting states — **not terminal**: `status:"running"` +
  `status_detail:"waiting_for_user"`, and `status:"suspended"` +
  `status_detail:"inactivity"` (idled out while waiting; resumable by
  posting a message). `poll_session` terminates on `status` ∈
  `{exit,error}`, `status_detail == "finished"`, or non-null
  `structured_output`.
- The session object carries `url` (used verbatim — never string-built),
  `pull_requests`, `structured_output`, `acus_consumed`, `session_id`.
- There is no `idempotent` flag in v3; reruns create new sessions (tagged
  `run:<run_id>`).

## Deliberate constraints

- The detection prompt forbids the session from running
  `scripts/validate_cross_drift.py` or reading `docs/drift-scenarios.md` —
  both encode the expected answer; reading them would make the POC prove
  nothing. The session has the repo checked out for remediation but is
  told not to use it for the comparison.
- Tests use `httpx.MockTransport` for all Devin calls and fake clients for
  the session lifecycle — nothing hits the real API, ever.
- The orchestrator never writes to a provider API; remediation lands as
  IaC PRs for humans to merge.
