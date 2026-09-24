#!/usr/bin/env bash
# One-command demo entry point: ensure simulators are up, ensure the
# service-user token is in the environment, then run the orchestrator.
#   ./scripts/demo.sh            # live run
#   ./scripts/demo.sh --dry-run  # rehearsal: collect + render, no sessions
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${HOME}/cdn-drift-venv/bin/python"

up() { curl -sf -m 3 -o /dev/null "http://127.0.0.1:$1/healthz"; }

if ! up 8081; then
  echo "starting akamai simulator on :8081"
  nohup "$PY" -m sim.run --provider akamai --port 8081 >/tmp/sim-ak.log 2>&1 &
fi
if ! up 8082; then
  echo "starting cloudflare simulator on :8082"
  nohup "$PY" -m sim.run --provider cloudflare --port 8082 >/tmp/sim-cf.log 2>&1 &
fi
for port in 8081 8082; do
  for _ in $(seq 1 30); do up "$port" && break || sleep 0.5; done
  up "$port" || { echo "simulator on :$port did not come up" >&2; exit 1; }
done

if [ -z "${DEVIN_ENTERPRISE_SERVICE_USER:-}" ]; then
  echo "DEVIN_ENTERPRISE_SERVICE_USER is not set — the service-user token is" \
       "required to call the Devin v3 API." >&2
  exit 1
fi

exec "$PY" -m orchestrator.run_detection "$@"
