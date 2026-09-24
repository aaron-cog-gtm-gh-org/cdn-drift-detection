#!/usr/bin/env bash
# Start both provider simulators. PIDs go to .sim.pids; logs to /tmp.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${VENV:-$HOME/cdn-drift-venv}/bin/python"

"$PY" -m sim.run --provider akamai     --port 8081 > /tmp/akamai-sim.log 2>&1 &
echo $! >> .sim.pids
"$PY" -m sim.run --provider cloudflare --port 8082 > /tmp/cloudflare-sim.log 2>&1 &
echo $! >> .sim.pids
echo "akamai-sim     :8081 (log /tmp/akamai-sim.log)"
echo "cloudflare-sim :8082 (log /tmp/cloudflare-sim.log)"
