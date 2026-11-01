#!/usr/bin/env bash
# Runs the red-team harness against the demo app without Docker: starts the mock upstream
# (with the simulated model), the gateway, and the demo app as local processes on spare
# ports, runs `gateway redteam run --target demo_rag`, then stops them.
#
# Extra arguments go to the run command, e.g. --fail-on-regression or --limit 5.
# Runs are stored in the SQLite file $REDTEAM_DB (default ./redteam.db); keep that file to
# compare each run with the previous one. Used by the nightly CI job.
#
# Usage: scripts/redteam_local.sh [run options...]
set -euo pipefail

cd "$(dirname "$0")/.."
rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(48))'; }

MOCK_PORT=9100 GATEWAY_PORT=8010 DEMO_PORT=8110
DB="${REDTEAM_DB:-$PWD/redteam.db}"
export GATEWAY_DATABASE_URL="sqlite:///$DB"
export UPSTREAM_BASE_URL="http://127.0.0.1:$MOCK_PORT/v1"
export UPSTREAM_API_KEY=local-mock-key
# Fresh secrets each time: runs mint and revoke their own gateway keys.
export GATEWAY_HASH_SECRET="$(rand)" ADMIN_BOOTSTRAP_KEY="$(rand)"
export LOG_LEVEL=WARNING
export REDTEAM_DEMO_URL="http://127.0.0.1:$DEMO_PORT"
export DEMO_GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
export DEMO_UPSTREAM_BASE_URL="$UPSTREAM_BASE_URL" DEMO_UPSTREAM_API_KEY="$UPSTREAM_API_KEY"
export DEMO_QDRANT_URL=":memory:" DEMO_MODEL=sim-obedient

pids=()
cleanup() { if ((${#pids[@]})); then kill "${pids[@]}" 2>/dev/null || true; fi; }
trap cleanup EXIT

uv run gateway db upgrade
uv run uvicorn scripts.mock_upstream:app --port "$MOCK_PORT" --log-level warning &
pids+=($!)
uv run uvicorn gateway.main:app --port "$GATEWAY_PORT" --log-level warning &
pids+=($!)
uv run uvicorn demo_app.vulnerable_rag:app --port "$DEMO_PORT" --log-level warning &
pids+=($!)

for port in "$MOCK_PORT" "$GATEWAY_PORT" "$DEMO_PORT"; do
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$port/healthz" >/dev/null && break
    sleep 0.5
  done
  curl -sf "http://127.0.0.1:$port/healthz" >/dev/null || { echo "port $port did not start" >&2; exit 2; }
done

uv run gateway redteam run --target demo_rag "$@"
