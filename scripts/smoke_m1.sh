#!/usr/bin/env bash
# M1 acceptance smoke test against the real Docker Compose stack (spec section 12).
#
# Runs in its own compose project with freshly generated throwaway secrets, so it does not
# touch a stack you started yourself. Tears everything down (including its volume) on exit.
# Set KEEP=1 to leave the stack running for inspection.
#
# Usage: scripts/smoke_m1.sh
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT=aisg-m1-smoke
ENV_FILE="$(mktemp)"
BASE=http://127.0.0.1:8000
FAKE_SECRET="sk-$(python3 -c 'print("s" * 40)')"
FAKE_EMAIL="smoke.user@example.org"

rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(48))'; }
cat >"$ENV_FILE" <<EOF
POSTGRES_PASSWORD=$(rand)
UPSTREAM_API_KEY=mock-upstream-key
GATEWAY_HASH_SECRET=$(rand)
ADMIN_BOOTSTRAP_KEY=$(rand)
EOF
BOOTSTRAP_KEY="$(grep ADMIN_BOOTSTRAP_KEY "$ENV_FILE" | cut -d= -f2-)"

compose() { docker compose -p "$PROJECT" --env-file "$ENV_FILE" --profile dev "$@"; }
cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then compose down -v --remove-orphans >/dev/null 2>&1 || true; fi
  rm -f "$ENV_FILE"
}
trap cleanup EXIT

pass=0
fail=0
check() { # check "<name>" <command...>
  local name="$1"; shift
  if "$@"; then echo "PASS  $name"; pass=$((pass + 1)); else echo "FAIL  $name"; fail=$((fail + 1)); fi
}
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== starting stack"
compose up -d --build --wait

check "gateway and database running (healthz)" \
  test "$(curl -s "$BASE/healthz" | json "['database']")" = ok

echo "== keys"
ADMIN_KEY="$(curl -s -X POST "$BASE/admin/keys" -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"smoke-admin","role":"admin"}' | json "['key']")"
CLIENT_KEY="$(curl -s -X POST "$BASE/admin/keys" -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"smoke-client","role":"client"}' | json "['key']")"

BODY="{\"model\":\"mock-model\",\"messages\":[{\"role\":\"user\",\"content\":\"hello, my key is $FAKE_SECRET, email $FAKE_EMAIL\"}]}"

echo "== auth"
check "missing key rejected (401)" \
  test "$(status -X POST "$BASE/v1/chat/completions" -H 'Content-Type: application/json' -d "$BODY")" = 401
check "wrong key rejected (401)" \
  test "$(status -X POST "$BASE/v1/chat/completions" -H 'Authorization: Bearer gw.0000000000000000.wrongwrongwrongwrongwrongwrongwrong' -H 'Content-Type: application/json' -d "$BODY")" = 401
check "bootstrap key disabled after first admin key (401)" \
  test "$(status -X POST "$BASE/admin/keys" -H "Authorization: Bearer $BOOTSTRAP_KEY" -H 'Content-Type: application/json' -d '{"name":"x","role":"client"}')" = 401

echo "== proxy"
HEADERS="$(mktemp)"
RESPONSE="$(curl -s -D "$HEADERS" -X POST "$BASE/v1/chat/completions" \
  -H "Authorization: Bearer $CLIENT_KEY" -H 'Content-Type: application/json' \
  -H 'X-Gateway-App: smoke' -H "X-Gateway-User: $FAKE_EMAIL" -d "$BODY")"
check "request reaches mock upstream and returns its response" \
  grep -q "mock reply to: hello" <<<"$RESPONSE"
check "X-Gateway-Verdict: allow" grep -qi '^x-gateway-verdict: allow' "$HEADERS"
check "X-Gateway-Request-Id present" grep -qi '^x-gateway-request-id: ' "$HEADERS"
rm -f "$HEADERS"

STREAM_BODY="${BODY%\}},\"stream\":true}"
STREAM="$(curl -sN -X POST "$BASE/v1/chat/completions" -H "Authorization: Bearer $CLIENT_KEY" \
  -H 'Content-Type: application/json' -d "$STREAM_BODY")"
check "streaming passthrough ends with [DONE]" grep -q 'data: \[DONE\]' <<<"$STREAM"

echo "== events in Postgres"
sleep 1 # background event writes finish after the response is sent
sql() { compose exec -T db psql -U gateway -d gateway -tA -c "$1"; }
check "4 events written (request+response, 2 calls)" \
  test "$(sql "select count(*) from events")" = 4
check "excerpts are redacted" \
  test "$(sql "select count(*) from events where excerpt_redacted like '%[REDACTED:api_key]%' and excerpt_redacted like '%[REDACTED:email]%'")" = 4
check "full text not stored" test "$(sql "select count(*) from events where full_text is not null")" = 0
DUMP="$(compose exec -T db pg_dump -U gateway -d gateway --data-only)"
check "raw secret absent from the whole database" bash -c '! grep -q "$1" <<<"$2"' _ "$FAKE_SECRET" "$DUMP"
check "raw email absent from the whole database" bash -c '! grep -q "$1" <<<"$2"' _ "$FAKE_EMAIL" "$DUMP"
LOGS="$(compose logs gateway 2>&1)"
check "raw secret absent from gateway logs" bash -c '! grep -q "$1" <<<"$2"' _ "$FAKE_SECRET" "$LOGS"

echo
echo "passed: $pass  failed: $fail"
test "$fail" -eq 0
