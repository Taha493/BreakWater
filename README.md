# AI Security Gateway

An LLM firewall: an OpenAI-compatible proxy that sits between your app and its model provider,
inspects every request and response, and logs a redacted record of each call. A red-team
harness that measures how well it holds comes in later milestones.

Full design: [docs/SPEC.md](docs/SPEC.md). Choices made along the way: [docs/DECISIONS.md](docs/DECISIONS.md).

**Status: milestone M1 (foundation and proxy).** The proxy, auth, event log, and Docker setup
work. No detectors run yet, so every request is allowed; detection arrives in M2.

## Run with Docker Compose

```sh
cp .env.example .env    # then fill in the secrets (see comments in the file)
docker compose --profile dev up --build
```

`--profile dev` also starts `mock_upstream`, a fake model that echoes your message back. To use
a real provider, set `UPSTREAM_BASE_URL` and `UPSTREAM_API_KEY` in `.env` and drop the profile.
The gateway listens on `127.0.0.1:8000`; Postgres is not exposed to the host.

Create keys. The bootstrap key works only until the first admin key exists:

```sh
curl -s -X POST localhost:8000/admin/keys \
  -H "Authorization: Bearer $ADMIN_BOOTSTRAP_KEY" -H 'Content-Type: application/json' \
  -d '{"name": "me", "role": "admin"}'
# use the returned admin key to create a client key
curl -s -X POST localhost:8000/admin/keys \
  -H "Authorization: Bearer <admin key>" -H 'Content-Type: application/json' \
  -d '{"name": "my-app", "role": "client"}'
```

Keys are shown once; only an HMAC is stored. You can also create them with
`docker compose exec gateway gateway keys create --name my-app --role client`.

Point your app at the gateway by changing its base URL to `http://localhost:8000/v1` and its
API key to the client key:

```sh
curl -s localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer <client key>" -H 'Content-Type: application/json' \
  -H 'X-Gateway-App: my-app' -H 'X-Gateway-User: user-123' \
  -d '{"model": "mock-model", "messages": [{"role": "user", "content": "hello"}]}'
```

Responses carry `X-Gateway-Request-Id` and `X-Gateway-Verdict`. `stream: true` is passed
through as server-sent events.

## Run locally

```sh
uv sync
cp .env.example .env    # fill in; GATEWAY_DATABASE_URL defaults to SQLite
uv run gateway db upgrade
uv run uvicorn scripts.mock_upstream:app --port 9000 &   # optional fake upstream
uv run uvicorn gateway.main:app --reload
```

## Endpoints in M1

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/chat/completions` | client key | Inspect, forward upstream, inspect, log |
| `POST /admin/keys` | admin or bootstrap key | Create a client or admin key |
| `POST /admin/keys/{id}/revoke` | admin key | Revoke a key |
| `GET /healthz` | none | Liveness and database check |

Every non-2xx response uses the error format from spec section 5.

## Privacy defaults

- Events store a keyed hash of the text and a 160-character excerpt with secrets and PII
  redacted. Raw text is stored only if `STORE_FULL_TEXT=true`.
- User ids from `X-Gateway-User` are stored as keyed hashes.
- Logs are JSON and never contain prompt or response text.

## Development

```sh
uv run pytest                                   # unit + integration tests
uv run ruff check . && uv run mypy gateway/core gateway/detectors
scripts/smoke_m1.sh                             # M1 acceptance test against Docker Compose
```

`scripts/smoke_m1.sh` brings up its own throwaway Compose project with generated secrets, runs
the M1 acceptance checks, and tears it down. It needs access to the Docker daemon.
