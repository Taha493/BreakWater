# AI Security Gateway

An LLM firewall: an OpenAI-compatible proxy that sits between your app and its model provider,
inspects every request and response, and logs a redacted record of each call. A red-team
harness that measures how well it holds comes in later milestones.

Full design: [docs/SPEC.md](docs/SPEC.md). Choices made along the way: [docs/DECISIONS.md](docs/DECISIONS.md).

**Status: milestone M2 (detectors).** The proxy, auth, event log, and Docker setup work, and
rules-based detection is on: prompt injection is blocked, secrets, personal data, system prompt
echoes, and exfiltration links in responses are redacted. The ML classifier and LLM judge come
in M5, document scanning and the tool-call guard in M3.

## What it catches

| Detector | Inspects | Catches | Default action |
| --- | --- | --- | --- |
| `injection_rules` | user messages, tool results | instruction override, role reassignment, prompt-reveal requests, fake chat tokens | block (user), strip the message (tool result) |
| `leak_secrets` | responses, prompts, tool results | provider API keys, tokens, private keys, JWTs, credentials in URLs or assignments | redact in responses, block in prompts |
| `leak_pii` | responses | emails, card numbers (Luhn-checked), CNIC, phone numbers | redact |
| `leak_system_prompt` | responses | long verbatim echoes of the system prompt; the canary token if enabled | redact; canary blocks |
| `exfil_channel` | responses | markdown images or links that carry data to non-allowlisted domains | redact |

Before any rule runs, text is normalized (Unicode NFKC, zero-width and control characters
removed, Cyrillic/Greek lookalikes folded) and hidden content is extracted (HTML and markdown
comments; base64, hex, and URL-encoded segments, two levels deep), so obfuscated attacks are
caught too.

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

Responses carry `X-Gateway-Request-Id` and `X-Gateway-Verdict` (`allow`, `redacted`, or
`blocked`). A blocked call returns 403 with the findings (rule ids, reasons, spans; never the
matched text). With `stream: true` the gateway holds back the last `STREAM_HOLDBACK_CHARS`
characters (default 200) and rescans as text arrives, so a secret split across chunks is still
redacted; a blocking finding ends the stream with an error event. For streams the verdict
header reflects the request only.

To check text without proxying, use `/v1/scan/text`:

```sh
curl -s localhost:8000/v1/scan/text -H "Authorization: Bearer <client key>" \
  -H 'Content-Type: application/json' \
  -d '{"text": "Ignore previous instructions.", "role": "user"}'
```

It returns a Verdict (`action`, `risk_score`, `findings`) with HTTP 200 even when the action
is `block`. Roles: `user`, `assistant`, `system`, `retrieved`, `tool_result`.

## Policy and rules

Behaviour is configured in [gateway/rules/](gateway/rules/): thresholds and actions in
`policies.yaml`, injection phrasing in `injection.yaml`, secret formats in `secrets.yaml`.
Rules are [RE2](https://github.com/google/re2/wiki/Syntax) patterns, so they always run in
linear time. Changes are picked up within `CONFIG_RELOAD_SECONDS` (default 2) without a
restart; a change that fails to validate is ignored and logged, and the last good version keeps
running. Every rule needs at least two positive and two negative examples in
[tests/unit/rule_cases.yaml](tests/unit/rule_cases.yaml).

To edit them under Docker, copy the directory, mount it, and point the gateway at it:

```yaml
# docker-compose.override.yml
services:
  gateway:
    volumes: ["./my-rules:/rules:ro"]
    environment:
      POLICIES_PATH: /rules/policies.yaml
      RULES_DIR: /rules
```

Optional extras in `policies.yaml`: `canary.enabled` adds a per-session canary token to the
system prompt and blocks any response that repeats it; `detectors.exfil_channel.allowed_domains`
and `detectors.leak_pii.allowed_email_domains` exempt your own domains.

## Run locally

```sh
uv sync
cp .env.example .env    # fill in; GATEWAY_DATABASE_URL defaults to SQLite
uv run gateway db upgrade
uv run uvicorn scripts.mock_upstream:app --port 9000 &   # optional fake upstream
uv run uvicorn gateway.main:app --reload
```

## Endpoints

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/chat/completions` | client key | Inspect, forward upstream, inspect, log |
| `POST /v1/scan/text` | client key | Scan one text and return a Verdict |
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
uv run python scripts/eval_detectors.py --show-misses   # detector recall and false positives
scripts/smoke.sh                                # acceptance test against Docker Compose
```

`scripts/eval_detectors.py` runs the labeled set in [tests/data/](tests/data/) (60 attacks,
100 benign) and reports recall per attack class, the false positive rate, and per-detector
precision. The set was written alongside the rules, so treat its numbers as optimistic.

`scripts/smoke.sh` brings up its own throwaway Compose project with generated secrets, runs
the M1 and M2 acceptance checks, and tears it down. It needs access to the Docker daemon.
