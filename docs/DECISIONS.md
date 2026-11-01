# Decisions

Choices made where the spec left room, with the reason. Newest milestone last.

## M1: Foundation and proxy

### Toolchain and versions
- **Python 3.12** for local development (`.python-version`) and the Docker image. The package
  declares `requires-python >= 3.11` per spec. 3.12 is chosen over 3.14 (the system Python) because
  the M5 classifier stack (`transformers`, torch) is safest on a widely supported version.
- **Dependency versions are not hand-picked.** They were added with `uv add` and are pinned by
  `uv.lock`. Versions resolved at M1: FastAPI 0.162.0, Starlette 1.10.0, Pydantic 2.14.2,
  pydantic-settings 2.16.2, SQLAlchemy 2.1.6, Alembic 1.20.1, httpx 0.28.1, psycopg 3.3.6,
  aiosqlite 0.22.1, uvicorn 0.54.0; dev: pytest 9.2.0, pytest-asyncio 1.4.1, respx 0.23.1,
  Hypothesis 6.170.14, ruff 0.17.3, mypy 2.4.1, pip-audit 2.10.1. APIs used were checked against
  the installed packages.
- **Docker images**: `python:3.12-slim`, `ghcr.io/astral-sh/uv:0.12.7` (matches local uv),
  `postgres:17-alpine`. Postgres 17 rather than 18 because the 18 images changed the data
  directory layout; 17 keeps the well-known `/var/lib/postgresql/data` volume path. Tags were
  confirmed to exist. Digest pinning is left for the M5 supply-chain hardening item.
- **CI actions**: `actions/checkout@v7`, `astral-sh/setup-uv@v10` (latest majors on GitHub as
  of 2026-10-30; setup-uv v10 has been out since 2026-08-12).

### Database
- **Async SQLAlchemy.** The spec's default URL is the sync form `sqlite:///./gateway.db`, so
  `to_async_database_url` maps `sqlite://` to `sqlite+aiosqlite://` and `postgres(ql)://` to
  `postgresql+psycopg://` (psycopg 3 has a native async mode, so one driver serves both the app
  and Alembic). URLs that already name a driver are left alone.
- **M1 creates only the tables M1 uses**: `events`, `findings`, `api_keys`, plus `audit_log`.
  Every later table arrives with its milestone in its own migration.
- **`audit_log` table** (not in the section 9 table list) backs the section 11 audit log
  requirement: actor, action, target, time. M1 records key creation and revocation.
- **`events.full_text` column** (not in the section 9 list) holds raw text only when
  `STORE_FULL_TEXT=true`, which section 11 implies needs somewhere to go. It is NULL by default.
- **UTC-aware timestamps everywhere** via a `UTCDateTime` column type, because SQLite drops
  timezone info and would otherwise hand back naive datetimes.
- **Migrations run from `gateway db upgrade`**, which locates the migration scripts relative to
  the package, so it works from any working directory and inside the installed wheel. The
  container runs it before starting uvicorn. `alembic.ini` exists only for authoring migrations.
  The migration test also runs `alembic check` to catch drift between models and migrations.

### Keys and hashing
- **New env var `GATEWAY_HASH_SECRET`** (required, at least 32 chars). Section 9 needs a salt for
  `user_hash` and section 5 needs hashed keys; the env table in section 11 has no variable for it.
- **HMAC-SHA256 with domain separation** (`text`, `user`, `api_key`) rather than bcrypt/argon2:
  API keys are 256-bit random tokens, so a slow KDF adds latency without adding security.
  `text_hash` is keyed too, so short prompts cannot be confirmed by hashing guesses.
  Consequence: rotating the secret invalidates all keys and user hashes.
- **Key format `gw.<16 hex id>.<43 char secret>`.** The public id is the primary key, so lookup
  is by id and the hash comparison is `hmac.compare_digest` (constant time, section 11).
- **Bootstrap key** (`ADMIN_BOOTSTRAP_KEY`) is an admin credential that works only while no
  active admin key exists, which makes it effectively one-time. Startup fails with a clear
  message if there is neither a bootstrap key nor an admin key. Minimum 32 chars. An empty
  value is treated as unset (Compose passes empty strings for unset variables).
- **Key management**: `POST /admin/keys` and `POST /admin/keys/{id}/revoke` (not in the
  section 5 table) plus `gateway keys create|revoke` on the CLI. Both audit. Revoke is idempotent.
- **Roles are strict**: client routes reject admin keys and admin routes reject client keys
  (403, `wrong_key_role`).

### Proxy behaviour
- **Upstream errors** all become `upstream_error`: non-2xx upstream status → 502 with
  code `upstream_status_<n>` and the upstream's error message, redacted and capped; timeout → 504
  `upstream_timeout`; connection failure → 502 `upstream_unreachable`; non-JSON → 502
  `upstream_invalid_response`. Upstream 4xx is not passed through as-is, because an upstream
  401 means the server's provider key is wrong, not the client's.
- **New env var `UPSTREAM_TIMEOUT_SECONDS`** (default 60).
- **Mid-stream upstream failure** ends the stream with a final `data: {"error": ...}` event,
  preceded by a blank line so it never merges into a partial upstream event.
- **What gets logged per call**: one `request` event (the newest user message, role `user`) and
  one `response` event (assistant text). Earlier turns were logged on their own calls; logging
  the full history each turn would multiply storage and keep re-storing the system prompt.
  M2 decides which messages the detectors inspect.
- **Event writes run as a background task** after the response is sent, in their own DB session,
  to keep them off the latency path. Blocked and failed calls write synchronously.
- **Excerpt redaction in M1** uses a fixed set of linear-time regexes in `core/redact.py`
  (private key blocks, JWTs, common provider key formats, bearer tokens, `password=`-style
  assignments, emails, Pakistani CNIC, long digit runs), then truncates to 160 chars. Redaction
  runs before truncation so a cut secret cannot leave a raw prefix. M2 replaces this with the
  `leak_secrets`/`leak_pii` detectors.
- **Client-supplied request ids are ignored**; the gateway always generates its own.
- **Body size limit** is enforced in ASGI middleware that buffers up to `MAX_BODY_BYTES`, so it
  holds for chunked requests with no `Content-Length`.
- **`internal_error`** is added to the error `type` list for unhandled exceptions (500).
- **Policy file location**: `POLICIES_PATH` defaults to the packaged
  `gateway/rules/policies.yaml` (spec layout), not the cwd-relative `rules/policies.yaml`
  written in the env table, so the default works from any directory and inside the image.
  `ruleset_version` is the first 12 hex chars of the SHA-256 of the policy file.
- **Pre-M2 policy**: risk = max finding score; `>= block_at` blocks (quarantines for
  `retrieved`); everything else allows. Until M2 adds redaction, any non-allow response verdict
  blocks rather than ships.

### Deferred (with milestone)
- Streaming hold-back scan and mid-stream blocking: M2 (`STREAM_HOLDBACK_CHARS` is read but unused).
- Per-key rate limiting and admin IP allowlist: M5 hardening.
- Client pass-through of their own upstream key: not in M1; needs a header that does not collide
  with the gateway `Authorization` header. To decide when picked up.
- Retention cleanup job (`RETENTION_DAYS` is read but unused): later milestone.

### Open spec questions (not blocking M1)
- `policies.yaml` sets `judge.enabled: true` while the `JUDGE_ENABLED` env var defaults to
  `false`. Which one wins needs a decision in M5.
