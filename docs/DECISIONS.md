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

## M2: Detectors

Answers to the M2 plan questions were approved as proposed (Q1 to Q8 below reference them).

### Regex engine
- **`google-re2` 1.1.20251105 (BSD-3-Clause) for the YAML rules.** RE2 matches in linear time
  with no backtracking, so a crafted prompt cannot hang a rule. Checked against the installed
  package: `re2.compile(pattern, options)`, `Options.case_sensitive`, `Options.log_errors`,
  `finditer`/`span()` in character offsets; lookarounds and backreferences fail to compile.
  Rules are also rejected if they match empty or blank text. The `regex` package (timeouts)
  stays the fallback if RE2 proves too limiting.
- **Stdlib `re` for fixed internal patterns** (Layer 0 extraction, PII, exfiltration). These
  are written with bounded, disjoint character classes; each has pathological-input tests.
  Two classes that could rescan on long runs of `[` were tightened during M2.

### Layer 0 normalization
- Per-character NFKC (not whole-string) so every output character maps to an input offset;
  combining marks (Mn/Me), format characters (Cf, includes zero-width and bidi controls),
  controls, and a few invisible letters are dropped; whitespace collapses to one space.
- **Homoglyphs: a curated table** of Cyrillic and Greek lookalikes of Latin letters, not the
  full Unicode confusables list (~6k entries, many multi-character, and broad folding would
  garble legitimate non-Latin text). NFKC already handles fullwidth and math alphanumerics.
- Plain printable ASCII with single spaces skips normalization (identity).
- Decoding: base64 runs of 16+ chars, hex runs of 16+ hex digits or `\x` escapes, and
  URL-encoded tokens with 2+ escapes. Decoded bytes must be UTF-8, at least 90% printable, and
  contain 3+ letters, so hashes and binary are ignored. Pure hex, pure letters, and pure digits
  are not treated as base64. Two levels deep (spec), at most 32 extracted views and 200k
  extracted characters per text.
- Comments (HTML `<!-- -->`, including unterminated ones, and markdown `[//]: # (...)`) and
  decoded segments become views; a match inside one maps to the whole segment's span, and the
  finding's reason names the view ("found in base64 content").
- Hidden-text counts (`removed_chars`, `comment_count`) are computed but not yet findings;
  "hidden text is itself a finding" is an M3 document-scanner requirement.

### Detectors
- **`injection_rules`**: 18 YAML rules. Rules are written as A1; the detector reports A2 when
  the role is `retrieved` or `tool_result` (same phrasing, indirect delivery). At most 10 hits
  per rule per text.
- **`leak_secrets`**: 13 YAML rules for public token formats, plus a high-entropy heuristic
  (tokens of 32+ chars with letters and digits, Shannon entropy >= 4.3 bits/char, so hex hashes
  at <= 4.0 never qualify). Entropy hits score 0.6: judge band, logged but never acted on.
  **Inspects `user` too** (spec table says assistant and tool_result) to implement Q1's
  `secrets: block` for prompts.
- **`leak_system_prompt`**: canary echo (score 1.0, always blocks), and word overlap with the
  request's system prompt using 8-word shingles; a run of >= 12 words scores 0.75, >= 24 scores
  0.9. Both thresholds are in `policies.yaml`.
- **`leak_pii`**: emails (domain allowlist in policy), card numbers with Luhn check (windows
  aligned to digit groups, so a card followed by extra digits is still found, found by a
  Hypothesis test), dashed CNIC (`5-7-1`), phone numbers (10-15 digits with a `+` or
  separators; IPs and ISO dates excluded). Presidio deferred (Q8).
- **`exfil_channel`**: markdown images and `<img>` tags (0.9) or links (0.75) to
  non-allowlisted domains whose URL carries data (query >= 16 chars, a value >= 12 chars, or a
  path segment >= 32 chars); data-free external images score 0.4 (logged). The span covers the
  whole construct so redaction leaves nothing behind.

### Policy
- **Q1, spec conflict resolved**: A3 findings in assistant text are redacted (the M2 acceptance
  criterion); `A3.secrets: block` applies to `leak_secrets` findings outside assistant text
  (prompts, tool results); a canary echo always blocks.
- Action vocabulary: `allow`, `block`, `redact`, `quarantine`, `strip_and_log`, `deny`.
  `strip_and_log` is reported as `redact` (the verdict enum has no strip) with the whole message
  replaced; `deny` is reported as `block`. A class/role pair with no configured action blocks.
- Weights multiply detector scores (`weights:` in `policies.yaml`, default 1.0).
- Judge band: allow and log until the M5 judge exists.
- New `policies.yaml` sections: `weights`, `limits` (`max_scan_chars: 200000`,
  `over_limit: block|truncate`; spec section 11 asks for a scan limit but names no value),
  `canary`, `detectors` (per-detector settings), and
  `failure_mode.request_inspection_error` (Q7: fail closed).
- Gateway-generated findings (detector error, scan limit) always block, whatever the class
  policy says; without this a response-side detector error was being *redacted* (caught by a
  unit test).

### Hot reload (Q2)
- `ConfigStore` checks the mtime and size of `policies.yaml`, `injection.yaml`, and
  `secrets.yaml` at most every `CONFIG_RELOAD_SECONDS` (new env var, default 2) and rebuilds the
  policy, detectors, and redactor together. A file that fails to load keeps the last good
  version and logs an error; startup with invalid files fails.
- New env var `RULES_DIR` (default: the packaged `gateway/rules`).
- `ruleset_version` is now a hash over all three files (was: policy file only).
- `GET/PUT /admin/policies` and the `policy_versions` table remain M5.

### Proxy
- **Request inspection covers every `user` message (as `user`) and every `tool` message (as
  `tool_result`)** (Q3), concurrently. Findings gain `message_index` (an addition to the spec's
  Finding shape, plus a `findings.message_index` column and migration). The request event's
  hash and excerpt still use the newest user message.
- Flagged tool results are replaced by `[REDACTED:<rule_id>]` before forwarding; the verdict
  header says `redacted`.
- Redaction placeholders are now `[REDACTED:<rule_id>]` everywhere (M1 used format kinds).
- **Canary (Q5)**: off by default. `cnry-` + 20 hex of HMAC(secret, session id or request id),
  appended to the first system/developer message as an "internal reference" note, or inserted
  as a system message if none exists.
- Upstream error details are redacted with the runtime redactor before they are returned.
- **Streaming**: assistant text is held back by `STREAM_HOLDBACK_CHARS` and rescanned every 64
  new characters; content is re-framed into new SSE events (text is preserved, bytes are not);
  role/finish/usage events keep their order relative to text; a block ends the stream with an
  error event and no `[DONE]`. The `X-Gateway-Verdict` header is sent before the response is
  known, so for streams it reflects the request only; the response verdict is in the event log.
- **`/v1/scan/text`**: returns the Verdict with HTTP 200 even when the action is block (the
  caller asked for an opinion). Optional context: `app`, `session`, `user`, `system_prompt`.
  Logged with direction `request` (user/system), `response` (assistant), or `document`
  (retrieved/tool_result).

### Evaluation (Q6)
- `tests/data/attacks.yaml` (60: 20 each of A1, A2, A3, including deliberate paraphrases and a
  format-less leak that rules should miss) and `tests/data/benign.yaml` (100: user prompts,
  assistant responses, retrieved text, with near-misses). `scripts/eval_detectors.py` reports
  and never fails CI.
- **Caveat**: both sets were written alongside the rules, so the numbers are optimistic. An
  independent benign set (e.g. sampled real prompts, licence permitting) should replace or
  extend it before quoting results externally.

### Tooling
- `scripts/smoke_m1.sh` became `scripts/smoke.sh` and covers M1 and M2. The mock upstream leaks a
  fake key when a message contains `MOCK_LEAK`, so response redaction can be tested without
  sending a secret (which the gateway now blocks).

### Open questions carried forward
- M3: whether proxied chat messages can mark retrieved context (role `retrieved`) and how; and
  turning hidden-text signals into findings.
- M5: `judge.enabled: true` in `policies.yaml` vs `JUDGE_ENABLED=false` (from M1).

## M3: RAG document scanner and tool-call guard

The approved plan's defaults were applied (Q1 to Q11 below reference them).

### Libraries (Q6)
Checked at install; versions pinned by `uv.lock`:
- `pdfplumber` 0.11.10 (MIT; brings `pdfminer.six` MIT and `pypdfium2` BSD-3/Apache-2.0):
  per-character `size` and `non_stroking_color` make tiny and white text detectable.
  PyMuPDF was not used (AGPL).
- `beautifulsoup4` 4.15.0 (MIT) with the stdlib `html.parser`.
- `python-docx` 1.2.0 (MIT): `run.font.hidden`, `font.color.rgb`, `font.size` (EMU; 12700 per
  point), `core_properties`.
- `jsonschema` 4.26.0 (MIT): `Draft202012Validator`, schemas checked at load.
- Demo only, in a `demo` dependency group: `qdrant-client` 1.20.0 (Apache-2.0; uses
  `query_points`, `search` no longer exists) and server image `qdrant/qdrant:v1.20.0` (matches
  the client; released 2026-10-22).
- Dev only: `reportlab` 5.1.0 (BSD) to build PDF fixtures; `types-jsonschema`.

### Document scanner
- **Extraction** returns visible text plus hidden segments with their kind. HTML: comments,
  `hidden` attribute, inline styles that hide (display, visibility, opacity, zero or 1px font,
  zero size, large negative offsets, clip), simple `.class`/`#id` rules from `<style>`, and
  text whose colour equals its background (white assumed when none is declared). External
  stylesheets and the full CSS cascade are not evaluated. PDF: font size < 2pt, white fill
  (grey, RGB, or CMYK), or outside the page box; up to 200 pages. DOCX: hidden runs, white
  runs, runs <= 2pt, core properties. Markdown: comments, image alt text, embedded HTML.
  Alt text and metadata are scanned but not reported as hidden (they are normal content).
  Scripts, styles, templates, and `noscript` are dropped.
- **Chunking**: paragraphs packed to 1000 characters with a 200-character overlap. Visible
  chunks are returned (`text`) so callers can index the gateway's chunks; hidden chunks never
  are. Every chunk carries `origin` (`visible`, `metadata`, `alt_text`, or the hiding kind).
- **`hidden_content` detector (Q4)**: hidden text by source 0.5, comments 0.35, 3+ invisible
  characters 0.4; all below the default block threshold, so hidden text alone makes a
  document `suspicious`. What hidden text *says* is judged by `injection_rules`.
- **Status (Q5)**: a chunk is `quarantined` at or above its trust level's `block_at`
  (internal 0.80, partner 0.70, public_web 0.60, user_upload 0.60; new `trust_levels` section
  in `policies.yaml`), `suspicious` at or above `allow_below`, else `clean`. A document takes
  its worst chunk. Status is threshold-based; class actions in `actions:` do not apply here.
- **Cache**: chunks table lookup by keyed text hash + ruleset version. The cached risk score is
  re-thresholded for the requesting trust level. A cache hit runs no detectors and returns no
  findings (`cached: true`). Ingest and retrieval share the cache. A ruleset change (any of the
  four rule files) invalidates it.
- **Release (Q8)**: a released chunk passes for that exact content under any ruleset until the
  content changes. `POST /admin/quarantine/{id}/keep` records the opposite decision (added for
  the dashboard's "Keep quarantined" action; not in the spec's API table). Both are audited.
- **Storage**: `documents` gains `scan_mode`; `chunks` gains `ruleset_version`, `hidden_kind`,
  and `created_at` (needed for the cache); `quarantine.decision` is null while pending, then
  `released` or `kept`. Every scan (ingest or retrieval) is a `documents` row; cached chunks are
  not stored again.
- **Input (Q7)**: text, base64 file, or caller chunks (max 500); the 1 MB body limit applies.
  Extraction runs in a worker thread with a 15 s timeout (a timed-out thread is not killed;
  hostile PDFs are bounded by the body size and page limit).

### Tool-call guard
- **Policy file** `gateway/rules/tools.yaml`, hot-reloaded with the others. Spec fields plus
  `impact: low|high` (the spec does not define "high-impact"), `schema` (JSON Schema), and
  `on_taint`. Constraint names follow the spec; the arguments they apply to are fixed:
  `to_domain_allowlist` -> to/cc/bcc/recipient/recipients, `max_body_chars` -> body,
  `path_prefix` -> path/file/file_path/filename. Paths are URL-decoded (twice), backslashes
  become slashes, and `..` is resolved before the prefix check. Strings over 20,000 chars are
  denied.
- **Not a `Detector`**: it judges a structured call, so it is a separate class in
  `detectors/tool_guard.py` with its state behind a `GuardState` protocol.
- **Taint (Q2, Q3)**: keyed hashes of 6-word shingles and entities (URLs, emails, domains,
  paths, 6+ digit numbers) from untrusted text, stored per keyed session hash in a `taint`
  table for 1 hour (`taint_ttl_seconds`). Sources: `/v1/scan/document` with a `session`,
  `/v1/scan/text` with role `retrieved`/`tool_result` and a session, and `tool` messages in
  proxied chats with `X-Gateway-Session`. Only high-impact tools are checked, and only when the
  call has a session. Expected false positive: a legitimate address that also appeared in a
  retrieved document is treated as tainted (deny, or require_confirmation via `on_taint`).
- **Rate limits** count `tool_call` events in the last 60 s (per agent via `events.app`, per
  session via `events.session`), so they hold across gateway instances; the event is written
  before the response. New optional `session_rate_limit_per_minute`.
- **Session (Q9)**: request field `session`, falling back to `X-Gateway-Session`.
- **Decisions are HTTP 200** with `decision`, `rule_id`, `reason`, and A4 findings. Events:
  direction `tool_call`, role `tool_call`, action `allow`/`block`/`require_confirmation`.
- Schema errors report the location and failed keyword only (validator messages can echo
  argument values).

### SDK (`sdk/python`, package `aisg-client`)
- Depends only on httpx. `GatewayClient` (sync and async methods), `scan_chunks`,
  `filter_retrieved`, `check_tool_call`, `guarded_tool` (sync or async functions; raises
  `ToolDenied` / `ConfirmationRequired`, or calls a `confirm` callback), and `harden_context`
  (random per-call delimiter marker, so a document cannot close the block). No LangGraph
  dependency: the decorator wraps plain functions before they are registered as tools.
- Installed editable in the `dev` and `demo` groups (`uv add --editable ./sdk/python`).

### Demo app (`demo_app/`)
- **Embeddings (Q1)**: feature-hashing bag of words (512 dims, blake2b), no model download.
- Ingest is naive on purpose (hidden text is indexed). With `protected: true` it also sends
  its chunks to `/v1/scan/document` (ingest), so retrieval-time scans hit the cache.
  `/ask` with `protected: true` re-scans top-k, drops disallowed chunks, wraps the rest with
  `harden_context`, and calls the model through the gateway; `protected: false` goes straight
  to the upstream (the M4 baseline). The gateway key comes from `DEMO_GATEWAY_KEY` or an
  `X-Gateway-Key` request header.
- Sample docs: three clean, three poisoned (CSS-hidden HTML, white-text PDF, hidden DOCX
  run), generated by `demo_app/make_sample_docs.py`.
- **Compose**: `qdrant` and `demo_app` are in a `demo` profile (not started by default,
  because the app is deliberately vulnerable); the demo binds to 127.0.0.1:8100.
- **Docker image**: one image; a `UV_GROUPS` build arg selects dependency groups. The gateway
  build installs none (`--no-default-groups`), so it ships no demo or test packages.

### Other
- `EventInput.role` accepts `"tool_call"`; `EventInput.action` can override the verdict's action.
- Migrations render the app's `UTCDateTime` as `sa.DateTime(timezone=True)` (`render_item` in
  `env.py`), so migration files never import app code.
- Retrieved context inside proxied chat messages is still not marked (Q10); apps scan chunks
  with `/v1/scan/document` before building the prompt.
- Not built (Q11): per-document `allowed_roles` (spec stretch goal), and a mock model that
  follows injected instructions (M4, where attack success is measured).

## M4: Red-team harness

The approved plan's defaults were applied: a simulated model, demo app test hooks, `judge`
criteria skipped until M5, a regression tolerance of 2 points, and a separate end-to-end
benign set.

### Simulated target model
- `scripts/sim_model.py`, served by the mock upstream for the model name `sim-obedient`, is a
  deterministic stand-in for a model that obeys every instruction it reads. It repeats red-team
  canaries (`RTC-` + 12 hex) found outside its system prompt, reproduces markdown links and
  images with absolute URLs, dumps its system prompt (or the lines holding a secret) when asked,
  repeats text it is told to confirm, and calls each offered tool its input asks for. It reads
  base64 and hex runs (two levels) and ignores zero-width characters, like a capable model.
- Unprotected ASR is near 100% by design. Protected ASR measures what the gateway stops when
  the model is fully hijackable, not real-model susceptibility; every report says so when the
  model is simulated (`model_simulated` in the config snapshot).
- The demo app's default model is now `sim-obedient` (`DEMO_MODEL`).
- `scripts/` became a package (`__init__.py`) so the mock upstream can import the simulator;
  `tests/unit/test_eval_data.py` now imports `scripts.eval_detectors` instead of editing
  `sys.path`.

### Attack library and benign set
- 75 attacks, one YAML file each under `gateway/redteam/attacks/<category>/` (20 direct, 25
  indirect, 15 leakage, 15 tool abuse), in the spec's format. Fields added: `question` (the
  user's question for indirect attacks), `history` (multi-turn), `agent` (offer tools),
  `system_secret` (put the canary in the system prompt), `tool_result` (template), and per
  document `hidden`, `hiding`, `metadata`. `{{PAYLOAD}}` marks where the payload goes.
- Content is generic and widely documented phrasing; hosts are RFC 2606 reserved names
  (`*.example`, `example.com/org/net`), enforced by a test. PII is synthetic.
- Validation: a retrieved-document attack must place `{{PAYLOAD}}` in a document, and every
  attack needs at least one criterion besides `judge`.
- 100 benign cases in `gateway/redteam/benign.yaml`: 50 questions (including near-misses such
  as "ignore the typo" and "act as a guide"), 30 documents in all five formats (some with
  benign hidden menus, cookie banners, and comments), 5 tool results, 15 in-scope agent tasks.
  `send_email` is left out: its policy requires confirmation, which is not a false positive.
  This set is separate from `tests/data/benign.yaml`, which has no delivery or documents.
- Mutators: case, base64, hex, zero-width, language (fixed Spanish, French, and German phrase
  tables), and split across two planted documents (retrieved-document attacks only). Each
  attack runs as-is plus `--mutations` (default 1) variants. The choice depends only on the
  seed and attack id, and canaries, addresses, URLs, paths, and tool names are never altered.
- Canaries are fresh per probe (`secrets.token_hex`), so reruns differ only in the token.

### Targets and runner
- `gateway/redteam/targets.yaml` (`REDTEAM_TARGETS_PATH`) with `${VAR:-default}` expansion.
  `owned: true` is required and checked before anything runs or is stored. Per-target limits:
  concurrency 4, 20 requests/s, 30 s timeout, 2 retries on transport errors (httpx
  `TransportError`, which includes timeouts) only.
- `demo_rag` plants each probe's documents under a fresh namespace (`/plant`), asks, and
  deletes them, so probes cannot see each other's documents. The sample documents live in the
  `base` namespace and are not used by runs.
- `http_chat` mimics an app using the SDK: documents become retrieved context (all text,
  hidden parts included), filtered with `/v1/scan/document` in protected mode; tool calls are
  checked with `/v1/scan/tool-call`.
- `python_callable`: `module:function(probe: dict, protected: bool)`, sync or async.
- An intervention is any gateway action on the probe: blocked request or response, redacted
  response, excluded chunk, denied tool, or a tool held for confirmation. For attacks this is
  the block rate; for benign cases it is a false positive.
- Probes run unprotected and then protected back to back under a concurrency limit; results
  are stored in probe order, so runs with the same seed list the same rows.
- **Attribution**: targets return the gateway request ids they caused; after the run, blocked
  probes are matched to non-allow events and their findings (lowest layer, detector names).
  This needs the gateway's database, which the CLI and API share.
- **Gateway key**: each run mints a client key (`redteam-run-<id>`) and revokes it at the end,
  both audited. `REDTEAM_GATEWAY_KEY` overrides it.

### Metrics and regression
- ASR = successful / probes that ran; errored probes are excluded and counted separately (the
  CLI warns). Reported overall, per category, and split into base and mutated probes.
- Latency overhead is measured on benign probes only (blocked attacks return early), as the
  per-case difference protected minus unprotected; nearest-rank p50/p95.
- A run is compared with the latest completed run against the same target with the same
  attack and benign sets (`library_hash`), seed, and mutation count. The first full run in the
  compose test was compared with a smaller smoke run and reported a false regression, which
  is why the comparison is restricted to comparable runs. A regression is a category whose
  protected ASR rose by more than `regression_tolerance` (0.02). A regressed run is still
  stored and becomes the next baseline.
- Exit codes: 0 done, 1 regression with `--fail-on-regression`, 2 refused or misconfigured,
  3 run failed.

### Storage and API
- `redteam_runs` (spec fields plus `status` and `error`) and `redteam_results` (spec fields
  plus `position`, `kind`, `variant`, `category`, `detectors`, `error`). JSON columns use
  `sa.JSON`. Migration `bec14c182111`.
- Transcripts store the probe, response, tool calls, and interventions, each string cut to
  2000 characters and passed through the same secret and PII redactor as event excerpts.
  Canaries stay (they are harmless by design).
- `POST /redteam/runs` takes only a target name (plus seed, mutations, limit, categories), so
  the gateway never calls a URL a caller supplied. Runs execute as background tasks in the
  gateway process; tasks are cancelled on shutdown and the run is marked failed.
- Reports are built from the stored run. The HTML report is self-contained, escapes every
  value, and is served with `Content-Security-Policy: default-src 'none'; style-src
  'unsafe-inline'`.

### CI
- Every push: the full in-process run (gateway, demo app, and simulated model on ASGI
  transports) is part of `pytest`, and the compose smoke test runs a short red-team run
  through the CLI and the API plus the regression gate.
- Nightly (`.github/workflows/redteam-nightly.yml`): `scripts/redteam_local.sh` starts the
  three services as local processes on SQLite and runs `--fail-on-regression`. The run
  database is carried between nights with `actions/cache/restore@v6` and `actions/cache/save@v6`
  (v6.1.0 is the latest release, checked 2026-10-31; both sub-actions exist at that tag), and
  reports are uploaded with `actions/upload-artifact@v7` (v7.0.2, checked the same day).

### Changes to earlier milestones
- `tools.yaml`: `support-agent` `rate_limit_per_minute` raised from 20 to 120. The limit
  counts calls from all sessions of the agent together, and a single red-team run exceeded 20,
  which would have shown up as false positives. The per-session limit stays at 10.
- `reportlab` moved from the dev group to the demo group: the demo app renders planted PDFs.
  The first compose run failed every PDF probe without it.
- The demo app extracts HTML comments and `<meta>` content, PDF Subject and Keywords, and DOCX
  subject, keywords, and comments as text, as some loaders do, so metadata attacks reach the
  model in unprotected mode.
- `gateway.__version__` added; the FastAPI app and run snapshots use it.

### Results and known gaps (seed 1, one mutation per attack, compose with Postgres)
- ASR without / with the gateway: direct injection 100% / 65%, indirect 96% / 74%, leakage
  100% / 33%, tool abuse 97% / 0%; overall 98% / 49%. False positive rate 0/100. Latency
  overhead p50 11 ms, p95 44 ms in compose; p50 8 ms, p95 23 ms with local processes. Both
  are on one developer laptop with the simulated model; they are not production numbers.
- The rules-only layer misses paraphrased injections ("disregard the rules above", personas,
  fake banners, authority claims). The rules were not tuned to this library, so it stays a
  fair baseline for the M5 classifier and judge.
- The demo app scans its own chunks (plain text), so the gateway's hidden-text signal never
  fires in the demo: hidden instructions are caught only by their wording. Scanning the
  original file at ingest (`content_base64`) and skipping quarantined documents would use it.
- A secret leaked on its own (the canary line, under the 12-word overlap threshold) is not
  caught: the gateway cannot know an app's secrets unless its own canary feature is used.
- Hex payloads wrapped across PDF lines, and a delete instruction split so the record id
  lands in the other chunk, fail even unprotected; they are counted as failures, not removed.
