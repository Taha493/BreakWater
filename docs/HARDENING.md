# Hardening checklist

Each hardening requirement in spec section 11, how the gateway meets it, and the test that
shows it (or why there is no test). Section 12's security tests (oversized bodies, auth
bypass, catastrophic regex input, dashboard output escaping) are covered here too.

| Requirement | How it is met | Evidence |
| --- | --- | --- |
| **Input limits: request body** | `MAX_BODY_BYTES` (1 MiB default) is enforced on the raw stream before parsing, including chunked bodies without a length | `tests/integration/test_proxy.py` (413 with and without Content-Length) |
| **Input limits: scanned text** | `limits.max_scan_chars` per inspected text; over the limit blocks or truncates per policy | `tests/unit/test_pipeline.py::test_scan_limit_blocks_or_truncates` |
| **Input limits: documents** | At most 500 chunks per call; extraction runs in a thread with a 15 s timeout | `tests/integration/test_documents.py` (501 chunks: 422), `test_hardening.py::test_slow_extraction_is_cut_off` |
| **Input limits: costly layers** | Classifier scores at most `max_windows` windows per text (first and last ones beyond that); the judge sees at most `max_input_chars` (start and end) | `tests/unit/test_injection_classifier.py`, `tests/unit/test_judge.py::test_long_text_is_clipped_at_both_ends` |
| **Regex safety** | Rules run on `google-re2` (linear time, no backtracking); rule files are validated on load | `tests/unit/test_rules.py::test_rules_are_fast_on_pathological_input`; property tests in `tests/unit/test_normalize.py` |
| **Judge isolation: data, not instructions** | Inspected text is quoted between `<untrusted-NONCE>` markers with a fresh random nonce per call; the system prompt says never to follow it | `tests/unit/test_judge.py::test_text_is_quoted_data_between_nonce_markers`, `test_real_nonces_are_random` |
| **Judge isolation: no tools** | Neither client sends tools | `test_anthropic_client_request`, `test_openai_compatible_client_request` |
| **Judge isolation: schema-validated JSON** | Anthropic structured outputs (`output_config.format`) or `response_format`, then strict Pydantic validation (no extra keys, typed fields, confidence in 0..1) | `test_invalid_replies_are_rejected` |
| **Judge isolation: failure modes** | Errors, timeouts, refusals, cut-off or invalid replies, and an exhausted call budget all go to `judge_error` (default: block if the score was at least 0.5) | `test_judge_error_modes`, `test_timeout_is_a_judge_error`, `test_call_budget_per_minute`, `test_a_judge_steered_into_a_bad_reply_fails_closed` |
| **Judge is never the only layer** | The judge only sees text layers 1-2 already scored as borderline, and can only add risk (it never lowers a score) | `test_benign_verdict_allows_and_never_lowers_the_score`, `test_only_borderline_scores_reach_the_judge` |
| **Keys: hashed, constant-time** | Only keyed hashes are stored; comparison uses `hmac.compare_digest` | `tests/unit/test_keys.py::test_hashes_match`; `tests/integration/test_auth.py` |
| **Keys: revocation** | Revoked keys fail at once; the bootstrap key stops working once an admin key exists | `test_auth.py::test_revoked_key_rejected`, `test_bootstrap_flow` |
| **Keys: per-key rate limit** | Token bucket per key per process (`RATE_LIMIT_CLIENT_PER_MINUTE` 3000, `RATE_LIMIT_ADMIN_PER_MINUTE` 120); 429 with `Retry-After` | `tests/integration/test_hardening.py::test_token_bucket`, `test_keys_are_rate_limited` |
| **Keys: separate admin key** | Client and admin roles are separate; each route requires one | `test_auth.py::test_roles_are_separate`; `test_admin_api.py::test_admin_routes_need_an_admin_key` |
| **Keys: admin IP allowlist** | `ADMIN_IP_ALLOWLIST` (IPs or CIDRs) is checked before the key on every admin and red-team route | `test_hardening.py::test_admin_routes_only_from_allowed_addresses`, `test_allowlist_is_validated` |
| **No server-side fetching** | Scanning never resolves or fetches URLs in content; red-team runs take a target name from config, never a URL | `test_hardening.py::test_scanning_never_fetches_urls` (fails on any DNS lookup or socket connect); `test_redteam.py::test_api_auth_and_errors` (a `url` field is rejected) |
| **Transport: TLS** | Not handled by the gateway: terminate TLS at a reverse proxy. Compose binds every port to 127.0.0.1 so nothing is exposed by default. Behind a proxy, run uvicorn with `--forwarded-allow-ips` so the IP allowlist sees the real client | No test: deployment configuration |
| **Transport: CORS** | Only `CORS_ORIGINS` (the dashboard origin) gets CORS headers; credentials are never allowed (the key is a bearer header) | `test_hardening.py::test_cors_only_for_the_dashboard_origin` |
| **Audit log** | Policy seed, update, and rollback; key creation and revocation (with `max_layer`); quarantine release and keep; red-team runs and their keys; retention cleanups; user data export and deletion | `test_admin_api.py::test_policy_versions_and_rollback`, `test_auth.py::test_bootstrap_flow`, `test_documents.py`, `test_redteam.py`, `test_layers.py` |
| **Supply chain: pinned dependencies** | `uv.lock`; `dashboard/package-lock.json` with exact versions; base images pinned by tag and digest | `tests/unit/test_supply_chain.py` |
| **Supply chain: audits in CI** | `pip-audit` and `npm audit` run on every push (`.github/workflows/ci.yml`) | CI (not yet run: no remote) |
| **Supply chain: minimal image, non-root** | `python:3.12-slim` with only runtime dependency groups; the dashboard is a static build on `nginx-unprivileged`; the gateway runs as uid 10001 | `tests/unit/test_supply_chain.py::test_containers_run_as_non_root` |
| **Dashboard: output escaping** | Logged text is rendered as React text, never HTML; lint bans `dangerouslySetInnerHTML` and `innerHTML`; nginx sends a strict CSP (`script-src 'self'`, `connect-src` the gateway only) | `dashboard/src/test/dashboard.test.tsx` ("escapes excerpts and finding reasons"); `dashboard/eslint.config.js` |
| **Dashboard: key in memory only** | The admin key lives in React state; lint bans `localStorage` and `sessionStorage` | `dashboard.test.tsx` ("never stores it") |
| **Privacy: retention** | Events, findings, red-team transcripts, expired taint marks, and old retrieval scans are deleted after `RETENTION_DAYS`, hourly in the gateway and on demand with `gateway db cleanup` | `test_hardening.py::test_retention_cleanup`, `test_gateway_runs_retention_on_start` |
| **Privacy: per-user export and deletion** | `gateway data export|delete --user ID` (or `--user-hash`) | `test_hardening.py::test_user_export_and_delete` |

## Known limits

- **Rate limits and the judge call budget are per process.** With N replicas a key gets N
  times the limit. A shared store (Postgres or Redis) would make them global.
- **The classifier and judge add latency.** See the README for measured numbers. The
  classifier's window cap trades coverage of very long text for bounded latency: layer 1
  rules still scan all of it.
- **The judge can be attacked.** A reply it is steered into must still validate and can
  only add risk, but a judge persuaded to answer "not an attack" leaves the text where
  layers 1-2 put it (allowed and logged in the borderline band).
