# AI Security Gateway

Defensive security tool: an LLM firewall (FastAPI proxy) plus a red-team harness.
Full spec: docs/SPEC.md. Read it before changing anything.

## Commands
- Install: `uv sync`
- Run: `uv run uvicorn gateway.main:app --reload`
- Test: `uv run pytest`
- Lint and types: `uv run ruff check . && uv run mypy gateway/core gateway/detectors`
- Full stack: `docker compose up`

## Rules
- Work one milestone at a time (spec section 13). Finish and verify before starting the next.
- Write tests together with the code. Run lint, types, and tests before saying a task is done.
- Do not invent model names, library APIs, or package versions. Check the docs or the
  installed package. Record each choice in docs/DECISIONS.md.
- Never log or store raw secrets or full prompts by default (spec section 9).
- Never commit secrets. Use environment variables.
- Attack content stays generic. Red-team targets must be owned: true (spec section 8).
- If the spec is ambiguous or conflicts with reality, stop and ask. Do not guess silently.