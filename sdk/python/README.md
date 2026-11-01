# breakwater-client

A small client for Breakwater's scan endpoints.

```python
from breakwater_client import GatewayClient, ToolDenied, guarded_tool

gw = GatewayClient("http://localhost:8000", api_key="gw....")

# Ingestion: scan chunks before indexing them; index only the allowed ones.
result = gw.scan_chunks(chunks, doc_id="handbook.pdf", source="intranet", trust_level="internal")
safe = [c for c, r in zip(chunks, result["chunks"]) if r["allowed"]]

# Retrieval: re-scan top-k chunks before they enter the prompt (cached by the gateway).
allowed = gw.filter_retrieved(top_k_chunks, session="user-42")


# Agents: check every tool call before it runs.
@guarded_tool(gw, agent_id="support-agent", session=lambda: current_session_id())
def send_email(to: str, subject: str, body: str) -> None: ...
```

`guarded_tool` raises `ToolDenied` on `deny` and `ConfirmationRequired` on
`require_confirmation` (or calls your `confirm` callback). It works on plain and async
functions, so it can wrap LangGraph tools before they are registered.

Install: `pip install ./sdk/python`.
