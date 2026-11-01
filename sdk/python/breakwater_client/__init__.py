"""Python client for Breakwater, the LLM firewall (spec section 7, integration)."""

from breakwater_client.client import GatewayClient, GatewayError
from breakwater_client.guard import ConfirmationRequired, ToolDenied, guarded_tool
from breakwater_client.hardening import harden_context

__all__ = [
    "ConfirmationRequired",
    "GatewayClient",
    "GatewayError",
    "ToolDenied",
    "guarded_tool",
    "harden_context",
]
