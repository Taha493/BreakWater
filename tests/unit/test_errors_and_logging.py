from __future__ import annotations

import json
import logging

from breakwater.api.errors import error_body
from breakwater.core.verdict import AttackClass, Finding, Severity
from breakwater.log import JsonFormatter


def test_error_body_shape() -> None:
    finding = Finding(
        detector="leak_secrets",
        attack_class=AttackClass.A3,
        severity=Severity.CRITICAL,
        score=1.0,
        reason="API key format",
        rule_id="sec-001",
        span=(3, 20),
        layer=1,
    )
    body = error_body("gateway_blocked", "data_leak", "Blocked", "req-1", [finding])
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"type", "code", "message", "request_id", "findings"}
    assert error["findings"][0]["span"] == [3, 20]
    assert error["findings"][0]["rule_id"] == "sec-001"


def test_json_formatter_includes_extras() -> None:
    record = logging.makeLogRecord(
        {"name": "breakwater", "levelname": "INFO", "msg": "hi", "request_id": "r1", "risk": 0.5}
    )
    entry = json.loads(JsonFormatter().format(record))
    assert entry["msg"] == "hi"
    assert entry["request_id"] == "r1"
    assert entry["risk"] == 0.5
    assert "ts" in entry
