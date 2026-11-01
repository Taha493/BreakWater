"""The error format used by every non-2xx response (spec section 5)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from breakwater.core.verdict import Finding

log = logging.getLogger("breakwater")

REQUEST_ID_HEADER = "X-Gateway-Request-Id"


class GatewayError(Exception):
    def __init__(
        self,
        status_code: int,
        type_: str,
        code: str,
        message: str,
        findings: list[Finding] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.type = type_
        self.code = code
        self.message = message
        self.findings = findings or []
        self.headers = headers or {}


def request_id_of(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def error_body(
    type_: str, code: str, message: str, request_id: str, findings: list[Finding] | None = None
) -> dict[str, Any]:
    return {
        "error": {
            "type": type_,
            "code": code,
            "message": message,
            "request_id": request_id,
            "findings": [f.model_dump(mode="json") for f in findings or []],
        }
    }


def error_response(
    status_code: int,
    type_: str,
    code: str,
    message: str,
    request_id: str,
    findings: list[Finding] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        error_body(type_, code, message, request_id, findings),
        status_code=status_code,
        headers={REQUEST_ID_HEADER: request_id, **(headers or {})},
    )


_HTTP_TYPES = {401: "unauthorized", 403: "unauthorized", 429: "rate_limited"}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(GatewayError)
    async def _gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        return error_response(
            exc.status_code,
            exc.type,
            exc.code,
            exc.message,
            request_id_of(request),
            exc.findings,
            exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field locations only: validation messages can echo the submitted values.
        fields = sorted({".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()})
        message = "Invalid request body" + (f" ({', '.join(fields)})" if fields else "")
        return error_response(
            422, "invalid_request", "validation_error", message, request_id_of(request)
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        type_ = _HTTP_TYPES.get(exc.status_code, "invalid_request")
        return error_response(
            exc.status_code,
            type_,
            f"http_{exc.status_code}",
            str(exc.detail),
            request_id_of(request),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"request_id": request_id_of(request)})
        return error_response(
            500,
            "internal_error",
            "internal_error",
            "Internal gateway error",
            request_id_of(request),
        )
