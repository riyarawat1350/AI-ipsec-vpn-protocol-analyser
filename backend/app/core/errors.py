"""Standard error envelope and exception handlers per SRS §9.1."""

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class AppException(Exception):
    """Base application exception mapped to the standard error envelope."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Any = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


AppError = AppException


class NotFoundError(AppException):
    def __init__(self, message: str = "Resource not found", details: Any = None):
        super().__init__(
            code="NOT_FOUND",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class UnauthorizedError(AppException):
    def __init__(self, message: str = "Invalid or missing bearer token", details: Any = None):
        super().__init__(
            code="UNAUTHORIZED",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class UnsupportedFileTypeError(AppException):
    def __init__(self, message: str = "File is not a valid pcap/pcapng capture", details: Any = None):
        super().__init__(
            code="UNSUPPORTED_FILE_TYPE",
            message=message,
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            details=details,
        )


class FileTooLargeError(AppException):
    def __init__(self, message: str = "Uploaded file exceeds maximum permitted size", details: Any = None):
        super().__init__(
            code="FILE_TOO_LARGE",
            message=message,
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            details=details,
        )


class AnalysisNotCompleteError(AppException):
    def __init__(self, message: str = "Analysis is still running or has not completed", details: Any = None):
        super().__init__(
            code="ANALYSIS_NOT_COMPLETE",
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


def make_error_envelope(code: str, message: str, details: Any = None) -> dict[str, Any]:
    """Format payload according to SRS §9.1."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


def register_exception_handlers(app: FastAPI) -> None:
    """Register uniform exception handlers returning the standard error envelope."""

    @app.exception_handler(AppException)
    async def app_exception_handler(_request: Request, exc: AppException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=make_error_envelope(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Avoid leaking raw server paths or sensitive details; format errors cleanly
        clean_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(x) for x in err.get("loc", []))
            clean_errors.append({"field": loc, "issue": err.get("msg", "Invalid value")})

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=make_error_envelope(
                code="VALIDATION_ERROR",
                message="Request validation failed",
                details={"errors": clean_errors},
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code_map = {
            status.HTTP_401_UNAUTHORIZED: "UNAUTHORIZED",
            status.HTTP_403_FORBIDDEN: "FORBIDDEN",
            status.HTTP_404_NOT_FOUND: "NOT_FOUND",
            status.HTTP_405_METHOD_NOT_ALLOWED: "METHOD_NOT_ALLOWED",
            status.HTTP_409_CONFLICT: "ANALYSIS_NOT_COMPLETE",
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE: "FILE_TOO_LARGE",
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: "UNSUPPORTED_FILE_TYPE",
            status.HTTP_429_TOO_MANY_REQUESTS: "RATE_LIMITED",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "INTERNAL_ERROR",
        }
        code = code_map.get(exc.status_code, "ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content=make_error_envelope(code, str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
        # Never leak stack traces to client (SRS §8.2 / SPEC §7)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=make_error_envelope("INTERNAL_ERROR", "An unexpected internal server error occurred"),
        )
