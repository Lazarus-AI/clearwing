"""Provider failure classification shared by LLM clients and resumable jobs."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


class ProviderExhaustedError(BaseException):
    """A provider rejected work because its account quota is exhausted.

    This is deliberately distinct from authentication and authorization
    failures.  Callers may safely stop scheduling new work and resume later
    after credentials or quota have changed.
    Ordinary fallback handlers intentionally do not catch this run-wide stop.
    Sourcehunt orchestration catches it only at boundaries where outstanding
    tasks can be cancelled and a resumable result can be returned.
    """


def _exception_text(exc: BaseException) -> str:
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        current = current.__cause__ or current.__context__
    return " ".join(parts).lower()


def is_provider_exhausted_error(exc: BaseException) -> bool:
    """Return whether *exc* is a terminal provider quota rejection.

    Kimi Code reports billing-cycle exhaustion as HTTP 403 with the structured
    error type ``access_terminated_error``.  Requiring both the structured type
    and quota-specific language keeps ordinary 401/403 auth failures out of
    this category.
    """

    if isinstance(exc, ProviderExhaustedError):
        return True
    text = _exception_text(exc)
    status_codes: set[int] = set()
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        try:
            status_codes.add(int(current.status_code))  # type: ignore[attr-defined]
        except (AttributeError, TypeError, ValueError):
            pass
        response = getattr(current, "response", None)
        try:
            status_codes.add(int(response.status_code))  # type: ignore[union-attr]
        except (AttributeError, TypeError, ValueError):
            pass
        current = current.__cause__ or current.__context__
    has_http_403 = any(
        marker in text
        for marker in (
            "http 403",
            "error code: 403",
            "status code 403",
            "status=403",
            "status: 403",
        )
    ) or 403 in status_codes
    has_kimi_type = "access_terminated_error" in text
    has_quota_message = any(
        marker in text
        for marker in (
            "usage limit",
            "billing cycle",
            "quota exhausted",
            "quota exceeded",
        )
    )
    return has_http_403 and has_kimi_type and has_quota_message


@dataclass
class ProviderExhaustionState:
    """Run-shared stop signal used by all bound LLM client views."""

    _event: threading.Event = field(default_factory=threading.Event)
    _message: str = "Provider quota exhausted"
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def exhausted(self) -> bool:
        return self._event.is_set()

    def mark(self, exc: BaseException) -> ProviderExhaustedError:
        with self._lock:
            if not self._event.is_set():
                self._message = str(exc) or self._message
                self._event.set()
        return ProviderExhaustedError(self._message)

    def raise_if_exhausted(self) -> None:
        if self._event.is_set():
            raise ProviderExhaustedError(self._message)
