"""Run-scoped LLM spend accounting and hard budget enforcement.

The observability ``CostTracker`` is intentionally process-global and records
cost only after a response arrives.  ``SpendLedger`` is different: it belongs
to one run, reserves the maximum cost of a call before dispatch, and settles
that reservation from provider usage afterwards.  A single thread lock makes
the reserve/check operation atomic across asyncio tasks and worker threads.
"""

from __future__ import annotations

import json
import math
import os
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clearwing.observability.telemetry import CostTracker


class BudgetExceeded(RuntimeError):
    """Raised before dispatch when another LLM call cannot fit the budget."""


class BudgetConfigurationError(ValueError):
    """Raised when a requested hard cap cannot be enforced safely."""


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """USD rates per one million tokens."""

    input_per_million: float
    output_per_million: float
    cached_input_per_million: float
    source: str


@dataclass(slots=True)
class BudgetReservation:
    """Maximum authorized cost for one physical provider request."""

    call_id: str
    model: str
    provider: str
    stage: str
    metadata: dict[str, Any]
    reserved_usd: float
    input_token_upper_bound: int
    max_output_tokens: int | None
    pricing: ModelPricing
    created_at: str
    active: bool = True


_SPEND_METADATA: ContextVar[dict[str, Any] | None] = ContextVar(
    "clearwing_spend_metadata", default=None
)


@contextmanager
def spend_metadata(**metadata: Any) -> Iterator[None]:
    """Attach stage-local fields (for example tier/band) to nested LLM calls."""

    merged = dict(_SPEND_METADATA.get() or {})
    merged.update({key: value for key, value in metadata.items() if value is not None})
    token = _SPEND_METADATA.set(merged)
    try:
        yield
    finally:
        _SPEND_METADATA.reset(token)


def current_spend_metadata() -> dict[str, Any]:
    """Return a copy of the metadata inherited by the current async context."""

    return dict(_SPEND_METADATA.get() or {})


class SpendLedger:
    """Concurrency-safe, progressively persisted spend ledger for one run."""

    DEFAULT_MAX_OUTPUT_TOKENS = 4096
    _EPSILON = 1e-9

    def __init__(
        self,
        *,
        limit_usd: float,
        session_id: str,
        repo_url: str,
        output_dir: str | Path,
        input_price_per_million: float | None = None,
        output_price_per_million: float | None = None,
        default_max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        manifest_filename: str = "manifest.json",
    ) -> None:
        if not math.isfinite(limit_usd) or limit_usd < 0:
            raise BudgetConfigurationError("LLM budget must be a finite value >= 0")
        if (input_price_per_million is None) != (output_price_per_million is None):
            raise BudgetConfigurationError(
                "input and output token prices must be provided together"
            )
        for name, value in (
            ("input token price", input_price_per_million),
            ("output token price", output_price_per_million),
        ):
            if value is not None and (not math.isfinite(value) or value < 0):
                raise BudgetConfigurationError(f"{name} must be a finite value >= 0")
        if default_max_output_tokens < 1:
            raise BudgetConfigurationError("default_max_output_tokens must be >= 1")
        if (
            not manifest_filename
            or Path(manifest_filename).name != manifest_filename
            or manifest_filename in {".", ".."}
        ):
            raise BudgetConfigurationError(
                "manifest_filename must be a safe session-local filename"
            )

        self.limit_usd = float(limit_usd)
        self.session_id = session_id
        self.repo_url = repo_url
        self.default_max_output_tokens = int(default_max_output_tokens)
        self._pricing_override = (
            ModelPricing(
                input_per_million=float(input_price_per_million),
                output_per_million=float(output_price_per_million),
                cached_input_per_million=float(input_price_per_million),
                source="operator_override",
            )
            if input_price_per_million is not None
            and output_price_per_million is not None
            else None
        )

        self._lock = threading.RLock()
        self._spent_usd = 0.0
        self._reserved_usd = 0.0
        self._input_tokens = 0
        self._output_tokens = 0
        self._cached_input_tokens = 0
        self._records: list[dict[str, Any]] = []
        self._exhausted = False
        self._status = "running"
        self._finalized = False

        session_dir = Path(output_dir) / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = session_dir / "spend-ledger.jsonl"
        self.manifest_path = session_dir / manifest_filename
        with self._lock:
            self._persist_event_locked(
                {
                    "event": "run_started",
                    "session_id": self.session_id,
                    "budget_usd": self.limit_usd,
                    "timestamp": self._timestamp(),
                }
            )
            self._persist_snapshot_locked()

    @property
    def enforcing(self) -> bool:
        """Whether this run has a finite non-zero dollar cap."""

        return self.limit_usd > 0

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._exhausted

    @property
    def finalized(self) -> bool:
        with self._lock:
            return self._finalized

    @property
    def spent_usd(self) -> float:
        with self._lock:
            return self._spent_usd

    @property
    def remaining_usd(self) -> float | None:
        with self._lock:
            if not self.enforcing:
                return None
            return max(0.0, self.limit_usd - self._spent_usd - self._reserved_usd)

    def validate_model(
        self,
        *,
        model: str,
        provider: str,
        supports_output_limit: bool,
    ) -> ModelPricing:
        """Fail before spending when strict pricing/capping is unavailable."""

        pricing = self._resolve_pricing(
            model,
            provider=provider,
            strict=self.enforcing,
        )
        if (
            self.enforcing
            and pricing.output_per_million > 0
            and not supports_output_limit
        ):
            raise BudgetConfigurationError(
                f"--budget cannot be enforced for provider {provider!r}: "
                "it does not accept an output-token ceiling"
            )
        return pricing

    def reserve_call(
        self,
        *,
        model: str,
        provider: str,
        stage: str,
        input_token_upper_bound: int,
        requested_max_output_tokens: int | None,
        supports_output_limit: bool,
        metadata: dict[str, Any] | None = None,
    ) -> BudgetReservation:
        """Atomically reserve the worst-case price and return the output cap."""

        pricing = self.validate_model(
            model=model,
            provider=provider,
            supports_output_limit=supports_output_limit,
        )
        input_token_upper_bound = max(0, int(input_token_upper_bound))
        metadata = dict(metadata or {})

        with self._lock:
            if self._finalized:
                raise RuntimeError("cannot reserve an LLM call on a finalized spend ledger")

            effective_max_tokens = requested_max_output_tokens
            reserved_usd = 0.0
            if self.enforcing:
                requested = (
                    self.default_max_output_tokens
                    if requested_max_output_tokens is None
                    else max(1, int(requested_max_output_tokens))
                )
                available = max(
                    0.0,
                    self.limit_usd - self._spent_usd - self._reserved_usd,
                )
                input_cost = (
                    input_token_upper_bound * pricing.input_per_million / 1_000_000
                )
                if input_cost > available + self._EPSILON:
                    self._mark_exhausted_locked(
                        stage=stage,
                        model=model,
                        reason="input_cost_exceeds_remaining_budget",
                    )
                    raise BudgetExceeded(
                        f"LLM budget exhausted before {stage}: "
                        f"${available:.6f} remains, request input may cost ${input_cost:.6f}"
                    )

                if pricing.output_per_million > 0:
                    affordable_output = math.floor(
                        max(0.0, available - input_cost)
                        * 1_000_000
                        / pricing.output_per_million
                    )
                    effective_max_tokens = min(requested, affordable_output)
                    if effective_max_tokens < 1:
                        self._mark_exhausted_locked(
                            stage=stage,
                            model=model,
                            reason="no_affordable_output_tokens",
                        )
                        raise BudgetExceeded(
                            f"LLM budget exhausted before {stage}: no output token fits "
                            f"within the remaining ${available:.6f}"
                        )
                else:
                    effective_max_tokens = requested

                reserved_usd = input_cost + (
                    (effective_max_tokens or 0)
                    * pricing.output_per_million
                    / 1_000_000
                )
                if reserved_usd > available + self._EPSILON:
                    self._mark_exhausted_locked(
                        stage=stage,
                        model=model,
                        reason="reservation_exceeds_remaining_budget",
                    )
                    raise BudgetExceeded(
                        f"LLM budget exhausted before {stage}: call reservation "
                        f"${reserved_usd:.6f} exceeds remaining ${available:.6f}"
                    )

            reservation = BudgetReservation(
                call_id=uuid.uuid4().hex,
                model=model,
                provider=provider,
                stage=stage,
                metadata=metadata,
                reserved_usd=reserved_usd,
                input_token_upper_bound=input_token_upper_bound,
                max_output_tokens=effective_max_tokens,
                pricing=pricing,
                created_at=self._timestamp(),
            )
            self._reserved_usd += reserved_usd
            self._persist_event_locked(
                {
                    "event": "call_reserved",
                    "call_id": reservation.call_id,
                    "timestamp": reservation.created_at,
                    "stage": stage,
                    "model": model,
                    "provider": provider,
                    "reserved_usd": reserved_usd,
                    "input_token_upper_bound": input_token_upper_bound,
                    "max_output_tokens": effective_max_tokens,
                    "metadata": metadata,
                }
            )
            self._persist_snapshot_locked()
            return reservation

    def settle_call(
        self,
        reservation: BudgetReservation,
        *,
        input_tokens: int | None,
        output_tokens: int | None,
        cached_input_tokens: int | None = 0,
        provider_cost_usd: float | None = None,
    ) -> float:
        """Replace a reservation with provider usage and return recorded cost."""

        with self._lock:
            self._require_active_locked(reservation)
            input_count = max(0, int(input_tokens or 0))
            output_count = max(0, int(output_tokens or 0))
            cached_count = min(input_count, max(0, int(cached_input_tokens or 0)))
            usage_missing = input_tokens is None and output_tokens is None

            provider_cost = (
                float(provider_cost_usd) if provider_cost_usd is not None else None
            )
            if provider_cost is not None and math.isfinite(provider_cost) and provider_cost >= 0:
                actual_cost = provider_cost
                cost_source = "provider"
            elif usage_missing and self.enforcing:
                # A provider response without usage cannot prove a lower cost.
                # Charge the full reservation so later calls remain safe.
                actual_cost = reservation.reserved_usd
                cost_source = "reservation"
            else:
                uncached_count = max(0, input_count - cached_count)
                actual_cost = (
                    uncached_count * reservation.pricing.input_per_million
                    + cached_count * reservation.pricing.cached_input_per_million
                    + output_count * reservation.pricing.output_per_million
                ) / 1_000_000
                cost_source = reservation.pricing.source

            status = "usage_missing" if usage_missing else "succeeded"
            self._finish_reservation_locked(
                reservation,
                charged_usd=actual_cost,
                input_tokens=input_count,
                output_tokens=output_count,
                cached_input_tokens=cached_count,
                status=status,
                cost_source=cost_source,
            )
            return actual_cost

    def fail_call(
        self,
        reservation: BudgetReservation,
        *,
        error: str,
        definitely_unbilled: bool = False,
    ) -> None:
        """Close a failed call, conservatively charging ambiguous failures."""

        with self._lock:
            if not reservation.active:
                return
            charged = 0.0 if definitely_unbilled or not self.enforcing else reservation.reserved_usd
            status = "rejected" if definitely_unbilled else "ambiguous_failure"
            self._finish_reservation_locked(
                reservation,
                charged_usd=charged,
                input_tokens=0,
                output_tokens=0,
                cached_input_tokens=0,
                status=status,
                cost_source="none" if definitely_unbilled else "reservation",
                error=error,
            )

    def release_call(self, reservation: BudgetReservation, *, reason: str) -> None:
        """Release a reservation that failed before any provider dispatch."""

        with self._lock:
            if not reservation.active:
                return
            self._finish_reservation_locked(
                reservation,
                charged_usd=0.0,
                input_tokens=0,
                output_tokens=0,
                cached_input_tokens=0,
                status="not_dispatched",
                cost_source="none",
                error=reason,
            )

    def spent_by(self, field_name: str, **filters: Any) -> dict[str, float]:
        """Aggregate settled spend by a metadata field, optionally filtering."""

        totals: dict[str, float] = {}
        with self._lock:
            for record in self._records:
                metadata = record.get("metadata", {})
                if any(
                    (record.get(key) if key in record else metadata.get(key)) != value
                    for key, value in filters.items()
                ):
                    continue
                value = record.get(field_name, metadata.get(field_name))
                if value is None:
                    continue
                label = str(value)
                totals[label] = totals.get(label, 0.0) + float(record["cost_usd"])
        return totals

    def snapshot(self) -> dict[str, Any]:
        """Return a serializable point-in-time summary."""

        with self._lock:
            return self._snapshot_locked()

    def finalize(self, status: str | None = None) -> dict[str, Any]:
        """Mark the run complete and persist its final ledger snapshot."""

        with self._lock:
            if status is None:
                status = "budget_exhausted" if self._exhausted else "completed"
            self._status = status
            self._finalized = True
            self._persist_event_locked(
                {
                    "event": "run_finished",
                    "timestamp": self._timestamp(),
                    "status": status,
                    "spent_usd": self._spent_usd,
                    "reserved_usd": self._reserved_usd,
                }
            )
            self._persist_snapshot_locked()
            return self._snapshot_locked()

    def _finish_reservation_locked(
        self,
        reservation: BudgetReservation,
        *,
        charged_usd: float,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int,
        status: str,
        cost_source: str,
        error: str | None = None,
    ) -> None:
        self._require_active_locked(reservation)
        reservation.active = False
        self._reserved_usd = max(0.0, self._reserved_usd - reservation.reserved_usd)
        self._spent_usd += max(0.0, charged_usd)
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        self._cached_input_tokens += cached_input_tokens
        if self.enforcing and self._spent_usd > self.limit_usd + self._EPSILON:
            # This indicates provider usage exceeded the conservative preflight
            # bound.  Never hide it by clamping the recorded cost.
            self._exhausted = True

        record: dict[str, Any] = {
            "event": "call_settled",
            "call_id": reservation.call_id,
            "timestamp": self._timestamp(),
            "stage": reservation.stage,
            "model": reservation.model,
            "provider": reservation.provider,
            "status": status,
            "reserved_usd": reservation.reserved_usd,
            "cost_usd": max(0.0, charged_usd),
            "cost_source": cost_source,
            "input_tokens": input_tokens,
            "cached_input_tokens": cached_input_tokens,
            "output_tokens": output_tokens,
            "metadata": dict(reservation.metadata),
        }
        if error:
            record["error"] = error[:1000]
        self._records.append(record)
        self._persist_event_locked(record)
        self._persist_snapshot_locked()

    def _mark_exhausted_locked(self, *, stage: str, model: str, reason: str) -> None:
        self._exhausted = True
        self._status = "budget_exhausted"
        self._persist_event_locked(
            {
                "event": "budget_exhausted",
                "timestamp": self._timestamp(),
                "stage": stage,
                "model": model,
                "reason": reason,
                "spent_usd": self._spent_usd,
                "reserved_usd": self._reserved_usd,
            }
        )
        self._persist_snapshot_locked()

    @staticmethod
    def _require_active_locked(reservation: BudgetReservation) -> None:
        if not reservation.active:
            raise RuntimeError(f"budget reservation {reservation.call_id} is already closed")

    def _snapshot_locked(self) -> dict[str, Any]:
        remaining = (
            max(0.0, self.limit_usd - self._spent_usd - self._reserved_usd)
            if self.enforcing
            else None
        )
        return {
            "session_id": self.session_id,
            "repo_url": self.repo_url,
            "status": self._status,
            "complete": self._finalized and self._status == "completed",
            "budget_usd": self.limit_usd,
            "total_spent": self._spent_usd,
            "reserved_usd": self._reserved_usd,
            "remaining_usd": remaining,
            "input_tokens": self._input_tokens,
            "cached_input_tokens": self._cached_input_tokens,
            "output_tokens": self._output_tokens,
            "total_tokens": self._input_tokens + self._output_tokens,
            "call_count": len(self._records),
            "ledger_path": str(self.ledger_path),
            "spend_summary_path": str(self.manifest_path),
        }

    def _persist_snapshot_locked(self) -> None:
        snapshot = self._snapshot_locked()
        tmp_path = self.manifest_path.with_suffix(".json.tmp")
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, self.manifest_path)

    def _persist_event_locked(self, event: dict[str, Any]) -> None:
        with open(self.ledger_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _resolve_pricing(
        self,
        model: str,
        *,
        provider: str,
        strict: bool,
    ) -> ModelPricing:
        if self._pricing_override is not None:
            return self._pricing_override

        normalized = model.lower().strip()
        basename = normalized.rsplit("/", 1)[-1]
        pricing_table = CostTracker.PRICING
        matched_key: str | None = None
        for key in sorted(pricing_table, key=len, reverse=True):
            lower_key = key.lower()
            if (
                normalized == lower_key
                or basename == lower_key
                or normalized.startswith(lower_key + "-")
                or basename.startswith(lower_key + "-")
            ):
                matched_key = key
                break

        # Version aliases in provider catalogs often omit a dated suffix or
        # select a nearby point release with the same family pricing.
        if matched_key is None:
            family_aliases = (
                ("claude-sonnet-4", "claude-sonnet-4-6"),
                ("claude-opus-4", "claude-opus-4-6"),
                ("claude-haiku-4-5", "claude-haiku-4-5"),
                ("glm-5.2", "glm-5.2"),
            )
            for family, key in family_aliases:
                if family in normalized and key in pricing_table:
                    matched_key = key
                    break

        if (
            strict
            and matched_key is not None
            and matched_key.startswith("claude-")
            and provider not in {"anthropic", "anthropic_oauth"}
        ):
            raise BudgetConfigurationError(
                f"Built-in {matched_key!r} pricing is only valid for direct Anthropic "
                f"requests, not provider {provider!r}; provide explicit input/output "
                "prices to use --budget through a gateway"
            )

        if matched_key is None:
            if strict:
                raise BudgetConfigurationError(
                    f"No verified pricing is configured for model {model!r}; "
                    "provide explicit input/output prices to use --budget"
                )
            matched_key = "claude-sonnet-4-6"

        prices = pricing_table[matched_key]
        return ModelPricing(
            input_per_million=float(prices["input"]),
            output_per_million=float(prices["output"]),
            cached_input_per_million=float(
                prices.get("cached_input", prices["input"])
            ),
            source=f"pricing_table:{matched_key}",
        )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()


__all__ = [
    "BudgetConfigurationError",
    "BudgetExceeded",
    "BudgetReservation",
    "ModelPricing",
    "SpendLedger",
    "current_spend_metadata",
    "spend_metadata",
]
