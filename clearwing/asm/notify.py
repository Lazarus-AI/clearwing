"""Outbound notifications for new assets and findings.

The event bus already carries `ASSET_DISCOVERED` (emitted by the ASM monitor)
and `FINDING_RECORDED` (emitted by the hunt pipeline). This subscribes to both
and pushes a short message to a Slack incoming-webhook and/or a generic webhook
— the outbound half Clearwing didn't have. Modeled on the sourcehunt CLI's
`_on_finding` subscribe/unsubscribe pattern; best-effort like `github_checks`
(a failed POST is logged, never raised, so notifications can't break a scan).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from clearwing.core.events import EventBus, EventType

logger = logging.getLogger(__name__)


class Notifier:
    """Pushes new-asset / new-finding events to Slack and/or a webhook."""

    def __init__(self, slack_url: str = "", webhook_url: str = "", timeout: int = 10):
        self.slack_url = slack_url
        self.webhook_url = webhook_url
        self.timeout = timeout
        self._subscribed = False

    @property
    def enabled(self) -> bool:
        return bool(self.slack_url or self.webhook_url)

    @classmethod
    def from_config(cls, asm_config: dict[str, Any]) -> Notifier:
        """Build from the `asm` config section (env var wins over the literal)."""
        section = asm_config or {}
        slack_env = section.get("slack_webhook_env", "CLEARWING_SLACK_WEBHOOK")
        slack = os.environ.get(slack_env, "") or section.get("slack_webhook_url", "")
        webhook = section.get("webhook_url", "")
        return cls(slack_url=slack, webhook_url=webhook)

    def subscribe(self) -> None:
        if self._subscribed or not self.enabled:
            return
        bus = EventBus()
        bus.subscribe(EventType.ASSET_DISCOVERED, self._on_asset)
        bus.subscribe(EventType.FINDING_RECORDED, self._on_finding)
        self._subscribed = True

    def unsubscribe(self) -> None:
        if not self._subscribed:
            return
        bus = EventBus()
        bus.unsubscribe(EventType.ASSET_DISCOVERED, self._on_asset)
        bus.unsubscribe(EventType.FINDING_RECORDED, self._on_finding)
        self._subscribed = False

    def __enter__(self) -> Notifier:
        self.subscribe()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.unsubscribe()

    # -- event handlers -------------------------------------------------

    def _on_asset(self, payload: Any) -> None:
        scope = getattr(payload, "scope", "?")
        atype = getattr(payload, "asset_type", "asset")
        value = getattr(payload, "value", "")
        source = getattr(payload, "source", "")
        self.notify(f":satellite: New {atype} in *{scope}*: `{value}`" + (f" (via {source})" if source else ""))

    def _on_finding(self, data: Any) -> None:
        if not isinstance(data, dict):
            return
        severity = data.get("severity", "info")
        ftype = data.get("finding_type", "finding")
        where = data.get("file") or data.get("hunter_target") or ""
        self.notify(f":rotating_light: New *{severity}* {ftype}" + (f" in `{where}`" if where else ""))

    # -- transport ------------------------------------------------------

    def notify(self, text: str) -> None:
        """Send *text* to every configured sink. Never raises."""
        if self.slack_url:
            self._post(self.slack_url, {"text": text})
        if self.webhook_url:
            self._post(self.webhook_url, {"text": text, "source": "clearwing-asm"})

    def _post(self, url: str, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):  # noqa: S310
                pass
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.debug("notification POST to %s failed: %s", url, exc)


__all__ = ["Notifier"]
