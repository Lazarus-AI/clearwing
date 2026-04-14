"""Session persistence for Clearwing penetration testing sessions."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SessionInfo:
    """Represents a single Clearwing session."""

    session_id: str
    target: str
    model: str
    status: str  # running, paused, completed, error
    start_time: datetime
    end_time: datetime | None = None
    flags_found: list[dict] = field(default_factory=list)  # {flag, context, timestamp}
    cost_usd: float = 0.0
    token_count: int = 0
    open_ports: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    exploit_results: list[dict] = field(default_factory=list)
    os_info: str | None = None
    kali_container_id: str | None = None
    custom_tool_names: list[str] = field(default_factory=list)
    langgraph_thread_id: str = ""


class _DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def _datetime_decoder(dct: dict) -> dict:
    """Decode ISO-format datetime strings back to datetime objects."""
    for key in ("start_time", "end_time"):
        if key in dct and dct[key] is not None:
            try:
                dct[key] = datetime.fromisoformat(dct[key])
            except (ValueError, TypeError):
                pass
    return dct


class SessionStore:
    """Persists Clearwing sessions as JSON files on disk."""

    BASE_DIR: Path = Path("~/.clearwing/sessions").expanduser()

    def __init__(self) -> None:
        self.BASE_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, target: str, model: str) -> SessionInfo:
        """Create a new session and persist it to disk."""
        session = SessionInfo(
            session_id=uuid.uuid4().hex[:8],
            target=target,
            model=model,
            status="running",
            start_time=datetime.now(tz=timezone.utc),
            langgraph_thread_id=uuid.uuid4().hex,
        )
        self.save(session)
        return session

    def save(self, session: SessionInfo) -> None:
        """Serialize *session* to JSON and write to BASE_DIR/{session_id}.json."""
        path = self.BASE_DIR / f"{session.session_id}.json"
        data = asdict(session)
        path.write_text(
            json.dumps(data, cls=_DateTimeEncoder, indent=2),
            encoding="utf-8",
        )

    def load(self, session_id: str) -> SessionInfo:
        """Load a session from disk by its ID."""
        path = self.BASE_DIR / f"{session_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Session file not found: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw = _datetime_decoder(raw)
        return SessionInfo(**raw)

    def list_sessions(self, target: str | None = None) -> list[SessionInfo]:
        """Return all persisted sessions, optionally filtered by *target*."""
        sessions: list[SessionInfo] = []
        for path in sorted(self.BASE_DIR.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                raw = _datetime_decoder(raw)
                session = SessionInfo(**raw)
                if target is None or session.target == target:
                    sessions.append(session)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
        return sessions

    def get_latest(self, target: str | None = None) -> SessionInfo | None:
        """Return the most recent session (by start_time), optionally for *target*."""
        sessions = self.list_sessions(target=target)
        if not sessions:
            return None
        return max(sessions, key=lambda s: s.start_time)

    def delete(self, session_id: str) -> None:
        """Remove the session file for *session_id*."""
        path = self.BASE_DIR / f"{session_id}.json"
        if path.exists():
            path.unlink()
