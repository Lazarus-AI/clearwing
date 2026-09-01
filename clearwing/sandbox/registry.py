"""Singleton registry that tracks active sandbox containers for leak prevention.

The registry uses a WeakSet so that containers which are properly stopped and
dereferenced don't prevent garbage collection.  An atexit handler calls
``_cleanup_all`` as a last-resort safety net on interpreter shutdown.
"""

from __future__ import annotations

import atexit
import logging
import threading
import weakref

logger = logging.getLogger(__name__)


class ContainerRegistry:
    """Process-wide registry of live sandbox instances."""

    _instance: ContainerRegistry | None = None
    _init_lock = threading.Lock()

    @classmethod
    def get(cls) -> ContainerRegistry:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
                    atexit.register(cls._instance._cleanup_all)
        return cls._instance

    def __init__(self) -> None:
        self._containers: weakref.WeakSet = weakref.WeakSet()
        self._lock = threading.Lock()

    def register(self, container: object) -> None:
        with self._lock:
            self._containers.add(container)

    def unregister(self, container: object) -> None:
        with self._lock:
            self._containers.discard(container)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._containers)

    def _cleanup_all(self) -> None:
        with self._lock:
            containers = list(self._containers)
        for c in containers:
            try:
                c.stop()
            except Exception:
                logger.debug("Failed to cleanup container", exc_info=True)
