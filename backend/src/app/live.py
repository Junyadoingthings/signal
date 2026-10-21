"""In-process pub/sub for the live WebSocket stream.

Publishers run on worker threads (ingest, detection); subscribers are asyncio tasks.
Messages cross over with call_soon_threadsafe. Slow clients get messages dropped rather
than growing memory without bound.
"""

import asyncio
import contextlib
import threading
from typing import Any

QUEUE_SIZE = 500


class Hub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: set[tuple[asyncio.Queue[dict[str, Any]], asyncio.AbstractEventLoop]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(QUEUE_SIZE)
        with self._lock:
            self._subs.add((q, asyncio.get_running_loop()))
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subs = {(sq, lp) for sq, lp in self._subs if sq is not q}

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, message: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for q, loop in subs:
            with contextlib.suppress(RuntimeError):  # loop already closed
                loop.call_soon_threadsafe(_offer, q, message)


def _offer(q: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
    with contextlib.suppress(asyncio.QueueFull):
        q.put_nowait(message)


hub = Hub()
