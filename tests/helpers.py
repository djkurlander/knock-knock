"""Shared test helpers (importable by both conftest.py and test modules)."""
import json
import queue
import time


def read_knock(q, proto, timeout=5):
    """Drain the stdout queue until a KNOCK for proto appears."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            line = q.get(timeout=max(0.05, remaining))
        except queue.Empty:
            break
        try:
            data = json.loads(line)
            if data.get('type') == 'KNOCK' and data.get('proto') == proto:
                return data
        except (json.JSONDecodeError, AttributeError):
            pass
    raise AssertionError(f"No KNOCK for proto={proto!r} within {timeout}s")
