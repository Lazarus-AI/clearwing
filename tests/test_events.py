"""Tests for the EventBus pub/sub system."""

import threading

from vulnexploit.core.events import EventBus, EventType


def _reset_bus():
    """Reset the EventBus singleton for test isolation."""
    EventBus._instance = None


class TestEventType:
    def test_all_event_types_exist(self):
        expected = {
            "STATE_CHANGED", "MESSAGE", "TOOL_START", "TOOL_RESULT",
            "FLAG_FOUND", "APPROVAL_NEEDED", "COST_UPDATE", "ERROR",
            "USER_INPUT", "USER_COMMAND",
        }
        actual = {e.name for e in EventType}
        assert expected == actual

    def test_event_type_values(self):
        assert EventType.MESSAGE.value == "message"
        assert EventType.FLAG_FOUND.value == "flag_found"


class TestEventBus:
    def setup_method(self):
        _reset_bus()

    def teardown_method(self):
        _reset_bus()

    def test_singleton(self):
        bus1 = EventBus()
        bus2 = EventBus()
        assert bus1 is bus2

    def test_subscribe_and_emit(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.MESSAGE, lambda data: received.append(data))
        bus.emit(EventType.MESSAGE, {"content": "hello"})
        assert len(received) == 1
        assert received[0]["content"] == "hello"

    def test_unsubscribe(self):
        bus = EventBus()
        received = []
        handler = lambda data: received.append(data)
        bus.subscribe(EventType.MESSAGE, handler)
        bus.unsubscribe(EventType.MESSAGE, handler)
        bus.emit(EventType.MESSAGE, "should not arrive")
        assert len(received) == 0

    def test_unsubscribe_absent_handler_is_noop(self):
        bus = EventBus()
        bus.unsubscribe(EventType.MESSAGE, lambda x: None)  # should not raise

    def test_handler_isolation(self):
        """One handler crashing should not prevent other handlers from running."""
        bus = EventBus()
        received = []

        def bad_handler(data):
            raise RuntimeError("boom")

        def good_handler(data):
            received.append(data)

        bus.subscribe(EventType.ERROR, bad_handler)
        bus.subscribe(EventType.ERROR, good_handler)
        bus.emit(EventType.ERROR, "test")
        assert received == ["test"]

    def test_no_duplicate_subscriptions(self):
        bus = EventBus()
        received = []
        handler = lambda data: received.append(data)
        bus.subscribe(EventType.MESSAGE, handler)
        bus.subscribe(EventType.MESSAGE, handler)
        bus.emit(EventType.MESSAGE, "once")
        assert len(received) == 1

    def test_emit_message_convenience(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.MESSAGE, lambda data: received.append(data))
        bus.emit_message("hello", "info")
        assert received[0]["content"] == "hello"
        assert received[0]["type"] == "info"

    def test_emit_tool_start(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TOOL_START, lambda data: received.append(data))
        bus.emit_tool("nmap", "start", {"target": "10.0.0.1"})
        assert received[0]["tool"] == "nmap"
        assert received[0]["phase"] == "start"

    def test_emit_tool_result(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TOOL_RESULT, lambda data: received.append(data))
        bus.emit_tool("nmap", "result", {"ports": [22, 80]})
        assert received[0]["tool"] == "nmap"

    def test_emit_flag(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.FLAG_FOUND, lambda data: received.append(data))
        bus.emit_flag("flag{test123}", "tool output")
        assert received[0]["flag"] == "flag{test123}"
        assert received[0]["context"] == "tool output"

    def test_emit_cost(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.COST_UPDATE, lambda data: received.append(data))
        bus.emit_cost(1000, 0.05)
        assert received[0]["tokens"] == 1000
        assert received[0]["cost_usd"] == 0.05

    def test_thread_safety(self):
        """Concurrent subscribes and emits should not crash."""
        bus = EventBus()
        results = []

        def worker(i):
            handler = lambda data: results.append((i, data))
            bus.subscribe(EventType.MESSAGE, handler)
            bus.emit(EventType.MESSAGE, i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All emits should have occurred without error
        assert len(results) > 0

    def test_different_event_types_isolated(self):
        bus = EventBus()
        messages = []
        errors = []
        bus.subscribe(EventType.MESSAGE, lambda d: messages.append(d))
        bus.subscribe(EventType.ERROR, lambda d: errors.append(d))
        bus.emit(EventType.MESSAGE, "msg")
        bus.emit(EventType.ERROR, "err")
        assert messages == ["msg"]
        assert errors == ["err"]
