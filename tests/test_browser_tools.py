"""Tests for browser tools module (unit tests, no real browser)."""

from clearwing.agent.tools.recon.browser_tools import (
    _browser_state,
    browser_close,
    browser_list_tabs,
    get_browser_tools,
)


class TestGetBrowserTools:
    def test_returns_list(self):
        tools = get_browser_tools()
        assert isinstance(tools, list)
        assert len(tools) == 11

    def test_tool_names(self):
        tools = get_browser_tools()
        names = [t.name for t in tools]
        expected = [
            "browser_navigate",
            "browser_get_content",
            "browser_get_html",
            "browser_fill",
            "browser_click",
            "browser_get_cookies",
            "browser_set_cookie",
            "browser_execute_js",
            "browser_screenshot",
            "browser_list_tabs",
            "browser_close",
        ]
        assert names == expected


class TestBrowserState:
    def test_initial_state(self):
        assert _browser_state["browser"] is None
        assert _browser_state["context"] is None
        assert isinstance(_browser_state["tabs"], dict)
        assert _browser_state["active_tab"] is None


class TestBrowserListTabs:
    def test_empty_tabs(self):
        result = browser_list_tabs.invoke({})
        assert result == []


class TestBrowserClose:
    def test_close_nonexistent_tab(self):
        result = browser_close.invoke({"tab_name": "nonexistent"})
        assert result["closed"] == "nonexistent"
        assert result["remaining_tabs"] == []

    def test_close_all_when_empty(self):
        result = browser_close.invoke({})
        assert result["closed"] == "all"
        assert result["remaining_tabs"] == []
