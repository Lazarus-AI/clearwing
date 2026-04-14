"""Playwright-based browser automation tools for web application testing."""

from __future__ import annotations

from typing import Optional
from langchain_core.tools import tool
from langgraph.types import interrupt


# Module-level browser state
_browser_state = {
    "browser": None,
    "context": None,
    "tabs": {},  # name -> page
    "active_tab": None,
}


def _ensure_browser():
    """Lazily initialize the browser if not already running."""
    if _browser_state["browser"] is not None:
        return

    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    _browser_state["_pw"] = pw
    _browser_state["browser"] = pw.chromium.launch(headless=True)
    _browser_state["context"] = _browser_state["browser"].new_context(
        ignore_https_errors=True,
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Clearwing/1.0",
    )


def _get_page(tab_name: Optional[str] = None):
    """Get the active page, or create one if none exists."""
    _ensure_browser()
    name = tab_name or _browser_state.get("active_tab") or "default"
    if name not in _browser_state["tabs"]:
        page = _browser_state["context"].new_page()
        _browser_state["tabs"][name] = page
        _browser_state["active_tab"] = name
    return _browser_state["tabs"][name]


@tool
def browser_navigate(url: str, tab_name: str = "default") -> dict:
    """Navigate a browser tab to a URL. Creates the tab if it doesn't exist.

    Args:
        url: URL to navigate to.
        tab_name: Name for this browser tab (default: "default").

    Returns:
        Dict with keys: status, url, title, tab_name.
    """
    try:
        page = _get_page(tab_name)
        _browser_state["active_tab"] = tab_name
        response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
        status = response.status if response else 0
        return {
            "status": status,
            "url": page.url,
            "title": page.title(),
            "tab_name": tab_name,
        }
    except Exception as e:
        return {"status": 0, "url": url, "title": "", "tab_name": tab_name, "error": str(e)}


@tool
def browser_get_content(tab_name: str = "default", selector: str = "body") -> dict:
    """Get the text content of an element in the browser.

    Args:
        tab_name: Browser tab name.
        selector: CSS selector for the element (default: "body").

    Returns:
        Dict with keys: content, url, selector.
    """
    try:
        page = _get_page(tab_name)
        element = page.query_selector(selector)
        content = element.text_content() if element else ""
        # Truncate to prevent context overflow
        if len(content) > 5000:
            content = content[:5000] + "\n... (truncated)"
        return {"content": content, "url": page.url, "selector": selector}
    except Exception as e:
        return {"content": "", "url": "", "selector": selector, "error": str(e)}


@tool
def browser_get_html(tab_name: str = "default", selector: str = "html") -> dict:
    """Get the HTML source of an element in the browser.

    Args:
        tab_name: Browser tab name.
        selector: CSS selector for the element (default: "html").

    Returns:
        Dict with keys: html, url, selector.
    """
    try:
        page = _get_page(tab_name)
        element = page.query_selector(selector)
        html = element.inner_html() if element else ""
        if len(html) > 10000:
            html = html[:10000] + "\n... (truncated)"
        return {"html": html, "url": page.url, "selector": selector}
    except Exception as e:
        return {"html": "", "url": "", "selector": selector, "error": str(e)}


@tool
def browser_fill(selector: str, value: str, tab_name: str = "default") -> dict:
    """Fill an input field in the browser.

    Args:
        selector: CSS selector for the input element.
        value: Value to fill in.
        tab_name: Browser tab name.

    Returns:
        Dict with keys: success, selector, tab_name.
    """
    try:
        page = _get_page(tab_name)
        page.fill(selector, value)
        return {"success": True, "selector": selector, "tab_name": tab_name}
    except Exception as e:
        return {"success": False, "selector": selector, "tab_name": tab_name, "error": str(e)}


@tool
def browser_click(selector: str, tab_name: str = "default") -> dict:
    """Click an element in the browser.

    Args:
        selector: CSS selector for the element to click.
        tab_name: Browser tab name.

    Returns:
        Dict with keys: success, url (after click), title (after click), tab_name.
    """
    try:
        page = _get_page(tab_name)
        page.click(selector)
        page.wait_for_load_state("domcontentloaded", timeout=10000)
        return {
            "success": True,
            "url": page.url,
            "title": page.title(),
            "tab_name": tab_name,
        }
    except Exception as e:
        return {"success": False, "url": "", "title": "", "tab_name": tab_name, "error": str(e)}


@tool
def browser_get_cookies(tab_name: str = "default") -> list[dict]:
    """Get all cookies for the current browser context.

    Args:
        tab_name: Browser tab name (cookies are context-wide).

    Returns:
        List of cookie dicts with keys: name, value, domain, path, etc.
    """
    try:
        _ensure_browser()
        cookies = _browser_state["context"].cookies()
        return [
            {
                "name": c["name"],
                "value": c["value"],
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "None"),
            }
            for c in cookies
        ]
    except Exception as e:
        return [{"error": str(e)}]


@tool
def browser_set_cookie(name: str, value: str, domain: str, path: str = "/") -> dict:
    """Set a cookie in the browser context.

    Args:
        name: Cookie name.
        value: Cookie value.
        domain: Cookie domain.
        path: Cookie path (default: "/").

    Returns:
        Dict with keys: success, name, domain.
    """
    try:
        _ensure_browser()
        _browser_state["context"].add_cookies([{
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
        }])
        return {"success": True, "name": name, "domain": domain}
    except Exception as e:
        return {"success": False, "name": name, "domain": domain, "error": str(e)}


@tool
def browser_execute_js(code: str, tab_name: str = "default") -> dict:
    """Execute JavaScript in the browser page. REQUIRES HUMAN APPROVAL.

    Args:
        code: JavaScript code to execute.
        tab_name: Browser tab name.

    Returns:
        Dict with keys: result, tab_name.
    """
    approval = interrupt(f"Approve executing JavaScript in browser: {code[:100]}...")
    if not approval:
        return {"result": None, "tab_name": tab_name, "error": "Denied by user"}

    try:
        page = _get_page(tab_name)
        result = page.evaluate(code)
        return {"result": str(result) if result is not None else None, "tab_name": tab_name}
    except Exception as e:
        return {"result": None, "tab_name": tab_name, "error": str(e)}


@tool
def browser_screenshot(tab_name: str = "default", path: str = "/tmp/screenshot.png") -> dict:
    """Take a screenshot of the current browser page.

    Args:
        tab_name: Browser tab name.
        path: File path to save the screenshot.

    Returns:
        Dict with keys: success, path, tab_name.
    """
    try:
        page = _get_page(tab_name)
        page.screenshot(path=path, full_page=True)
        return {"success": True, "path": path, "tab_name": tab_name}
    except Exception as e:
        return {"success": False, "path": path, "tab_name": tab_name, "error": str(e)}


@tool
def browser_list_tabs() -> list[dict]:
    """List all open browser tabs.

    Returns:
        List of tab info dicts with keys: name, url, title.
    """
    tabs = []
    for name, page in _browser_state.get("tabs", {}).items():
        try:
            tabs.append({
                "name": name,
                "url": page.url,
                "title": page.title(),
                "active": name == _browser_state.get("active_tab"),
            })
        except Exception:
            tabs.append({"name": name, "url": "?", "title": "?", "active": False})
    return tabs


@tool
def browser_close(tab_name: str = None) -> dict:
    """Close a browser tab or all tabs if no name specified.

    Args:
        tab_name: Tab name to close. If None, closes all tabs and the browser.

    Returns:
        Dict with keys: closed, remaining_tabs.
    """
    if tab_name:
        page = _browser_state["tabs"].pop(tab_name, None)
        if page:
            try:
                page.close()
            except Exception:
                pass
        remaining = list(_browser_state["tabs"].keys())
        if _browser_state["active_tab"] == tab_name:
            _browser_state["active_tab"] = remaining[0] if remaining else None
        return {"closed": tab_name, "remaining_tabs": remaining}
    else:
        # Close everything
        for name, page in _browser_state["tabs"].items():
            try:
                page.close()
            except Exception:
                pass
        _browser_state["tabs"].clear()
        _browser_state["active_tab"] = None

        if _browser_state.get("browser"):
            try:
                _browser_state["browser"].close()
            except Exception:
                pass
            _browser_state["browser"] = None

        if _browser_state.get("_pw"):
            try:
                _browser_state["_pw"].stop()
            except Exception:
                pass
            _browser_state["_pw"] = None

        _browser_state["context"] = None
        return {"closed": "all", "remaining_tabs": []}


def get_browser_tools() -> list:
    """Return all browser automation tools."""
    return [
        browser_navigate,
        browser_get_content,
        browser_get_html,
        browser_fill,
        browser_click,
        browser_get_cookies,
        browser_set_cookie,
        browser_execute_js,
        browser_screenshot,
        browser_list_tabs,
        browser_close,
    ]
