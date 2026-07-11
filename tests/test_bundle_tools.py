"""Tests for JS bundle analysis tools."""

from __future__ import annotations

from unittest.mock import patch

import clearwing.agent.tools.recon.bundle_tools as bun_mod
from clearwing.agent.tools.recon.bundle_tools import (
    extract_api_routes,
    fetch_js_bundles,
    get_bundle_tools,
    search_bundle_patterns,
)

FAKE_HTML = """
<html>
<head>
<script src="/js/app.12345.js"></script>
<script src="/js/vendor.abcde.js"></script>
</head>
<body></body>
</html>
"""

FAKE_JS = """
var API_KEY = "sk_test_AAAAAAAAAAAAAAAA";
fetch("/api/v2/auth/start", {method: "POST"});
fetch("/api/v1/account/settings", {method: "GET"});
var secret = "flag{test_flag_123}";
console.log("debug output");
// TODO: remove this before release
"""


class TestFetchJsBundles:
    def test_declined(self):
        with patch.object(bun_mod, "interrupt", return_value=False):
            result = fetch_js_bundles.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_page_fetch_failure(self):
        def mock_fetch(url, timeout=30):
            return (0, "Connection refused", 0.0)

        with (
            patch.object(bun_mod, "interrupt", return_value=True),
            patch.object(bun_mod, "_fetch_url", mock_fetch),
        ):
            result = fetch_js_bundles.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_successful_fetch(self):
        def mock_fetch(url, timeout=30):
            if url.endswith("/"):
                return (200, FAKE_HTML, 50.0)
            return (200, FAKE_JS, 20.0)

        with (
            patch.object(bun_mod, "interrupt", return_value=True),
            patch.object(bun_mod, "_fetch_url", mock_fetch),
        ):
            result = fetch_js_bundles.invoke({"target": "http://example.com"})
        assert result["bundles_found"] == 2
        assert result["bundles_downloaded"] == 2

    def test_no_scripts(self):
        def mock_fetch(url, timeout=30):
            return (200, "<html><body>No scripts</body></html>", 10.0)

        with (
            patch.object(bun_mod, "interrupt", return_value=True),
            patch.object(bun_mod, "_fetch_url", mock_fetch),
        ):
            result = fetch_js_bundles.invoke({"target": "http://example.com"})
        assert "error" in result


class TestSearchBundlePatterns:
    def test_no_bundles_no_target(self):
        result = search_bundle_patterns.invoke({})
        assert "error" in result

    def test_finds_patterns_in_provided_bundles(self):
        bundles = [{"filename": "app.js", "content": FAKE_JS, "size_kb": 1.0}]
        result = search_bundle_patterns.invoke({"bundles": bundles})
        assert result["total_matches"] > 0
        patterns_found = {m["pattern"] for m in result["matches"]}
        assert "flag_format" in patterns_found
        assert "debug_code" in patterns_found

    def test_custom_terms(self):
        bundles = [{"filename": "app.js", "content": "var mySpecialVar = 42;"}]
        result = search_bundle_patterns.invoke({
            "bundles": bundles,
            "custom_terms": ["mySpecialVar"],
        })
        assert result["total_matches"] >= 1

    def test_empty_bundle_content(self):
        bundles = [{"filename": "empty.js", "content": ""}]
        result = search_bundle_patterns.invoke({"bundles": bundles})
        assert result["total_matches"] == 0


class TestExtractApiRoutes:
    def test_no_bundles_no_target(self):
        result = extract_api_routes.invoke({})
        assert "error" in result

    def test_finds_routes(self):
        bundles = [{"filename": "app.js", "content": FAKE_JS}]
        result = extract_api_routes.invoke({"bundles": bundles})
        assert result["routes_found"] >= 2
        paths = [r["path"] for r in result["routes"]]
        assert "/api/v2/auth/start" in paths
        assert "/api/v1/account/settings" in paths

    def test_detects_methods(self):
        bundles = [{"filename": "app.js", "content": FAKE_JS}]
        result = extract_api_routes.invoke({"bundles": bundles})
        for route in result["routes"]:
            if route["path"] == "/api/v2/auth/start":
                assert "POST" in route["methods"]

    def test_api_prefixes(self):
        bundles = [{"filename": "app.js", "content": FAKE_JS}]
        result = extract_api_routes.invoke({"bundles": bundles})
        assert len(result["api_prefixes"]) > 0


class TestGetBundleTools:
    def test_returns_list(self):
        assert isinstance(get_bundle_tools(), list)

    def test_tool_count(self):
        assert len(get_bundle_tools()) == 3

    def test_tool_names(self):
        names = [t.name for t in get_bundle_tools()]
        assert names == ["fetch_js_bundles", "search_bundle_patterns", "extract_api_routes"]
