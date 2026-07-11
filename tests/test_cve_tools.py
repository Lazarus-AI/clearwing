"""Tests for the CVE database tools."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from clearwing.agent.tools.data.cve_tools import (
    _build_db,
    _create_schema,
    _extract_record,
    cve_db_update,
    cve_lookup,
    cve_search,
    get_cve_tools,
)


def _make_cve_json(
    cve_id: str,
    description: str = "Test vulnerability",
    cvss_score: float | None = 7.5,
    cvss_severity: str | None = "HIGH",
    cwe_id: str | None = "CWE-79",
    vendor: str = "TestVendor",
    product: str = "TestProduct",
    assigner: str = "test",
    state: str = "PUBLISHED",
) -> dict:
    metrics = []
    if cvss_score is not None:
        metrics.append(
            {
                "cvssV3_1": {
                    "baseScore": cvss_score,
                    "baseSeverity": cvss_severity or "HIGH",
                }
            }
        )

    problem_types = []
    if cwe_id:
        problem_types.append({"descriptions": [{"cweId": cwe_id, "type": "CWE"}]})

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": cve_id,
            "state": state,
            "assignerShortName": assigner,
            "datePublished": "2024-01-15T00:00:00.000Z",
            "dateUpdated": "2024-02-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": metrics,
                "problemTypes": problem_types,
                "affected": [
                    {
                        "vendor": vendor,
                        "product": product,
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
                "providerMetadata": {},
            }
        },
    }


@pytest.fixture
def cve_db(tmp_path):
    """Create a temporary CVE database with test data."""
    db_file = tmp_path / "cve.db"
    conn = sqlite3.connect(str(db_file))
    _create_schema(conn)

    records = [
        {
            "cve_id": "CVE-2024-0001",
            "state": "PUBLISHED",
            "date_published": "2024-01-15",
            "date_updated": "2024-02-01",
            "assigner": "test",
            "description": "SRP authentication bypass in TestProduct allows remote attackers to bypass authentication",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cwe_id": "CWE-287",
            "affected_json": json.dumps([{"vendor": "TestVendor", "product": "TestProduct"}]),
        },
        {
            "cve_id": "CVE-2024-0002",
            "state": "PUBLISHED",
            "date_published": "2024-03-01",
            "date_updated": "2024-03-15",
            "assigner": "test",
            "description": "AES-GCM nonce reuse in CryptoLib allows key recovery",
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "cwe_id": "CWE-323",
            "affected_json": json.dumps([{"vendor": "CryptoVendor", "product": "CryptoLib"}]),
        },
        {
            "cve_id": "CVE-2024-0003",
            "state": "PUBLISHED",
            "date_published": "2023-06-01",
            "date_updated": "2023-07-01",
            "assigner": "test",
            "description": "PBKDF2 timing side channel in 1Password allows password recovery",
            "cvss_score": 5.9,
            "cvss_severity": "MEDIUM",
            "cwe_id": "CWE-208",
            "affected_json": json.dumps([{"vendor": "AgileBits", "product": "1Password"}]),
        },
        {
            "cve_id": "CVE-2024-0004",
            "state": "PUBLISHED",
            "date_published": "2024-06-01",
            "date_updated": "2024-06-15",
            "assigner": "test",
            "description": "XSS vulnerability in WebApp allows script injection",
            "cvss_score": 4.3,
            "cvss_severity": "MEDIUM",
            "cwe_id": "CWE-79",
            "affected_json": json.dumps([{"vendor": "WebVendor", "product": "WebApp"}]),
        },
        {
            "cve_id": "CVE-2024-0005",
            "state": "PUBLISHED",
            "date_published": "2024-01-01",
            "date_updated": "2024-01-15",
            "assigner": "test",
            "description": "Buffer overflow with no CVSS score assigned",
            "cvss_score": None,
            "cvss_severity": None,
            "cwe_id": None,
            "affected_json": "",
        },
    ]

    conn.executemany(
        """INSERT INTO cve
           (cve_id, state, date_published, date_updated, assigner,
            description, cvss_score, cvss_severity, cwe_id, affected_json)
           VALUES (:cve_id, :state, :date_published, :date_updated, :assigner,
                   :description, :cvss_score, :cvss_severity, :cwe_id, :affected_json)""",
        records,
    )
    conn.executemany(
        "INSERT INTO cve_fts(cve_id, description, affected_json) VALUES (:cve_id, :description, :affected_json)",
        records,
    )
    conn.commit()
    conn.close()
    return db_file


class TestExtractRecord:
    def test_full_record(self):
        data = _make_cve_json("CVE-2024-9999", description="Test vuln", cvss_score=8.0)
        rec = _extract_record(data)
        assert rec is not None
        assert rec["cve_id"] == "CVE-2024-9999"
        assert rec["description"] == "Test vuln"
        assert rec["cvss_score"] == 8.0
        assert rec["cwe_id"] == "CWE-79"

    def test_no_metrics(self):
        data = _make_cve_json("CVE-2024-9998", cvss_score=None)
        rec = _extract_record(data)
        assert rec is not None
        assert rec["cvss_score"] is None
        assert rec["cvss_severity"] is None

    def test_no_cwe(self):
        data = _make_cve_json("CVE-2024-9997", cwe_id=None)
        rec = _extract_record(data)
        assert rec is not None
        assert rec["cwe_id"] is None

    def test_missing_cve_id_returns_none(self):
        data = {"cveMetadata": {}, "containers": {"cna": {}}}
        assert _extract_record(data) is None

    def test_non_english_description_fallback(self):
        data = _make_cve_json("CVE-2024-9996")
        data["containers"]["cna"]["descriptions"] = [
            {"lang": "es", "value": "Vulnerabilidad de prueba"},
        ]
        rec = _extract_record(data)
        assert rec is not None
        assert rec["description"] == "Vulnerabilidad de prueba"

    def test_affected_products_serialized(self):
        data = _make_cve_json("CVE-2024-9995", vendor="Acme", product="Widget")
        rec = _extract_record(data)
        assert rec is not None
        affected = json.loads(rec["affected_json"])
        assert affected[0]["vendor"] == "Acme"
        assert affected[0]["product"] == "Widget"


class TestCveSearch:
    def test_basic_search(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP")
        assert result["count"] >= 1
        assert result["results"][0]["cve_id"] == "CVE-2024-0001"

    def test_search_multiple_terms(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="nonce reuse")
        assert result["count"] >= 1
        cve_ids = {r["cve_id"] for r in result["results"]}
        assert "CVE-2024-0002" in cve_ids

    def test_min_cvss_filter(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP OR nonce OR PBKDF2 OR XSS", min_cvss=7.0)
        for r in result["results"]:
            assert r["cvss_score"] >= 7.0

    def test_date_filter(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP OR nonce OR PBKDF2 OR XSS", date_after="2024-02-01")
        for r in result["results"]:
            assert r["date_published"] >= "2024-02-01"

    def test_cwe_filter(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP OR nonce OR PBKDF2 OR XSS", cwe="CWE-287")
        for r in result["results"]:
            assert r["cwe_id"] == "CWE-287"

    def test_max_results(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP OR nonce OR PBKDF2 OR XSS", max_results=2)
        assert result["count"] <= 2

    def test_no_results(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="nonexistent_term_xyz123")
        assert result["count"] == 0

    def test_missing_database(self, tmp_path):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=tmp_path / "noexist.db"):
            result = cve_search.fn(query="test")
        assert "error" in result

    def test_results_sorted_by_cvss(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_search.fn(query="SRP OR nonce OR PBKDF2", max_results=10)
        scores = [r["cvss_score"] for r in result["results"] if r["cvss_score"] is not None]
        assert scores == sorted(scores, reverse=True)


class TestCveLookup:
    def test_existing_cve(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_lookup.fn(cve_id="CVE-2024-0001")
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["cvss_score"] == 9.8
        assert "SRP authentication bypass" in result["description"]
        assert "affected" in result

    def test_case_insensitive(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_lookup.fn(cve_id="cve-2024-0001")
        assert result["cve_id"] == "CVE-2024-0001"

    def test_not_found(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_lookup.fn(cve_id="CVE-9999-0001")
        assert "error" in result

    def test_missing_database(self, tmp_path):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=tmp_path / "noexist.db"):
            result = cve_lookup.fn(cve_id="CVE-2024-0001")
        assert "error" in result

    def test_cve_with_no_affected(self, cve_db):
        with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=cve_db):
            result = cve_lookup.fn(cve_id="CVE-2024-0005")
        assert result["cve_id"] == "CVE-2024-0005"
        assert "affected" not in result


class TestCveDbUpdate:
    def test_from_zip(self, tmp_path):
        cve_dir = tmp_path / "cvelistV5-main" / "cves" / "2024" / "0xxx"
        cve_dir.mkdir(parents=True)

        for i in range(3):
            data = _make_cve_json(f"CVE-2024-{i:04d}", description=f"Test vuln {i}")
            (cve_dir / f"CVE-2024-{i:04d}.json").write_text(json.dumps(data))

        zip_path = tmp_path / "cvelistV5-main.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            for json_file in cve_dir.glob("*.json"):
                arcname = f"cvelistV5-main/cves/2024/0xxx/{json_file.name}"
                zf.write(json_file, arcname)

        db_dir = tmp_path / "cve_db"
        with patch("clearwing.agent.tools.data.cve_tools._db_dir", return_value=db_dir):
            with patch("clearwing.agent.tools.data.cve_tools._db_path", return_value=db_dir / "cve.db"):
                result = cve_db_update.fn(zip_path=str(zip_path))

        assert result["status"] == "success"
        assert result["records"] == 3
        assert Path(result["db_path"]).exists()

    def test_missing_zip(self):
        result = cve_db_update.fn(zip_path="/nonexistent/path.zip")
        assert "error" in result

    def test_download_declined(self):
        with patch("clearwing.agent.tools.data.cve_tools.interrupt", return_value=False):
            result = cve_db_update.fn()
        assert "error" in result
        assert "declined" in result["error"]


class TestBuildDb:
    def test_builds_searchable_db(self, tmp_path):
        cve_dir = tmp_path / "cves" / "2024" / "0xxx"
        cve_dir.mkdir(parents=True)

        data = _make_cve_json(
            "CVE-2024-1234",
            description="1Password SRP bypass",
            vendor="AgileBits",
            product="1Password",
        )
        (cve_dir / "CVE-2024-1234.json").write_text(json.dumps(data))

        db_file = tmp_path / "test.db"
        count = _build_db(tmp_path / "cves", db_file)
        assert count == 1

        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM cve_fts WHERE cve_fts MATCH '1Password'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2024-1234"
        conn.close()

    def test_skips_invalid_json(self, tmp_path):
        cve_dir = tmp_path / "cves" / "2024" / "0xxx"
        cve_dir.mkdir(parents=True)

        (cve_dir / "CVE-2024-0001.json").write_text("{invalid json")

        data = _make_cve_json("CVE-2024-0002")
        (cve_dir / "CVE-2024-0002.json").write_text(json.dumps(data))

        db_file = tmp_path / "test.db"
        count = _build_db(tmp_path / "cves", db_file)
        assert count == 1


class TestGetCveTools:
    def test_returns_list(self):
        tools = get_cve_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_cve_tools()
        assert len(tools) == 3

    def test_tool_names(self):
        tools = get_cve_tools()
        names = [t.name for t in tools]
        assert "cve_db_update" in names
        assert "cve_search" in names
        assert "cve_lookup" in names
