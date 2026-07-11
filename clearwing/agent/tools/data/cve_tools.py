"""CVE database tools — download, index, and search the NVD CVE List V5."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any

from clearwing.agent.tooling import interrupt, tool

_CVE_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
_DB_NAME = "cve.db"


def _db_dir() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "cve"


def _db_path() -> Path:
    return _db_dir() / _DB_NAME


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve (
            cve_id TEXT PRIMARY KEY,
            state TEXT,
            date_published TEXT,
            date_updated TEXT,
            assigner TEXT,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            cwe_id TEXT,
            affected_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve(cvss_score);
        CREATE INDEX IF NOT EXISTS idx_cve_state ON cve(state);
        CREATE INDEX IF NOT EXISTS idx_cve_date ON cve(date_published);

        CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
            cve_id, description, affected_json, content=''
        );
    """)


def _extract_record(data: dict) -> dict[str, Any] | None:
    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    if not cve_id:
        return None

    cna = data.get("containers", {}).get("cna", {})

    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "en").startswith("en"):
            desc = d.get("value", "")
            break
    if not desc:
        descs = cna.get("descriptions", [])
        if descs:
            desc = descs[0].get("value", "")

    cvss_score = None
    cvss_severity = None
    for m in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                cvss_score = m[key].get("baseScore")
                cvss_severity = m[key].get("baseSeverity")
                break
        if cvss_score is not None:
            break

    cwe_id = None
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            cid = d.get("cweId", "")
            if cid:
                cwe_id = cid
                break
        if cwe_id:
            break

    affected = cna.get("affected", [])

    return {
        "cve_id": cve_id,
        "state": meta.get("state", ""),
        "date_published": meta.get("datePublished", ""),
        "date_updated": meta.get("dateUpdated", ""),
        "assigner": meta.get("assignerShortName", ""),
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_id": cwe_id,
        "affected_json": json.dumps(affected) if affected else "",
    }


def _build_db(cve_dir: Path, db_path: Path) -> int:
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    _create_schema(conn)

    count = 0
    batch: list[dict] = []

    for year_dir in sorted(cve_dir.iterdir()):
        if not year_dir.is_dir():
            continue
        for bucket_dir in sorted(year_dir.iterdir()):
            if not bucket_dir.is_dir():
                continue
            for json_file in bucket_dir.iterdir():
                if not json_file.suffix == ".json":
                    continue
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    rec = _extract_record(data)
                    if rec:
                        batch.append(rec)
                        count += 1
                except Exception:
                    pass

                if len(batch) >= 5000:
                    _flush_batch(conn, batch)
                    batch = []

    if batch:
        _flush_batch(conn, batch)

    conn.close()
    return count


def _flush_batch(conn: sqlite3.Connection, batch: list[dict]) -> None:
    conn.executemany(
        """INSERT OR REPLACE INTO cve
           (cve_id, state, date_published, date_updated, assigner,
            description, cvss_score, cvss_severity, cwe_id, affected_json)
           VALUES (:cve_id, :state, :date_published, :date_updated, :assigner,
                   :description, :cvss_score, :cvss_severity, :cwe_id, :affected_json)""",
        batch,
    )
    conn.executemany(
        "INSERT INTO cve_fts(cve_id, description, affected_json) VALUES (:cve_id, :description, :affected_json)",
        batch,
    )
    conn.commit()


def _get_conn() -> sqlite3.Connection:
    db = _db_path()
    if not db.exists():
        raise FileNotFoundError(
            f"CVE database not found at {db}. Run cve_db_update first."
        )
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn


def _format_results(rows: list[sqlite3.Row], limit: int) -> dict:
    results = []
    for row in rows[:limit]:
        entry: dict[str, Any] = {
            "cve_id": row["cve_id"],
            "cvss_score": row["cvss_score"],
            "cvss_severity": row["cvss_severity"],
            "description": row["description"][:500] if row["description"] else "",
        }
        if row["cwe_id"]:
            entry["cwe_id"] = row["cwe_id"]
        if row["date_published"]:
            entry["date_published"] = row["date_published"][:10]
        results.append(entry)
    return {
        "count": len(results),
        "total_matches": len(rows),
        "results": results,
    }


@tool
def cve_db_update(zip_path: str = "") -> dict:
    """Download and index the NVD CVE List V5 into a local SQLite database.

    If zip_path is provided, uses that local zip file instead of downloading.
    Otherwise downloads from GitHub (~550 MB). The database enables fast
    full-text search across all CVEs.

    Args:
        zip_path: Path to a local cvelistV5-main.zip file. If empty,
            downloads from GitHub.

    Returns:
        Status dict with record count and database path.
    """
    db_dir = _db_dir()
    db_dir.mkdir(parents=True, exist_ok=True)
    db = _db_path()

    try:
        if zip_path:
            src = Path(zip_path).expanduser().resolve()
            if not src.exists():
                return {"error": f"Zip file not found: {src}"}
        else:
            if not interrupt(
                f"Download CVE database (~550 MB) from GitHub to {db_dir}?"
            ):
                return {"error": "User declined download."}

            import urllib.request

            src = db_dir / "cvelistV5-main.zip"
            urllib.request.urlretrieve(_CVE_ZIP_URL, str(src))

        extract_dir = db_dir / "cvelistV5"
        if extract_dir.exists():
            import shutil

            shutil.rmtree(extract_dir)

        with zipfile.ZipFile(str(src), "r") as zf:
            zf.extractall(str(extract_dir))

        cve_dir = extract_dir / "cvelistV5-main" / "cves"
        if not cve_dir.is_dir():
            candidates = list(extract_dir.iterdir())
            if candidates:
                cve_dir = candidates[0] / "cves"

        if not cve_dir.is_dir():
            return {"error": f"Could not find cves/ directory in extracted archive under {extract_dir}"}

        count = _build_db(cve_dir, db)

        import shutil

        shutil.rmtree(extract_dir)

        return {
            "status": "success",
            "records": count,
            "db_path": str(db),
        }
    except Exception as e:
        return {"error": f"Failed to build CVE database: {e}"}


@tool
def cve_search(
    query: str,
    min_cvss: float = 0.0,
    max_results: int = 25,
    date_after: str = "",
    cwe: str = "",
) -> dict:
    """Full-text search across the local CVE database.

    Searches CVE descriptions and affected product names. Results are
    sorted by CVSS score descending.

    Args:
        query: Search terms (e.g. "1password", "SRP authentication bypass",
            "AES-GCM nonce reuse"). Supports FTS5 syntax: AND, OR, NOT,
            "exact phrase", prefix*.
        min_cvss: Minimum CVSS score filter (0.0-10.0).
        max_results: Maximum number of results to return.
        date_after: Only include CVEs published after this date (YYYY-MM-DD).
        cwe: Filter by CWE ID (e.g. "CWE-79").

    Returns:
        Dict with count, total_matches, and results list.
    """
    try:
        conn = _get_conn()
    except FileNotFoundError as e:
        return {"error": str(e)}

    try:
        fts_query = query
        if not any(op in query.upper() for op in ("AND", "OR", "NOT", '"')):
            terms = query.split()
            if len(terms) > 1:
                fts_query = " AND ".join(f'"{t}"' if " " in t else t for t in terms)

        sql = """
            SELECT c.cve_id, c.cvss_score, c.cvss_severity, c.description,
                   c.cwe_id, c.date_published, c.affected_json
            FROM cve_fts f
            JOIN cve c ON f.cve_id = c.cve_id
            WHERE cve_fts MATCH ?
        """
        params: list[Any] = [fts_query]

        if min_cvss > 0:
            sql += " AND c.cvss_score >= ?"
            params.append(min_cvss)

        if date_after:
            sql += " AND c.date_published >= ?"
            params.append(date_after)

        if cwe:
            sql += " AND c.cwe_id = ?"
            params.append(cwe)

        sql += " ORDER BY c.cvss_score DESC NULLS LAST"

        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return _format_results(rows, max_results)
    except Exception as e:
        conn.close()
        if "no such table" in str(e):
            return {"error": "CVE database exists but is missing FTS index. Run cve_db_update to rebuild."}
        return _format_results([], 0) if "fts5" in str(e).lower() else {"error": f"Search failed: {e}"}


@tool
def cve_lookup(cve_id: str) -> dict:
    """Look up a specific CVE by ID. Returns the full record.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2022-32550").

    Returns:
        Full CVE record including description, CVSS, CWE, affected products,
        and dates.
    """
    try:
        conn = _get_conn()
    except FileNotFoundError as e:
        return {"error": str(e)}

    try:
        cve_id_upper = cve_id.upper().strip()
        row = conn.execute(
            "SELECT * FROM cve WHERE cve_id = ?", (cve_id_upper,)
        ).fetchone()
        conn.close()

        if not row:
            return {"error": f"CVE {cve_id_upper} not found in database."}

        result: dict[str, Any] = {
            "cve_id": row["cve_id"],
            "state": row["state"],
            "date_published": row["date_published"],
            "date_updated": row["date_updated"],
            "assigner": row["assigner"],
            "description": row["description"],
            "cvss_score": row["cvss_score"],
            "cvss_severity": row["cvss_severity"],
            "cwe_id": row["cwe_id"],
        }

        if row["affected_json"]:
            try:
                result["affected"] = json.loads(row["affected_json"])
            except json.JSONDecodeError:
                result["affected_raw"] = row["affected_json"]

        return result
    except Exception as e:
        conn.close()
        return {"error": f"Lookup failed: {e}"}


def get_cve_tools() -> list[Any]:
    """Return all CVE database tools."""
    return [cve_db_update, cve_search, cve_lookup]
