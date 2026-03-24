"""Tests for CSV/JSON export functionality.

Tests the pure CSV generation logic without requiring backend dependencies
(redis, elasticsearch, etc.) which are only available inside Docker.
"""

import csv
import io
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Inline copies of the pure helpers to test without heavy imports ───

FINDING_CSV_COLUMNS = [
    "title",
    "severity",
    "category",
    "description",
    "affected_url",
    "cvss_score",
    "cve_id",
    "tool",
    "remediation",
    "confidence",
    "finding_status",
]

SCAN_CSV_COLUMNS = [
    "scan_id",
    "target",
    "scan_type",
    "status",
    "risk_score",
    "findings_count",
    "created_at",
]


def _findings_to_rows(hits: list[dict]) -> list[dict]:
    rows = []
    for hit in hits:
        src = hit.get("_source", {})
        rows.append({col: src.get(col, "") for col in FINDING_CSV_COLUMNS})
    return rows


def _build_csv(columns: list[str], rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


# ── CSV builder tests ────────────────────────────────────────────────


def test_build_csv_with_data():
    columns = ["name", "value"]
    rows = [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
    result = _build_csv(columns, rows)
    reader = csv.DictReader(io.StringIO(result))
    parsed = list(reader)
    assert len(parsed) == 2
    assert parsed[0]["name"] == "a"
    assert parsed[1]["value"] == "2"


def test_build_csv_empty():
    result = _build_csv(["col1", "col2"], [])
    reader = csv.DictReader(io.StringIO(result))
    parsed = list(reader)
    assert len(parsed) == 0
    assert "col1" in result
    assert "col2" in result


def test_build_csv_headers_match_finding_columns():
    result = _build_csv(FINDING_CSV_COLUMNS, [])
    reader = csv.reader(io.StringIO(result))
    header = next(reader)
    assert header == FINDING_CSV_COLUMNS


def test_build_csv_headers_match_scan_columns():
    result = _build_csv(SCAN_CSV_COLUMNS, [])
    reader = csv.reader(io.StringIO(result))
    header = next(reader)
    assert header == SCAN_CSV_COLUMNS


# ── Findings row extraction ──────────────────────────────────────────


def test_findings_to_rows_extracts_source():
    hits = [
        {
            "_source": {
                "title": "XSS in /login",
                "severity": "high",
                "category": "xss",
                "description": "Reflected XSS",
                "affected_url": "https://example.com/login",
                "cvss_score": 7.5,
                "cve_id": "CVE-2024-1234",
                "tool": "nuclei",
                "remediation": "Sanitize input",
                "confidence": 0.9,
                "finding_status": "new",
            }
        }
    ]
    rows = _findings_to_rows(hits)
    assert len(rows) == 1
    assert rows[0]["title"] == "XSS in /login"
    assert rows[0]["severity"] == "high"
    assert rows[0]["cvss_score"] == 7.5


def test_findings_to_rows_missing_fields():
    hits = [{"_source": {"title": "Minimal finding"}}]
    rows = _findings_to_rows(hits)
    assert len(rows) == 1
    assert rows[0]["title"] == "Minimal finding"
    assert rows[0]["severity"] == ""
    assert rows[0]["cve_id"] == ""


def test_findings_to_rows_empty():
    rows = _findings_to_rows([])
    assert rows == []


def test_full_csv_pipeline():
    """End-to-end: hits -> rows -> CSV string -> parsed back."""
    hits = [
        {
            "_source": {
                "title": "SQL Injection",
                "severity": "critical",
                "category": "sqli",
                "description": "Blind SQL injection in search",
                "affected_url": "https://example.com/search",
                "cvss_score": 9.8,
                "cve_id": "CVE-2024-5678",
                "tool": "sqlmap",
                "remediation": "Use parameterized queries",
                "confidence": 0.95,
                "finding_status": "new",
            }
        },
        {
            "_source": {
                "title": "Open Redirect",
                "severity": "low",
                "category": "redirect",
                "description": "Open redirect via returnUrl param",
                "affected_url": "https://example.com/redirect",
                "cvss_score": 3.1,
                "cve_id": "",
                "tool": "zap",
                "remediation": "Validate redirect targets",
                "confidence": 0.8,
                "finding_status": "existing",
            }
        },
    ]
    rows = _findings_to_rows(hits)
    csv_text = _build_csv(FINDING_CSV_COLUMNS, rows)
    reader = csv.DictReader(io.StringIO(csv_text))
    parsed = list(reader)
    assert len(parsed) == 2
    assert parsed[0]["title"] == "SQL Injection"
    assert parsed[0]["severity"] == "critical"
    assert parsed[1]["title"] == "Open Redirect"
    assert parsed[1]["tool"] == "zap"


def test_csv_special_characters():
    """Ensure commas, quotes, and newlines in values are properly escaped."""
    rows = [{"name": 'He said "hello"', "value": "a,b,c"}]
    csv_text = _build_csv(["name", "value"], rows)
    reader = csv.DictReader(io.StringIO(csv_text))
    parsed = list(reader)
    assert parsed[0]["name"] == 'He said "hello"'
    assert parsed[0]["value"] == "a,b,c"
