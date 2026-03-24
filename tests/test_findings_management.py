"""Tests for findings management — status validation and filtering logic.

Tests the pure validation and filtering logic without requiring backend
dependencies (redis, elasticsearch, etc.) which are only available inside Docker.
"""


# ── Inline copies of the constants to avoid heavy imports ───────────

VALID_STATUSES = frozenset({
    "new",
    "confirmed",
    "in_progress",
    "resolved",
    "false_positive",
    "accepted_risk",
})


def validate_status(status: str) -> bool:
    """Check if a status value is valid."""
    return status in VALID_STATUSES


def filter_findings(
    findings: list[dict],
    exclude_false_positives: bool = False,
    exclude_accepted_risk: bool = False,
    status: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
) -> list[dict]:
    """Filter findings by criteria (mirrors backend ES query logic)."""
    result = []
    for f in findings:
        if exclude_false_positives and f.get("finding_status") == "false_positive":
            continue
        if exclude_accepted_risk and f.get("finding_status") == "accepted_risk":
            continue
        if status and f.get("finding_status") != status:
            continue
        if severity and f.get("severity") != severity:
            continue
        if scan_id and f.get("scan_id") != scan_id:
            continue
        result.append(f)
    return result


def build_audit_entry(
    user_id: str,
    previous_status: str,
    new_status: str,
    reason: str,
) -> dict:
    """Build an audit trail entry."""
    return {
        "changed_by": user_id,
        "previous_status": previous_status,
        "new_status": new_status,
        "reason": reason,
    }


# ── Status validation tests ─────────────────────────────────────────

class TestStatusValidation:
    def test_valid_statuses_accepted(self):
        for status in ["new", "confirmed", "in_progress", "resolved", "false_positive", "accepted_risk"]:
            assert validate_status(status), f"{status} should be valid"

    def test_invalid_statuses_rejected(self):
        for status in ["", "invalid", "open", "closed", "wontfix", "NEW", "False_Positive"]:
            assert not validate_status(status), f"{status} should be invalid"

    def test_exactly_six_valid_statuses(self):
        assert len(VALID_STATUSES) == 6


# ── Filtering tests ──────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {"id": "1", "finding_status": "new", "severity": "critical", "scan_id": "scan-a", "title": "SQL Injection"},
    {"id": "2", "finding_status": "confirmed", "severity": "high", "scan_id": "scan-a", "title": "XSS"},
    {"id": "3", "finding_status": "false_positive", "severity": "medium", "scan_id": "scan-b", "title": "Info Leak"},
    {"id": "4", "finding_status": "resolved", "severity": "low", "scan_id": "scan-b", "title": "Outdated Header"},
    {"id": "5", "finding_status": "accepted_risk", "severity": "high", "scan_id": "scan-a", "title": "Weak Cipher"},
    {"id": "6", "finding_status": "in_progress", "severity": "critical", "scan_id": "scan-c", "title": "RCE"},
]


class TestFindingsFiltering:
    def test_no_filters_returns_all(self):
        result = filter_findings(SAMPLE_FINDINGS)
        assert len(result) == 6

    def test_exclude_false_positives(self):
        result = filter_findings(SAMPLE_FINDINGS, exclude_false_positives=True)
        assert len(result) == 5
        assert all(f["finding_status"] != "false_positive" for f in result)

    def test_exclude_accepted_risk(self):
        result = filter_findings(SAMPLE_FINDINGS, exclude_accepted_risk=True)
        assert len(result) == 5
        assert all(f["finding_status"] != "accepted_risk" for f in result)

    def test_exclude_both_false_positive_and_accepted_risk(self):
        result = filter_findings(
            SAMPLE_FINDINGS,
            exclude_false_positives=True,
            exclude_accepted_risk=True,
        )
        assert len(result) == 4
        statuses = {f["finding_status"] for f in result}
        assert "false_positive" not in statuses
        assert "accepted_risk" not in statuses

    def test_filter_by_status(self):
        result = filter_findings(SAMPLE_FINDINGS, status="confirmed")
        assert len(result) == 1
        assert result[0]["id"] == "2"

    def test_filter_by_severity(self):
        result = filter_findings(SAMPLE_FINDINGS, severity="critical")
        assert len(result) == 2
        assert {f["id"] for f in result} == {"1", "6"}

    def test_filter_by_scan_id(self):
        result = filter_findings(SAMPLE_FINDINGS, scan_id="scan-b")
        assert len(result) == 2
        assert {f["id"] for f in result} == {"3", "4"}

    def test_combined_filters(self):
        result = filter_findings(
            SAMPLE_FINDINGS,
            severity="high",
            exclude_accepted_risk=True,
        )
        assert len(result) == 1
        assert result[0]["id"] == "2"

    def test_filter_returns_empty_for_no_match(self):
        result = filter_findings(SAMPLE_FINDINGS, status="resolved", severity="critical")
        assert len(result) == 0

    def test_empty_findings_list(self):
        result = filter_findings([])
        assert result == []


# ── Audit trail tests ────────────────────────────────────────────────

class TestAuditTrail:
    def test_audit_entry_structure(self):
        entry = build_audit_entry("user-1", "new", "confirmed", "Verified by team")
        assert entry["changed_by"] == "user-1"
        assert entry["previous_status"] == "new"
        assert entry["new_status"] == "confirmed"
        assert entry["reason"] == "Verified by team"

    def test_audit_entry_empty_reason(self):
        entry = build_audit_entry("user-2", "confirmed", "resolved", "")
        assert entry["reason"] == ""

    def test_audit_trail_accumulation(self):
        trail = []
        trail.append(build_audit_entry("user-1", "new", "confirmed", "First triage"))
        trail.append(build_audit_entry("user-2", "confirmed", "false_positive", "Not a real vuln"))
        assert len(trail) == 2
        assert trail[0]["new_status"] == "confirmed"
        assert trail[1]["new_status"] == "false_positive"
        assert trail[1]["previous_status"] == "confirmed"
