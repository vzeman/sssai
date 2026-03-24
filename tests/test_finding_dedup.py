"""Unit tests for finding deduplication and lifecycle tracking."""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from modules.agent.finding_dedup import (
    make_dedup_key,
    deduplicate_findings,
    mark_resolved_in_es,
    _normalize_title,
    _title_similarity,
    _url_domain,
    _best_previous_match,
    _stamp_all_new,
)


class TestNormalizeTitle:
    """Test title normalization."""

    def test_lowercase_conversion(self):
        assert _normalize_title("XSS Attack") == "xss attack"

    def test_punctuation_removal(self):
        assert _normalize_title("SQL-Injection!") == "sql injection"

    def test_whitespace_collapse(self):
        assert _normalize_title("Multiple    Spaces") == "multiple spaces"

    def test_combined_normalization(self):
        assert _normalize_title("ReFlected  XSS & CSRF!") == "reflected xss csrf"


class TestUrlDomain:
    """Test URL domain extraction."""

    def test_extract_netloc(self):
        assert _url_domain("https://example.com:8080/path") == "example.com:8080"

    def test_simple_domain(self):
        assert _url_domain("http://example.com") == "example.com"

    def test_invalid_url_fallback(self):
        assert _url_domain("not-a-url") == "not-a-url"

    def test_empty_string(self):
        assert _url_domain("") == ""


class TestTitleSimilarity:
    """Test finding title similarity matching."""

    def test_identical_titles(self):
        assert _title_similarity("XSS Vulnerability", "XSS Vulnerability") == 1.0

    def test_high_similarity(self):
        score = _title_similarity("SQL Injection Found", "SQL Injection Detected")
        assert score >= 0.7

    def test_low_similarity(self):
        score = _title_similarity("XSS", "CSRF")
        assert score < 0.5

    def test_case_insensitive(self):
        assert _title_similarity("XSS", "xss") == 1.0


class TestMakeDedupKey:
    """Test deduplication key generation."""

    def test_consistent_key_generation(self):
        key1 = make_dedup_key("XSS Attack", "client-side", "https://example.com/page")
        key2 = make_dedup_key("XSS Attack", "client-side", "https://example.com/page")
        assert key1 == key2

    def test_different_categories_different_keys(self):
        key1 = make_dedup_key("Finding", "cat1", "https://example.com")
        key2 = make_dedup_key("Finding", "cat2", "https://example.com")
        assert key1 != key2

    def test_different_domains_different_keys(self):
        key1 = make_dedup_key("Finding", "cat", "https://example1.com")
        key2 = make_dedup_key("Finding", "cat", "https://example2.com")
        assert key1 != key2

    def test_path_difference_same_key(self):
        """Minor path differences on same domain should produce same key."""
        key1 = make_dedup_key("Finding", "cat", "https://example.com/path1")
        key2 = make_dedup_key("Finding", "cat", "https://example.com/path2")
        assert key1 == key2

    def test_empty_affected_url(self):
        key = make_dedup_key("Finding", "cat", "")
        assert isinstance(key, str)
        assert len(key) == 40  # SHA1 hex length


class TestBestPreviousMatch:
    """Test previous finding matching logic."""

    def test_exact_match(self):
        finding = {
            "title": "XSS Vulnerability",
            "category": "web",
            "affected_url": "https://example.com/page",
        }
        previous = [
            {
                "_id": "doc1",
                "title": "XSS Vulnerability",
                "category": "web",
                "affected_url": "https://example.com/page",
            }
        ]
        match = _best_previous_match(finding, previous)
        assert match is not None
        assert match["_id"] == "doc1"

    def test_category_mismatch_no_match(self):
        finding = {
            "title": "XSS",
            "category": "web",
            "affected_url": "https://example.com",
        }
        previous = [
            {
                "_id": "doc1",
                "title": "XSS",
                "category": "api",
                "affected_url": "https://example.com",
            }
        ]
        match = _best_previous_match(finding, previous)
        assert match is None

    def test_domain_mismatch_no_match(self):
        finding = {
            "title": "XSS",
            "category": "web",
            "affected_url": "https://example1.com",
        }
        previous = [
            {
                "_id": "doc1",
                "title": "XSS",
                "category": "web",
                "affected_url": "https://example2.com",
            }
        ]
        match = _best_previous_match(finding, previous)
        assert match is None

    def test_similarity_threshold_applied(self):
        """Findings below similarity threshold should not match."""
        finding = {
            "title": "XSS",
            "category": "web",
            "affected_url": "https://example.com",
        }
        previous = [
            {
                "_id": "doc1",
                "title": "CSRF",
                "category": "web",
                "affected_url": "https://example.com",
            }
        ]
        match = _best_previous_match(finding, previous)
        assert match is None

    def test_best_match_selection(self):
        """When multiple candidates exist, select the best similarity match."""
        finding = {
            "title": "SQL Injection Attack",
            "category": "database",
            "affected_url": "https://example.com",
        }
        previous = [
            {
                "_id": "doc1",
                "title": "SQL Injection",
                "category": "database",
                "affected_url": "https://example.com",
            },
            {
                "_id": "doc2",
                "title": "SQL Injection Vulnerability Found",
                "category": "database",
                "affected_url": "https://example.com",
            },
        ]
        match = _best_previous_match(finding, previous)
        assert match is not None
        # Should match one of the similar ones
        assert match["_id"] in ["doc1", "doc2"]


class TestStampAllNew:
    """Test fallback stamping when ES is unavailable."""

    def test_all_marked_new(self):
        findings = [
            {"title": "XSS", "category": "web"},
            {"title": "CSRF", "category": "web"},
        ]
        result = _stamp_all_new(findings, "scan-123", "2024-01-01T00:00:00Z")
        assert len(result) == 2
        assert all(f["finding_status"] == "new" for f in result)
        assert all(f["first_seen_scan_id"] == "scan-123" for f in result)

    def test_dedup_key_generated(self):
        findings = [{"title": "XSS", "category": "web", "affected_urls": ["https://example.com"]}]
        result = _stamp_all_new(findings, "scan-123", "2024-01-01T00:00:00Z")
        assert len(result[0]["dedup_key"]) == 40  # SHA1


class TestDeduplicateFindings:
    """Test main deduplication workflow."""

    @patch("modules.infra.elasticsearch.search")
    def test_no_previous_findings(self, mock_es_search):
        """When no previous findings exist, all should be marked 'new'."""
        mock_es_search.return_value = {"hits": {"hits": []}}

        findings = [
            {"title": "XSS", "category": "web", "affected_urls": ["https://example.com"]},
        ]
        enriched, resolved = deduplicate_findings(findings, "example.com", "scan-1", "2024-01-01T00:00:00Z")

        assert len(enriched) == 1
        assert enriched[0]["finding_status"] == "new"
        assert resolved == []

    @patch("modules.infra.elasticsearch.search")
    def test_existing_finding_still_present(self, mock_es_search):
        """When a previous finding is present in current scan, mark as 'existing'."""
        mock_es_search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "prev-doc-1",
                        "_source": {
                            "title": "XSS Vulnerability",
                            "category": "web",
                            "affected_url": "https://example.com/page",
                            "finding_status": "new",
                            "first_seen_scan_id": "scan-0",
                            "timestamp": "2024-01-01T00:00:00Z",
                        },
                    }
                ]
            }
        }

        findings = [
            {"title": "XSS Vulnerability", "category": "web", "affected_urls": ["https://example.com/page"]},
        ]
        enriched, resolved = deduplicate_findings(findings, "example.com", "scan-1", "2024-01-02T00:00:00Z")

        assert len(enriched) == 1
        assert enriched[0]["finding_status"] == "existing"
        assert enriched[0]["first_seen_scan_id"] == "scan-0"
        assert resolved == []

    @patch("modules.infra.elasticsearch.search")
    def test_finding_regression(self, mock_es_search):
        """When a resolved finding reappears, mark as 'regressed'."""
        mock_es_search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "prev-doc-1",
                        "_source": {
                            "title": "XSS Vulnerability",
                            "category": "web",
                            "affected_url": "https://example.com/page",
                            "finding_status": "resolved",
                            "first_seen_scan_id": "scan-0",
                            "timestamp": "2024-01-01T00:00:00Z",
                        },
                    }
                ]
            }
        }

        findings = [
            {"title": "XSS Vulnerability", "category": "web", "affected_urls": ["https://example.com/page"]},
        ]
        enriched, resolved = deduplicate_findings(findings, "example.com", "scan-2", "2024-01-03T00:00:00Z")

        assert len(enriched) == 1
        assert enriched[0]["finding_status"] == "regressed"
        assert resolved == []

    @patch("modules.infra.elasticsearch.search")
    def test_finding_resolution_detection(self, mock_es_search):
        """When a previous finding is not in current scan, mark its ID as resolved."""
        mock_es_search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "prev-doc-1",
                        "_source": {
                            "title": "Old XSS",
                            "category": "web",
                            "affected_url": "https://example.com/old",
                            "finding_status": "new",
                            "timestamp": "2024-01-01T00:00:00Z",
                        },
                    },
                    {
                        "_id": "prev-doc-2",
                        "_source": {
                            "title": "Still Present",
                            "category": "web",
                            "affected_url": "https://example.com/current",
                            "finding_status": "new",
                            "timestamp": "2024-01-01T00:00:00Z",
                        },
                    },
                ]
            }
        }

        findings = [
            {"title": "Still Present", "category": "web", "affected_urls": ["https://example.com/current"]},
        ]
        enriched, resolved = deduplicate_findings(findings, "example.com", "scan-1", "2024-01-02T00:00:00Z")

        assert len(enriched) == 1
        assert "prev-doc-1" in resolved
        assert "prev-doc-2" not in resolved

    @patch("modules.infra.elasticsearch.search")
    def test_es_failure_graceful_fallback(self, mock_es_search):
        """When ES search fails, fallback to marking all as 'new'."""
        mock_es_search.side_effect = Exception("ES connection failed")

        findings = [
            {"title": "XSS", "category": "web", "affected_urls": ["https://example.com"]},
        ]
        enriched, resolved = deduplicate_findings(findings, "example.com", "scan-1", "2024-01-01T00:00:00Z")

        assert len(enriched) == 1
        assert enriched[0]["finding_status"] == "new"
        assert resolved == []


class TestMarkResolvedInEs:
    """Test marking findings as resolved in Elasticsearch."""

    @patch("modules.infra.elasticsearch.get_client")
    def test_update_resolved_documents(self, mock_get_client):
        """Should update documents with resolved status."""
        mock_es = MagicMock()
        mock_get_client.return_value = mock_es

        resolved_ids = ["doc-1", "doc-2"]
        updated = mark_resolved_in_es(resolved_ids, "scan-1", "2024-01-01T00:00:00Z")

        assert updated == 2
        assert mock_es.update.call_count == 2

    @patch("modules.infra.elasticsearch.get_client")
    def test_empty_resolved_list(self, mock_get_client):
        """Empty resolved list should return 0."""
        updated = mark_resolved_in_es([], "scan-1", "2024-01-01T00:00:00Z")
        assert updated == 0

    @patch("modules.infra.elasticsearch.get_client")
    def test_update_partial_failure(self, mock_get_client):
        """Should return count of successfully updated docs."""
        mock_es = MagicMock()
        mock_es.update.side_effect = [None, Exception("Update failed"), None]
        mock_get_client.return_value = mock_es

        updated = mark_resolved_in_es(["doc-1", "doc-2", "doc-3"], "scan-1", "2024-01-01T00:00:00Z")
        assert updated == 2  # 2 successes, 1 failure

    @patch("modules.infra.elasticsearch.get_client")
    def test_es_client_failure(self, mock_get_client):
        """ES client initialization failure should return 0."""
        mock_get_client.side_effect = Exception("ES connection failed")

        updated = mark_resolved_in_es(["doc-1"], "scan-1", "2024-01-01T00:00:00Z")
        assert updated == 0
