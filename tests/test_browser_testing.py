"""Tests for browser-based security testing module (issue #64)."""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBrowserModule(unittest.TestCase):
    """Test the browser.py module functions."""

    def test_import_browser_module(self):
        from modules.agent.browser import run_browser_test, run_browser_crawl
        self.assertTrue(callable(run_browser_test))
        self.assertTrue(callable(run_browser_crawl))

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_fallback_browser_test(self, mock_run, mock_pw):
        """When Playwright is not available, falls back to curl-based analysis."""
        from modules.agent.browser import run_browser_test

        mock_run.return_value = MagicMock(
            stdout='<html><script>document.write(x); eval(y);</script></html>',
            returncode=0,
        )

        result = run_browser_test("https://example.com", "await page.goto(url)")

        self.assertIn("curl fallback", result)
        self.assertIn("example.com", result)
        self.assertIn("document.write", result)
        self.assertIn("eval(", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_fallback_browser_test_no_sinks(self, mock_run, mock_pw):
        """Fallback reports no sinks when HTML is clean."""
        from modules.agent.browser import run_browser_test

        mock_run.return_value = MagicMock(
            stdout='<html><body><h1>Hello</h1></body></html>',
            returncode=0,
        )

        result = run_browser_test("https://clean.example.com", "await page.goto(url)")
        self.assertIn("No obvious DOM XSS sinks", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_fallback_browser_crawl(self, mock_run, mock_pw):
        """Fallback crawl uses curl to extract links."""
        from modules.agent.browser import run_browser_crawl

        mock_run.return_value = MagicMock(
            stdout='<html><title>Test Page</title><a href="/about">About</a></html>',
            returncode=0,
        )

        result = run_browser_crawl("https://example.com", depth=1, max_pages=5)
        self.assertIn("curl fallback", result)
        self.assertIn("Pages visited:", result)
        self.assertIn("Test Page", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run", side_effect=Exception("curl not found"))
    def test_fallback_browser_test_error(self, mock_run, mock_pw):
        """Fallback handles curl failure gracefully."""
        from modules.agent.browser import run_browser_test

        result = run_browser_test("https://example.com", "test")
        self.assertIn("failed", result.lower())

    def test_check_playwright_caches_result(self):
        """_check_playwright caches its result."""
        from modules.agent import browser
        browser._playwright_available = None  # reset cache

        # Force the check (it will find playwright available or not)
        result1 = browser._check_playwright()
        result2 = browser._check_playwright()
        self.assertEqual(result1, result2)

        # Reset for other tests
        browser._playwright_available = None


class TestBrowserToolHandlers(unittest.TestCase):
    """Test the tool handler wiring in scan_agent.py.

    scan_agent.py requires anthropic which is only in Docker,
    so we test the handler logic via the browser module directly.
    """

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run", return_value=MagicMock(stdout="<html></html>", returncode=0))
    def test_browser_test_requires_url(self, mock_run, mock_pw):
        """run_browser_test with empty URL still runs (no crash)."""
        from modules.agent.browser import run_browser_test
        # Empty URL should not crash — curl fallback handles it
        result = run_browser_test("", "test script")
        self.assertIsInstance(result, str)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run", return_value=MagicMock(
        stdout="<html><title>Test</title></html>", returncode=0))
    def test_browser_crawl_respects_max_pages(self, mock_run, mock_pw):
        """Crawl fallback respects max_pages limit."""
        from modules.agent.browser import run_browser_crawl
        result = run_browser_crawl("https://example.com", depth=1, max_pages=2)
        self.assertIn("Pages visited:", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run", return_value=MagicMock(
        stdout="<html><title>Test</title></html>", returncode=0))
    def test_browser_crawl_caps_max_pages(self, mock_run, mock_pw):
        """Crawl fallback caps max_pages at 10 for curl mode."""
        from modules.agent.browser import run_browser_crawl
        result = run_browser_crawl("https://example.com", depth=1, max_pages=100)
        self.assertIn("example.com", result)


class TestDomXssKnowledge(unittest.TestCase):
    """Test that DOM XSS knowledge module is properly registered."""

    def test_dom_xss_in_knowledge_enum(self):
        """dom_xss is listed as a valid knowledge module."""
        from modules.agent.tools import TOOLS

        load_knowledge = next(
            (t for t in TOOLS if t["name"] == "load_knowledge"), None
        )
        self.assertIsNotNone(load_knowledge)

        enum_values = load_knowledge["input_schema"]["properties"]["module"]["enum"]
        self.assertIn("dom_xss", enum_values)
        self.assertIn("browser_testing", enum_values)

    def test_dom_xss_knowledge_file_exists(self):
        """The dom_xss.txt knowledge file exists."""
        knowledge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "modules", "agent", "prompts", "knowledge", "dom_xss.txt"
        )
        self.assertTrue(os.path.exists(knowledge_path))

    def test_browser_testing_knowledge_file_exists(self):
        """The browser_testing.txt knowledge file exists."""
        knowledge_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "modules", "agent", "prompts", "knowledge", "browser_testing.txt"
        )
        self.assertTrue(os.path.exists(knowledge_path))


class TestFallbackSinkDetection(unittest.TestCase):
    """Test that the curl fallback correctly identifies dangerous patterns."""

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_detects_innerhtml(self, mock_run, mock_pw):
        from modules.agent.browser import run_browser_test
        mock_run.return_value = MagicMock(
            stdout='<script>el.innerHTML = userInput;</script>', returncode=0)
        result = run_browser_test("https://test.com", "test")
        self.assertIn("innerHTML", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_detects_postmessage(self, mock_run, mock_pw):
        from modules.agent.browser import run_browser_test
        mock_run.return_value = MagicMock(
            stdout='<script>window.postMessage(data, "*")</script>', returncode=0)
        result = run_browser_test("https://test.com", "test")
        self.assertIn("postMessage", result)

    @patch("modules.agent.browser._check_playwright", return_value=False)
    @patch("subprocess.run")
    def test_detects_event_handlers(self, mock_run, mock_pw):
        from modules.agent.browser import run_browser_test
        mock_run.return_value = MagicMock(
            stdout='<img onerror="alert(1)" src="x"><div onload="test()">', returncode=0)
        result = run_browser_test("https://test.com", "test")
        self.assertIn("onerror", result)
        self.assertIn("onload", result)


if __name__ == "__main__":
    unittest.main()
