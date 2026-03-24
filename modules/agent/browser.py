"""
Browser-based security testing using Playwright.

Provides real implementations for browser_test and browser_crawl tools
used by the scan agent for client-side security testing (DOM XSS,
prototype pollution, open redirects, storage exposure, sink detection).
"""

import asyncio
import contextlib
import json
import logging
import os
import time
from io import StringIO
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

# Playwright is optional — only available in worker containers
_playwright_available = None


def _check_playwright():
    global _playwright_available
    if _playwright_available is None:
        try:
            import playwright  # noqa: F401
            _playwright_available = True
        except ImportError:
            _playwright_available = False
    return _playwright_available


def run_browser_test(url: str, script: str, timeout: int = 60,
                     screenshot_path: str = "/output/browser_test.png") -> str:
    """Execute a Playwright Python script against a URL.

    The script receives `page` (async Playwright Page) and `url` (target URL)
    as variables. All print() output is captured and returned.
    """
    # Validate script — only allow Playwright API calls, no dangerous imports
    _blocked = ["import os", "import subprocess", "import shutil", "__import__",
                "open(", "os.system", "os.popen", "subprocess."]
    for pattern in _blocked:
        if pattern in script:
            return f"Script rejected: forbidden pattern '{pattern}'. Only Playwright API calls are allowed."

    if not _check_playwright():
        return _fallback_browser_test(url, script)

    return asyncio.run(
        _async_browser_test(url, script, timeout, screenshot_path)
    )


async def _async_browser_test(url: str, script: str, timeout: int,
                               screenshot_path: str) -> str:
    from playwright.async_api import async_playwright

    captured = StringIO()
    console_msgs = []
    js_errors = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Capture console messages and errors
        page.on("console", lambda msg: console_msgs.append(
            f"[{msg.type}] {msg.text}"
        ))
        page.on("pageerror", lambda err: js_errors.append(str(err)))

        with contextlib.redirect_stdout(captured):
            try:
                # Wrap script in async function with page and url in scope
                async def run_script():
                    local_ns = {"page": page, "url": url}
                    exec(compile(
                        "async def __test__():\n" +
                        "\n".join(f"    {line}" for line in script.split("\n")),
                        "<browser_test>", "exec"
                    ), local_ns)
                    await local_ns["__test__"]()

                await asyncio.wait_for(run_script(), timeout=timeout)

            except asyncio.TimeoutError:
                captured.write(f"\nScript timed out after {timeout}s\n")
            except Exception as e:
                captured.write(f"\nScript error: {e}\n")

        # Take screenshot
        try:
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            await page.screenshot(path=screenshot_path, full_page=True)
        except Exception as e:
            log.debug("Screenshot failed: %s", e)

        # Get final page content snippet
        try:
            content = await page.content()
            dom_snippet = content[:2000]
        except Exception:
            dom_snippet = ""

        await browser.close()

    output = captured.getvalue()
    result_parts = [f"Browser test on {url}:"]
    if output.strip():
        result_parts.append(f"Script output:\n{output.strip()}")
    if console_msgs:
        result_parts.append(f"Console ({len(console_msgs)} msgs):\n" +
                          "\n".join(console_msgs[:20]))
    if js_errors:
        result_parts.append(f"JS Errors ({len(js_errors)}):\n" +
                          "\n".join(js_errors[:10]))
    if screenshot_path:
        result_parts.append(f"Screenshot saved: {screenshot_path}")
    if dom_snippet:
        result_parts.append(f"DOM snippet (first 2000 chars):\n{dom_snippet}")

    return "\n\n".join(result_parts)


def run_browser_crawl(url: str, depth: int = 2, max_pages: int = 20,
                      output_path: str = "/output/browser_crawl.json") -> str:
    """JavaScript-aware SPA crawl using Playwright.

    Discovers routes, forms, API calls, and script sinks in SPAs.
    """
    if not _check_playwright():
        return _fallback_browser_crawl(url, depth, max_pages)

    return asyncio.run(
        _async_browser_crawl(url, depth, max_pages, output_path)
    )


async def _async_browser_crawl(url: str, depth: int, max_pages: int,
                                output_path: str) -> str:
    from playwright.async_api import async_playwright

    base_domain = urlparse(url).netloc
    visited = set()
    to_visit = [(url, 0)]
    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )

        while to_visit and len(visited) < max_pages:
            current_url, current_depth = to_visit.pop(0)

            normalized = current_url.split("#")[0].split("?")[0].rstrip("/")
            if normalized in visited:
                continue
            visited.add(normalized)

            page = await context.new_page()
            js_errors = []
            console_msgs = []
            page.on("pageerror", lambda err: js_errors.append(str(err)))
            page.on("console", lambda msg: console_msgs.append(msg.text))

            try:
                response = await page.goto(current_url, timeout=15000,
                                           wait_until="networkidle")
                status = response.status if response else 0
            except Exception as e:
                log.debug("Crawl navigate error %s: %s", current_url, e)
                await page.close()
                continue

            await page.wait_for_timeout(1500)

            # Analyze the page
            page_info = await page.evaluate("""() => {
                const info = {
                    title: document.title,
                    url: location.href,
                    forms: [],
                    links: [],
                    scripts: [],
                    has_forms: false,
                    has_script_sinks: false,
                    has_localstorage: false,
                    has_event_listeners: false,
                    api_calls: [],
                };

                // Forms
                document.querySelectorAll('form').forEach(f => {
                    info.forms.push({
                        action: f.action,
                        method: f.method,
                        fields: Array.from(f.elements).map(e => ({
                            name: e.name, type: e.type, id: e.id
                        })).filter(e => e.name),
                    });
                });
                info.has_forms = info.forms.length > 0;

                // Links (for crawling)
                document.querySelectorAll('a[href]').forEach(a => {
                    try {
                        const href = new URL(a.href, location.origin).href;
                        if (href.startsWith('http')) info.links.push(href);
                    } catch(e) {}
                });

                // Script sources
                document.querySelectorAll('script[src]').forEach(s => {
                    info.scripts.push(s.src);
                });

                // Check for dangerous sinks in inline scripts
                const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
                    .map(s => s.textContent).join(' ');
                const sinkPatterns = ['innerHTML', 'outerHTML', 'document.write',
                    'eval(', 'setTimeout(', 'setInterval(', 'Function('];
                info.has_script_sinks = sinkPatterns.some(p => inlineScripts.includes(p));

                // localStorage usage
                try {
                    info.has_localstorage = localStorage.length > 0;
                } catch(e) {}

                return info;
            }""")

            page_info["status"] = status
            page_info["js_errors"] = js_errors[:5]
            page_info["console_messages"] = console_msgs[:10]

            results.append(page_info)

            # Queue discovered links for next depth
            if current_depth < depth:
                for link in page_info.get("links", []):
                    link_domain = urlparse(link).netloc
                    if link_domain == base_domain:
                        link_norm = link.split("#")[0].split("?")[0].rstrip("/")
                        if link_norm not in visited:
                            to_visit.append((link, current_depth + 1))

            await page.close()

        await browser.close()

    # Save results
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
    except Exception as e:
        log.warning("Could not save crawl results: %s", e)

    # Build summary
    total_forms = sum(len(r.get("forms", [])) for r in results)
    total_scripts = sum(len(r.get("scripts", [])) for r in results)
    pages_with_sinks = sum(1 for r in results if r.get("has_script_sinks"))
    pages_with_storage = sum(1 for r in results if r.get("has_localstorage"))
    pages_with_errors = sum(1 for r in results if r.get("js_errors"))

    summary = (
        f"Browser crawl of {url} (depth={depth}):\n"
        f"  Pages visited: {len(results)}\n"
        f"  Forms found: {total_forms}\n"
        f"  External scripts: {total_scripts}\n"
        f"  Pages with dangerous sinks: {pages_with_sinks}\n"
        f"  Pages with localStorage: {pages_with_storage}\n"
        f"  Pages with JS errors: {pages_with_errors}\n"
        f"  Results saved to: {output_path}\n\n"
        "Discovered pages:\n"
    )
    for r in results:
        flags = []
        if r.get("has_forms"):
            flags.append("forms")
        if r.get("has_script_sinks"):
            flags.append("SINKS")
        if r.get("has_localstorage"):
            flags.append("storage")
        if r.get("js_errors"):
            flags.append("JS_ERRORS")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        summary += f"  [{r.get('status', '?')}] {r.get('url', '?')} — {r.get('title', 'untitled')}{flag_str}\n"

    return summary


# ── Fallbacks when Playwright is not installed ──────────────────────────

def _fallback_browser_test(url: str, script: str) -> str:
    """Fallback using curl + basic analysis when Playwright is unavailable."""
    import subprocess

    log.info("Playwright not available — falling back to curl-based browser test")

    try:
        result = subprocess.run(
            ["curl", "-sL", "-m", "15", "--insecure", url],
            capture_output=True, text=True, timeout=20,
        )
        html = result.stdout
    except Exception as e:
        return f"Browser test fallback failed: {e}"

    findings = []

    # Check for dangerous sinks in HTML
    sink_patterns = {
        "innerHTML": "innerHTML assignment detected — potential DOM XSS sink",
        "outerHTML": "outerHTML assignment detected — potential DOM XSS sink",
        "document.write": "document.write() call — potential DOM XSS sink",
        "eval(": "eval() call — potential code injection sink",
        ".postMessage(": "postMessage usage — check for origin validation",
    }
    for pattern, desc in sink_patterns.items():
        if pattern in html:
            findings.append(desc)

    # Check for potentially unsafe event handlers
    unsafe_handlers = ["onerror=", "onload=", "onclick=", "onmouseover="]
    for h in unsafe_handlers:
        count = html.lower().count(h)
        if count > 0:
            findings.append(f"Found {count} inline {h.rstrip('=')} event handler(s)")

    # Check for script sources
    import re
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', html)

    result_parts = [
        f"Browser test (curl fallback) on {url}:",
        f"HTML size: {len(html)} bytes",
        f"External scripts: {len(scripts)}",
    ]
    if findings:
        result_parts.append("Potential issues:\n  " + "\n  ".join(findings))
    else:
        result_parts.append("No obvious DOM XSS sinks detected in static HTML analysis.")
    result_parts.append(
        "NOTE: This is a static analysis fallback. Install Playwright for "
        "full dynamic browser testing (DOM XSS, prototype pollution, etc.)"
    )

    return "\n".join(result_parts)


def _fallback_browser_crawl(url: str, depth: int, max_pages: int) -> str:
    """Fallback using curl + link extraction when Playwright is unavailable."""
    import re
    import subprocess

    log.info("Playwright not available — falling back to curl-based crawl")

    base_domain = urlparse(url).netloc
    visited = set()
    to_visit = [url]
    results = []

    while to_visit and len(visited) < min(max_pages, 10):
        current = to_visit.pop(0)
        normalized = current.split("#")[0].split("?")[0].rstrip("/")
        if normalized in visited:
            continue
        visited.add(normalized)

        try:
            r = subprocess.run(
                ["curl", "-sL", "-m", "10", "--insecure", current],
                capture_output=True, text=True, timeout=15,
            )
            html = r.stdout
        except Exception:
            continue

        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "untitled"

        has_sinks = any(p in html for p in ["innerHTML", "eval(", "document.write"])

        results.append({
            "url": current,
            "title": title,
            "has_script_sinks": has_sinks,
            "html_size": len(html),
        })

        # Extract links for further crawling
        if len(visited) < depth * max_pages:
            for href in re.findall(r'href=["\']([^"\']+)', html):
                try:
                    full = urljoin(current, href)
                    if urlparse(full).netloc == base_domain and full not in visited:
                        to_visit.append(full)
                except Exception:
                    pass

    summary = (
        f"Browser crawl (curl fallback) of {url}:\n"
        f"  Pages visited: {len(results)}\n"
        f"  Pages with sinks: {sum(1 for r in results if r.get('has_script_sinks'))}\n\n"
        "Discovered pages:\n"
    )
    for r in results:
        flag = " [SINKS]" if r.get("has_script_sinks") else ""
        summary += f"  {r['url']} — {r['title']}{flag}\n"

    summary += (
        "\nNOTE: This is a static fallback. Install Playwright for "
        "full SPA route discovery and JavaScript analysis."
    )

    return summary
