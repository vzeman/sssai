"""Post-processing finding verification to reduce false positives.

After the scan agent generates its report, this module re-tests each finding
using targeted HTTP requests to confirm or reject the vulnerability.

Safety: NEVER uses destructive payloads (DELETE, DROP, UPDATE, INSERT, ALTER).
Only uses read-only verification techniques.
"""

import logging
import time

import httpx

log = logging.getLogger(__name__)

# Maximum time to spend on verification phase (seconds)
MAX_VERIFICATION_TIME = 120
# Delay between verification requests to respect rate limits
REQUEST_DELAY = 0.5


def verify_findings(report: dict, target: str, scan_id: str) -> dict:
    """Verify each finding in the report and add verification metadata.

    Returns the modified report with verification_status and confidence added.
    """
    findings = report.get("findings", [])
    if not findings:
        return report

    log.info("Scan %s: starting finding verification for %d findings", scan_id, len(findings))
    start = time.time()
    verified_count = 0
    demoted_count = 0

    client = httpx.Client(timeout=10, follow_redirects=True, verify=False)

    try:
        for finding in findings:
            if time.time() - start > MAX_VERIFICATION_TIME:
                log.info("Scan %s: verification time limit reached", scan_id)
                break

            category = (finding.get("category") or "").lower()
            title = (finding.get("title") or "").lower()
            urls = finding.get("affected_urls") or []

            verifier = _get_verifier(category, title)
            if not verifier:
                finding["verification_status"] = "unverified"
                finding["verification_note"] = "No automated verification available for this finding type"
                continue

            try:
                result = verifier(client, finding, urls, target)
                finding["verification_status"] = result["status"]
                finding["verification_note"] = result["note"]
                finding["confidence"] = result.get("confidence", finding.get("confidence", 50))

                if result["status"] == "confirmed":
                    verified_count += 1
                elif result["status"] == "false_positive":
                    demoted_count += 1
                    finding["original_severity"] = finding.get("severity")
                    finding["severity"] = "info"

                time.sleep(REQUEST_DELAY)

            except Exception as e:
                log.warning("Verification failed for finding '%s': %s", finding.get("title", "?"), e)
                finding["verification_status"] = "unverified"
                finding["verification_note"] = f"Verification error: {e}"

    finally:
        client.close()

    report["verification_summary"] = {
        "total": len(findings),
        "confirmed": verified_count,
        "demoted": demoted_count,
        "unverified": len(findings) - verified_count - demoted_count,
        "duration_seconds": round(time.time() - start, 1),
    }

    log.info(
        "Scan %s: verification complete — %d confirmed, %d demoted, %d unverified",
        scan_id, verified_count, demoted_count,
        len(findings) - verified_count - demoted_count,
    )
    return report


def _get_verifier(category: str, title: str):
    """Return the appropriate verification function for a finding type."""
    # Map categories and title keywords to verifiers
    if "sql" in category or "sqli" in category or "sql injection" in title:
        return _verify_sqli
    if "xss" in category or "cross-site scripting" in title or "xss" in title:
        return _verify_xss_reflected
    if "cors" in category or "cors" in title:
        return _verify_cors
    if "header" in category or "missing" in title and "header" in title:
        return _verify_missing_header
    if "cookie" in category or "cookie" in title:
        return _verify_cookie_flags
    if "redirect" in category or "open redirect" in title:
        return _verify_open_redirect
    if "ssl" in category or "tls" in category or "certificate" in title:
        return _verify_ssl
    if "information" in category or "disclosure" in title or "exposed" in title:
        return _verify_info_disclosure
    return None


# ─── Verification Functions ───────────────────────────────────────────

def _verify_sqli(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify SQL injection using safe, read-only boolean-based blind testing."""
    test_url = urls[0] if urls else target

    # Find the query parameter to test
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(test_url)
    params = parse_qs(parsed.query)

    if not params:
        return {"status": "unverified", "note": "No query parameters to test", "confidence": 30}

    for param_name, param_values in params.items():
        original_value = param_values[0] if param_values else "test"

        # Test 1: Boolean-based — true condition vs false condition
        true_payload = f"{original_value}' OR '1'='1"
        false_payload = f"{original_value}' OR '1'='2"

        try:
            true_params = {**{k: v[0] for k, v in params.items()}, param_name: true_payload}
            false_params = {**{k: v[0] for k, v in params.items()}, param_name: false_payload}

            true_url = urlunparse(parsed._replace(query=urlencode(true_params)))
            false_url = urlunparse(parsed._replace(query=urlencode(false_params)))

            true_resp = client.get(true_url)
            time.sleep(REQUEST_DELAY)
            false_resp = client.get(false_url)

            # Check for SQL error messages in either response
            for resp in [true_resp, false_resp]:
                body = resp.text.lower()
                sql_errors = ["sql syntax", "mysql", "ora-", "postgresql", "sqlite", "odbc", "unclosed quotation"]
                if any(err in body for err in sql_errors):
                    return {
                        "status": "confirmed",
                        "note": f"SQL error message detected in response for parameter '{param_name}'",
                        "confidence": 90,
                    }

            # Check if responses differ significantly (boolean blind)
            len_diff = abs(len(true_resp.text) - len(false_resp.text))
            if len_diff > 100 and true_resp.status_code == false_resp.status_code:
                return {
                    "status": "confirmed",
                    "note": f"Boolean blind SQLi detected: {len_diff} byte difference between true/false conditions on '{param_name}'",
                    "confidence": 75,
                }

            # Same response = likely false positive (parameter not influencing query)
            if len_diff < 10:
                return {
                    "status": "false_positive",
                    "note": f"No response difference between true/false conditions on '{param_name}' — parameter does not influence SQL query",
                    "confidence": 85,
                }

        except Exception as e:
            log.debug("SQLi verification error for %s: %s", param_name, e)

    return {"status": "unverified", "note": "Could not conclusively verify", "confidence": 40}


def _verify_xss_reflected(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify reflected XSS by checking if a unique canary is reflected unescaped."""
    test_url = urls[0] if urls else target
    canary = "sssai7x3test"  # Unique string that won't appear naturally

    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(test_url)
    params = parse_qs(parsed.query)

    if not params:
        return {"status": "unverified", "note": "No query parameters to test", "confidence": 30}

    for param_name in params:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param_name] = f"<script>{canary}</script>"
        test_url_mod = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = client.get(test_url_mod)
            if f"<script>{canary}</script>" in resp.text:
                return {
                    "status": "confirmed",
                    "note": f"Reflected XSS confirmed: script tag reflected unescaped in '{param_name}'",
                    "confidence": 95,
                }
            if canary in resp.text:
                return {
                    "status": "likely",
                    "note": f"Canary reflected but HTML-encoded in '{param_name}' — potential DOM XSS",
                    "confidence": 50,
                }
        except Exception:
            pass

    return {"status": "false_positive", "note": "Payload not reflected in response", "confidence": 70}


def _verify_cors(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify CORS misconfiguration by sending request with evil Origin."""
    test_url = urls[0] if urls else target

    try:
        resp = client.get(test_url, headers={"Origin": "https://evil-attacker.com"})
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == "*":
            return {
                "status": "confirmed",
                "note": "Access-Control-Allow-Origin: * (wildcard) — allows any origin",
                "confidence": 95,
            }
        if "evil-attacker.com" in acao:
            return {
                "status": "confirmed",
                "note": f"Origin reflected: ACAO={acao} — accepts arbitrary origins",
                "confidence": 95,
            }
        if not acao:
            return {
                "status": "false_positive",
                "note": "No Access-Control-Allow-Origin header returned for cross-origin request",
                "confidence": 80,
            }
        return {
            "status": "likely",
            "note": f"ACAO header present ({acao}) but does not reflect arbitrary origin",
            "confidence": 40,
        }
    except Exception as e:
        return {"status": "unverified", "note": f"Request failed: {e}", "confidence": 20}


def _verify_missing_header(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify that a security header is actually missing."""
    test_url = urls[0] if urls else target
    title = (finding.get("title") or "").lower()

    # Determine which header to check
    header_checks = {
        "strict-transport": "strict-transport-security",
        "hsts": "strict-transport-security",
        "content-security": "content-security-policy",
        "csp": "content-security-policy",
        "x-frame": "x-frame-options",
        "x-content-type": "x-content-type-options",
        "referrer": "referrer-policy",
        "permissions": "permissions-policy",
    }

    target_header = None
    for keyword, header_name in header_checks.items():
        if keyword in title:
            target_header = header_name
            break

    if not target_header:
        return {"status": "unverified", "note": "Could not determine which header to check", "confidence": 30}

    try:
        resp = client.get(test_url)
        if target_header in [h.lower() for h in resp.headers.keys()]:
            return {
                "status": "false_positive",
                "note": f"Header '{target_header}' IS present: {resp.headers.get(target_header, '')[:100]}",
                "confidence": 90,
            }
        return {
            "status": "confirmed",
            "note": f"Header '{target_header}' confirmed missing from response",
            "confidence": 90,
        }
    except Exception as e:
        return {"status": "unverified", "note": f"Request failed: {e}", "confidence": 20}


def _verify_cookie_flags(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify cookie security flag issues."""
    test_url = urls[0] if urls else target
    title = (finding.get("title") or "").lower()

    try:
        resp = client.get(test_url)
        cookies = resp.headers.get_list("set-cookie")

        if not cookies:
            return {
                "status": "false_positive",
                "note": "No Set-Cookie headers in response",
                "confidence": 75,
            }

        issues = []
        for cookie in cookies:
            cookie_lower = cookie.lower()
            if "httponly" not in cookie_lower and "httponly" in title:
                issues.append(f"Missing HttpOnly: {cookie[:50]}")
            if "secure" not in cookie_lower and "secure" in title:
                issues.append(f"Missing Secure: {cookie[:50]}")
            if "samesite=none" in cookie_lower and "samesite" in title:
                issues.append(f"SameSite=None: {cookie[:50]}")

        if issues:
            return {
                "status": "confirmed",
                "note": f"Cookie flag issue confirmed: {'; '.join(issues[:3])}",
                "confidence": 90,
            }
        return {
            "status": "false_positive",
            "note": "Cookie flags appear correct",
            "confidence": 70,
        }
    except Exception as e:
        return {"status": "unverified", "note": f"Request failed: {e}", "confidence": 20}


def _verify_open_redirect(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify open redirect by following the redirect chain."""
    test_url = urls[0] if urls else target

    try:
        # Don't follow redirects — check where it goes
        no_follow = httpx.Client(timeout=10, follow_redirects=False, verify=False)
        try:
            resp = no_follow.get(test_url)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                from urllib.parse import urlparse
                parsed = urlparse(location)
                target_domain = urlparse(target).netloc
                if parsed.netloc and parsed.netloc != target_domain:
                    return {
                        "status": "confirmed",
                        "note": f"Open redirect confirmed: redirects to external domain {parsed.netloc}",
                        "confidence": 90,
                    }
            return {
                "status": "false_positive",
                "note": "No external redirect detected",
                "confidence": 70,
            }
        finally:
            no_follow.close()
    except Exception as e:
        return {"status": "unverified", "note": f"Request failed: {e}", "confidence": 20}


def _verify_ssl(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """SSL/TLS issues are best verified by the scanner tools — mark as likely."""
    return {
        "status": "likely",
        "note": "SSL/TLS findings require specialized tools for full verification",
        "confidence": 60,
    }


def _verify_info_disclosure(client: httpx.Client, finding: dict, urls: list, target: str) -> dict:
    """Verify information disclosure by re-fetching and checking for sensitive data."""
    test_url = urls[0] if urls else target
    evidence = (finding.get("evidence") or "").strip()

    if not evidence:
        return {"status": "unverified", "note": "No evidence to verify against", "confidence": 30}

    try:
        resp = client.get(test_url)
        # Check if the specific evidence string appears in the response
        if evidence[:50] in resp.text:
            return {
                "status": "confirmed",
                "note": "Sensitive information confirmed present in response",
                "confidence": 85,
            }
        return {
            "status": "false_positive",
            "note": "Evidence string not found in current response",
            "confidence": 65,
        }
    except Exception as e:
        return {"status": "unverified", "note": f"Request failed: {e}", "confidence": 20}
