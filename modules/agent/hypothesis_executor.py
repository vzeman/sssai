"""
Parallel hypothesis-branch executor (Issue #168).

Forks the scan into N parallel attack-hypothesis branches after the
discovery + attack-surface phase. Each branch runs a focused sub-agent
investigation with a narrow context and returns findings.

Leverages the existing sub-agent machinery (_handle_subagent) so we get
tool access, token tracking, and activity logging for free.

Concurrency is via ThreadPoolExecutor (not asyncio) because the
underlying Anthropic SDK call + tool dispatch is synchronous. We cap
concurrent branches to HYPOTHESIS_BRANCH_CONCURRENCY (default 3) to
avoid hammering the API rate limit.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

log = logging.getLogger(__name__)


# ── Hypothesis generation ──────────────────────────────────────────────────

def _has_forms(surface: dict) -> bool:
    return bool(surface.get("forms")) or bool(surface.get("login_forms"))


def _has_apis(surface: dict) -> bool:
    return bool(surface.get("api_endpoints")) or bool(surface.get("apis"))


def _has_auth(surface: dict) -> bool:
    return bool(surface.get("auth_mechanisms")) or bool(surface.get("login_forms"))


def _has_graphql(surface: dict) -> bool:
    return bool(surface.get("graphql_endpoints"))


def _has_file_ops(surface: dict) -> bool:
    text = str(surface).lower()
    return any(k in text for k in ("upload", "file", "download", "attachment"))


def fork_hypotheses(attack_surface: dict, scan_type: str = "security") -> list[dict]:
    """Derive concrete hypothesis branches from the attack surface.

    Returns a list of hypothesis dicts with {id, title, vulnerability_class,
    focus, task_instructions}. Only returns branches whose prerequisites are
    satisfied by the surface — never fabricates hypotheses.
    """
    surface = attack_surface or {}
    hypotheses: list[dict] = []

    if _has_forms(surface):
        hypotheses.append({
            "id": "h_sqli_forms",
            "title": "SQL injection in discovered forms",
            "vulnerability_class": "sqli",
            "focus": "forms",
            "task_instructions": (
                "Test every discovered form for SQL injection using boolean, "
                "time-based, and error-based oracle techniques. For each form "
                "field, use sweep_payloads with vulnerability_class='sqli_boolean' "
                "and 'sqli_time'. Record hits with payload, response, and reproduction steps."
            ),
        })
        hypotheses.append({
            "id": "h_xss_forms",
            "title": "Reflected XSS in discovered forms",
            "vulnerability_class": "xss",
            "focus": "forms",
            "task_instructions": (
                "Test every discovered form for reflected XSS. For each input "
                "field use sweep_payloads with vulnerability_class='xss_reflected'. "
                "Confirm payload reflection is unescaped and record execution context."
            ),
        })

    if _has_apis(surface):
        hypotheses.append({
            "id": "h_idor_api",
            "title": "IDOR in discovered API endpoints",
            "vulnerability_class": "idor",
            "focus": "api_endpoints",
            "task_instructions": (
                "Test discovered API endpoints for Insecure Direct Object "
                "References. For endpoints with numeric or UUID IDs, try "
                "adjacent IDs, other users' IDs, and verify horizontal access "
                "control. Report any response where a user can access another "
                "user's data."
            ),
        })
        hypotheses.append({
            "id": "h_api_auth",
            "title": "Missing auth on API endpoints",
            "vulnerability_class": "auth_bypass",
            "focus": "api_endpoints",
            "task_instructions": (
                "For each discovered API endpoint, send requests WITHOUT auth "
                "headers and compare to authenticated response. Flag endpoints "
                "that leak data without auth."
            ),
        })

    if _has_graphql(surface):
        hypotheses.append({
            "id": "h_graphql_introspection",
            "title": "GraphQL introspection + auth bypass",
            "vulnerability_class": "graphql",
            "focus": "graphql_endpoints",
            "task_instructions": (
                "For each discovered GraphQL endpoint run sweep_payloads with "
                "vulnerability_class='graphql_introspection'. If introspection "
                "succeeds, map the schema and test for auth-bypass on sensitive "
                "queries/mutations."
            ),
        })

    if _has_auth(surface):
        hypotheses.append({
            "id": "h_session_mgmt",
            "title": "Session management and auth bypass",
            "vulnerability_class": "auth_bypass",
            "focus": "auth",
            "task_instructions": (
                "Test session management: cookie flags (HttpOnly, Secure, "
                "SameSite), session fixation, concurrent sessions, logout "
                "behavior, token expiration. For OAuth/JWT, test alg "
                "confusion and none-alg. Use sweep_payloads with "
                "vulnerability_class='jwt_tamper' where applicable."
            ),
        })

    # Universal hypotheses — always worth checking
    hypotheses.append({
        "id": "h_ssrf",
        "title": "SSRF via fetch endpoints",
        "vulnerability_class": "ssrf",
        "focus": "url_params",
        "task_instructions": (
            "Scan URL parameters that accept external URLs (webhook, image, "
            "redirect, callback, fetch). Use sweep_payloads with "
            "vulnerability_class='ssrf_internal' against each. Report any "
            "response indicating internal resource access."
        ),
    })

    hypotheses.append({
        "id": "h_path_traversal",
        "title": "Path traversal / LFI",
        "vulnerability_class": "path_traversal",
        "focus": "file_params",
        "task_instructions": (
            "Identify parameters that might reference files (path, file, "
            "page, include, template, lang). Use sweep_payloads with "
            "vulnerability_class='path_traversal' on each. Report responses "
            "containing /etc/passwd or win.ini markers."
        ),
    })

    # For aggressive scan types, add more
    if scan_type in ("pentest", "full"):
        if _has_file_ops(surface):
            hypotheses.append({
                "id": "h_file_upload",
                "title": "File upload vulnerabilities",
                "vulnerability_class": "file_upload",
                "focus": "file_ops",
                "task_instructions": (
                    "Test file upload endpoints with harmless text files. "
                    "Check: extension filtering, content-type validation, "
                    "filename handling (null byte, traversal), stored location "
                    "discoverability, MIME sniffing, size limits. Never upload "
                    "executables."
                ),
            })
        hypotheses.append({
            "id": "h_open_redirect",
            "title": "Open redirect",
            "vulnerability_class": "open_redirect",
            "focus": "redirect_params",
            "task_instructions": (
                "Identify parameters named url, redirect, next, continue, "
                "return, callback. Use sweep_payloads with "
                "vulnerability_class='open_redirect' on each."
            ),
        })

    return hypotheses


# ── Branch execution ──────────────────────────────────────────────────────

def _run_branch(
    hypothesis: dict,
    scan_context: dict,
    subagent_dispatcher: Callable[[str, dict, dict], str],
) -> dict:
    """Run a single hypothesis branch via the pentester sub-agent.

    Returns a dict summarizing what the branch found.
    """
    started = time.time()
    try:
        target = scan_context.get("target", "")
        surface = scan_context.get("_attack_surface") or {}

        # Narrow context for this branch: only the pieces of the surface
        # relevant to the hypothesis's focus.
        narrow_context = {
            "hypothesis": hypothesis["title"],
            "vulnerability_class": hypothesis["vulnerability_class"],
            "target": target,
            "focus": hypothesis["focus"],
        }
        focus_key_map = {
            "forms":            ["forms", "login_forms"],
            "api_endpoints":    ["api_endpoints", "apis"],
            "graphql_endpoints": ["graphql_endpoints"],
            "auth":             ["auth_mechanisms", "login_forms"],
            "url_params":       ["api_endpoints", "apis"],
            "file_params":      ["api_endpoints", "apis"],
            "file_ops":         ["api_endpoints", "file_uploads"],
            "redirect_params":  ["api_endpoints", "apis"],
        }
        for k in focus_key_map.get(hypothesis["focus"], []):
            if surface.get(k):
                narrow_context[k] = surface[k]

        task = (
            f"Investigate ONLY the following hypothesis. Do not expand scope.\n\n"
            f"Hypothesis: {hypothesis['title']}\n"
            f"Vulnerability class: {hypothesis['vulnerability_class']}\n"
            f"Instructions: {hypothesis['task_instructions']}\n\n"
            f"Return a short findings summary as JSON: "
            f"{{\"branch_id\": \"{hypothesis['id']}\", \"findings\": [...], \"notes\": \"...\"}}"
        )

        context_str = str(narrow_context)[:8000]
        import json as _json
        context_str = _json.dumps(narrow_context, default=str)[:8000]

        result = subagent_dispatcher(
            "pentester",
            {"task": task, "context": context_str},
            scan_context,
        )

        return {
            "branch_id":   hypothesis["id"],
            "title":       hypothesis["title"],
            "status":      "completed",
            "duration_s":  round(time.time() - started, 2),
            "raw_output":  (result or "")[:20_000],
        }
    except Exception as e:
        log.warning("Hypothesis branch %s failed: %s", hypothesis.get("id"), e)
        return {
            "branch_id": hypothesis.get("id", "unknown"),
            "title":     hypothesis.get("title", ""),
            "status":    "failed",
            "error":     f"{type(e).__name__}: {e}",
            "duration_s": round(time.time() - started, 2),
        }


def run_parallel(
    hypotheses: list[dict],
    scan_context: dict,
    subagent_dispatcher: Callable[[str, dict, dict], str],
    concurrency: int | None = None,
    max_branches: int | None = None,
) -> dict:
    """Execute hypothesis branches in parallel.

    subagent_dispatcher is passed in (rather than imported) to avoid circular
    imports with scan_agent._handle_subagent.
    """
    if not hypotheses:
        return {"branches": [], "count": 0, "summary": "No hypotheses generated"}

    max_cap = int(os.environ.get("HYPOTHESIS_MAX_BRANCHES", max_branches or 6))
    hypotheses = hypotheses[:max_cap]

    conc = int(concurrency or os.environ.get("HYPOTHESIS_BRANCH_CONCURRENCY", "3"))
    conc = max(1, min(conc, 6))

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=conc) as pool:
        futures = {
            pool.submit(_run_branch, h, scan_context, subagent_dispatcher): h
            for h in hypotheses
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    return {
        "branches": results,
        "count": len(results),
        "concurrency": conc,
        "summary": (
            f"Ran {len(results)} hypothesis branches with concurrency={conc}. "
            f"completed={sum(1 for r in results if r['status'] == 'completed')}, "
            f"failed={sum(1 for r in results if r['status'] == 'failed')}"
        ),
    }
