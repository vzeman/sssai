"""
Cross-scan memory with per-tenant isolation and retrieval-augmented planning (#174).

Two public entry points:
  - recall_for_planning(scan_context, top_k=5) — called from adapt_plan handler
    to pull in prior experience on similar target classes
  - auto_store_scan_summary(scan_id, user_id, target, scan_type, report) — called
    from the worker after a scan completes to persist a structured summary

Storage: Postgres `scan_memory` table. User_id is the isolation key — no
memory is ever returned across users.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Iterable

log = logging.getLogger(__name__)

_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://scanner:scanner@postgres:5432/scanner",
)

# Minimum technology-overlap ratio required to include a memory in recall.
_MIN_TECH_OVERLAP = 0.25


# ── Database helpers ────────────────────────────────────────────────────────

def _get_engine():
    try:
        from sqlalchemy import create_engine
        return create_engine(_DB_URL, pool_pre_ping=True)
    except Exception as e:
        log.warning("Memory DB unavailable: %s", e)
        return None


def _ensure_schema(engine) -> None:
    """Idempotently ensure the scan_memory table and the user_id column exist."""
    from sqlalchemy import text
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_memory (
                id SERIAL PRIMARY KEY,
                content TEXT NOT NULL,
                memory_type VARCHAR(50) NOT NULL DEFAULT 'guide',
                tags TEXT[] DEFAULT '{}',
                metadata JSONB DEFAULT '{}',
                scan_id VARCHAR(100),
                target VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        # Additive migrations for #174
        conn.execute(text("ALTER TABLE scan_memory ADD COLUMN IF NOT EXISTS user_id VARCHAR(100)"))
        conn.execute(text("ALTER TABLE scan_memory ADD COLUMN IF NOT EXISTS target_class VARCHAR(200)"))
        conn.execute(text("ALTER TABLE scan_memory ADD COLUMN IF NOT EXISTS scan_type VARCHAR(50)"))
        conn.execute(text("ALTER TABLE scan_memory ADD COLUMN IF NOT EXISTS technologies TEXT[]"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scan_memory_user_id ON scan_memory(user_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scan_memory_target_class ON scan_memory(target_class)"))


# ── Target-class derivation ────────────────────────────────────────────────

def _normalize_tech(tech: str) -> str:
    return tech.lower().strip().replace(" ", "_")[:40]


def derive_target_class(technologies: Iterable[str]) -> str:
    """Sort + normalize + join tech list — deterministic identifier."""
    seen: list[str] = []
    for t in technologies or []:
        n = _normalize_tech(str(t))
        if n and n not in seen:
            seen.append(n)
    seen.sort()
    return "+".join(seen[:8])  # cap at 8 for sane keys


def _extract_technologies(attack_surface: dict | None) -> list[str]:
    if not attack_surface:
        return []
    techs = attack_surface.get("technologies") or []
    out: list[str] = []
    for t in techs:
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, dict):
            name = t.get("name") or t.get("tech") or t.get("technology")
            if name:
                out.append(str(name))
    return out


# ── Recall ─────────────────────────────────────────────────────────────────

def recall_for_planning(scan_context: dict | None, top_k: int = 5) -> str:
    """Return a formatted 'Prior experience' block for injection into adapt_plan,
    or an empty string if no memory is available / recall fails / no user_id.

    Per-tenant strict isolation: fails closed if user_id is missing.
    """
    if not scan_context:
        return ""
    user_id = scan_context.get("user_id") or scan_context.get("_user_id")
    if not user_id:
        return ""  # Fail closed — never leak across tenants

    attack_surface = scan_context.get("_attack_surface") or {}
    technologies = _extract_technologies(attack_surface)
    scan_type = scan_context.get("scan_type", "")

    if not technologies:
        return ""

    engine = _get_engine()
    if not engine:
        return ""
    try:
        _ensure_schema(engine)
        from sqlalchemy import text
        target_class = derive_target_class(technologies)

        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT content, memory_type, technologies, target_class, scan_type,
                       created_at, metadata
                FROM scan_memory
                WHERE user_id = :user_id
                  AND memory_type = 'scan_summary'
                ORDER BY created_at DESC
                LIMIT 100
            """), {"user_id": user_id}).fetchall()

        if not rows:
            return ""

        # Score: tech overlap * 0.7 + scan-type match * 0.2 + exact-class * 0.1
        scored: list[tuple[float, dict]] = []
        req_tech_set = {_normalize_tech(t) for t in technologies}
        for row in rows:
            row_tech = set((row[2] or []))
            if not req_tech_set:
                overlap = 0.0
            else:
                overlap = len(req_tech_set & row_tech) / len(req_tech_set)
            if overlap < _MIN_TECH_OVERLAP:
                continue
            score = overlap * 0.7
            if row[4] == scan_type:
                score += 0.2
            if row[3] == target_class:
                score += 0.1
            scored.append((score, {
                "content": row[0],
                "memory_type": row[1],
                "technologies": list(row_tech),
                "target_class": row[3],
                "scan_type": row[4],
                "created_at": row[5].isoformat() if row[5] else None,
                "metadata": row[6] or {},
                "score": round(score, 3),
            }))

        scored.sort(key=lambda kv: kv[0], reverse=True)
        top = [entry for _, entry in scored[:top_k]]
        if not top:
            return ""

        lines = [
            "## Prior experience on similar targets",
            f"(auto-recalled {len(top)} relevant memories for target_class={target_class})",
            "",
        ]
        for i, mem in enumerate(top, 1):
            lines.append(f"### {i}. score={mem['score']} scan_type={mem['scan_type']}")
            lines.append(f"Technologies: {', '.join(mem['technologies'][:8])}")
            lines.append(mem["content"][:1200])
            lines.append("")
        return "\n".join(lines)

    except Exception as e:
        log.warning("recall_for_planning failed: %s", e)
        return ""


# ── Auto-store ─────────────────────────────────────────────────────────────

def _summarize_findings(findings: list[dict]) -> list[dict]:
    """Keep only non-PII structural bits for persistence."""
    summary = []
    for f in (findings or [])[:50]:
        if not isinstance(f, dict):
            continue
        summary.append({
            "title":    f.get("title") or f.get("name") or "",
            "severity": f.get("severity", "unknown"),
            "category": f.get("category") or f.get("cwe") or "",
            "confirmed": (f.get("verification_status") == "confirmed"),
            "owasp":    f.get("owasp", ""),
        })
    return summary


def _extract_working_payloads(findings: list[dict]) -> list[str]:
    payloads: list[str] = []
    for f in (findings or [])[:50]:
        if not isinstance(f, dict):
            continue
        p = f.get("poc_payload") or f.get("payload") or f.get("evidence_snippet")
        if p and isinstance(p, str) and len(p) < 500:
            payloads.append(p)
    return payloads[:20]


def auto_store_scan_summary(
    scan_id: str,
    user_id: str | None,
    target: str,
    scan_type: str,
    report: dict,
) -> bool:
    """Persist a structured summary of a completed scan for future recall.

    Idempotent: if a summary for this scan_id already exists, it is replaced.
    Returns True if stored, False otherwise.
    """
    if not user_id:
        log.info("auto_store_scan_summary skipped for scan %s: no user_id", scan_id)
        return False
    findings = report.get("findings") or []
    if not findings:
        log.info("auto_store_scan_summary skipped for scan %s: no findings", scan_id)
        return False

    engine = _get_engine()
    if not engine:
        return False

    try:
        _ensure_schema(engine)
        from sqlalchemy import text

        attack_surface = report.get("attack_surface") or {}
        technologies = _extract_technologies(attack_surface)
        target_class = derive_target_class(technologies)

        payload = {
            "target":             target,
            "target_class":       target_class,
            "technologies":       technologies[:20],
            "scan_type":          scan_type,
            "findings_summary":   _summarize_findings(findings),
            "working_payloads":   _extract_working_payloads(findings),
            "risk_score":         report.get("risk_score", 0),
            "finding_count":      len(findings),
            "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        content = json.dumps(payload, sort_keys=True, default=str)

        with engine.begin() as conn:
            # Idempotency: remove prior summary for this scan_id
            conn.execute(text(
                "DELETE FROM scan_memory WHERE scan_id = :sid AND memory_type = 'scan_summary'"
            ), {"sid": scan_id})
            conn.execute(text("""
                INSERT INTO scan_memory
                    (content, memory_type, tags, metadata, scan_id, target,
                     user_id, target_class, scan_type, technologies)
                VALUES
                    (:content, 'scan_summary', :tags, :metadata, :scan_id, :target,
                     :user_id, :target_class, :scan_type, :techs)
            """), {
                "content":      content,
                "tags":         [scan_type, target_class][:10],
                "metadata":     json.dumps({"auto_stored": True}),
                "scan_id":      scan_id,
                "target":       target,
                "user_id":      user_id,
                "target_class": target_class,
                "scan_type":    scan_type,
                "techs":        [_normalize_tech(t) for t in technologies[:20]],
            })
        log.info("Stored scan_summary memory for scan %s (user=%s, class=%s)",
                 scan_id, user_id, target_class)
        return True

    except Exception as e:
        log.warning("auto_store_scan_summary failed for scan %s: %s", scan_id, e)
        return False
