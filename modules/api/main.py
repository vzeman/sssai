import os
import subprocess

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from modules.api.database import engine, Base
from modules.api.routes import scans, auth, monitors, schedules, notifications, reports, tools, search, campaigns, dashboard, audit, posture, webhooks, export, findings
from modules.infra import get_queue

Base.metadata.create_all(bind=engine)

# Add new User security columns if missing (migration)
try:
    from sqlalchemy import text
    with engine.connect() as conn:
        for col, default in [
            ("is_active", "TRUE"),
            ("failed_attempts", "0"),
            ("locked_until", "NULL"),
            ("last_login", "NULL"),
            ("totp_secret", "NULL"),
            ("totp_enabled", "FALSE"),
        ]:
            try:
                type_map = {
                    "is_active": f"BOOLEAN DEFAULT {default}",
                    "failed_attempts": f"INTEGER DEFAULT {default}",
                    "locked_until": f"TIMESTAMP {default}",
                    "last_login": f"TIMESTAMP {default}",
                    "totp_secret": f"VARCHAR {default}",
                    "totp_enabled": f"BOOLEAN DEFAULT {default}",
                }
                col_type = type_map.get(col, f"VARCHAR {default}")
                conn.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {col_type}"))
            except Exception:
                pass
        conn.commit()
except Exception:
    pass

# Add campaign_id column to scans table if missing (migration)
try:
    from sqlalchemy import text as _text2
    with engine.connect() as conn:
        try:
            conn.execute(_text2("ALTER TABLE scans ADD COLUMN IF NOT EXISTS campaign_id VARCHAR REFERENCES campaigns(id)"))
        except Exception:
            pass
        conn.commit()
except Exception:
    pass

# Add token tracking columns to scans table if missing (migration)
try:
    from sqlalchemy import text as _text
    with engine.connect() as conn:
        for col, col_type in [
            ("total_input_tokens", "INTEGER DEFAULT 0"),
            ("total_output_tokens", "INTEGER DEFAULT 0"),
            ("estimated_cost", "REAL DEFAULT 0.0"),
        ]:
            try:
                conn.execute(_text(f"ALTER TABLE scans ADD COLUMN IF NOT EXISTS {col} {col_type}"))
            except Exception:
                pass
        conn.commit()
except Exception:
    pass

# Add webhook_configs columns if missing (migration)
try:
    from sqlalchemy import text as _wh_text
    with engine.connect() as conn:
        # Create webhook_configs table if it doesn't exist via Base.metadata, but also
        # ensure any new columns are added to existing tables gracefully.
        for col, col_type in [
            ("last_used_at", "TIMESTAMP NULL"),
        ]:
            try:
                conn.execute(_wh_text(f"ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS {col} {col_type}"))
            except Exception:
                pass
        conn.commit()
except Exception:
    pass

# Set up Elasticsearch indices on startup
try:
    from modules.infra import setup_es
    setup_es()
except Exception:
    pass  # ES may not be ready yet; indices will be created on first use

app = FastAPI(
    title="Security Scanner API",
    version="0.2.0",
    description="AI-powered autonomous security scanning, SEO analysis, and compliance monitoring platform",
)

_ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Core routes
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(monitors.router, prefix="/api/monitors", tags=["monitors"])

# New routes
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(search.router, prefix="/api/search", tags=["search"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(dashboard.router, tags=["dashboard"])
app.include_router(audit.router, tags=["audit"])
app.include_router(posture.router, prefix="/api/posture", tags=["posture"])
app.include_router(webhooks.router, prefix="/api/webhooks", tags=["webhooks"])
app.include_router(export.router, prefix="/api/export", tags=["export"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


# ─── Worker logs endpoint (reads from Redis pub/sub or Docker logs) ────
import json as _json
import redis as _redis

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")


@app.get("/api/heartbeat")
def heartbeat_messages():
    """Return recent heartbeat status messages."""
    try:
        r = _redis.from_url(_REDIS_URL)
        raw = r.lrange("heartbeat:messages", -20, -1)
        messages = []
        for item in raw:
            try:
                messages.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
            except Exception:
                pass
        return {"messages": messages}
    except Exception:
        return {"messages": []}


@app.get("/api/logs/worker")
def worker_logs():
    """Return recent worker log lines stored in Redis."""
    try:
        r = _redis.from_url(_REDIS_URL)
        lines = r.lrange("worker:logs", -200, -1)
        return {"logs": "\n".join(l.decode() if isinstance(l, bytes) else l for l in lines)}
    except Exception:
        return {"logs": "Log streaming not available. Check docker compose logs worker."}


@app.get("/api/scans/{scan_id}/activity")
def scan_activity(scan_id: str):
    """Return live scan activity (commands executed, current tool) from Redis."""
    try:
        r = _redis.from_url(_REDIS_URL)
        # Read activity log for this scan
        lines = r.lrange(f"scan:activity:{scan_id}", 0, -1)
        activities = []
        for line in lines:
            try:
                import json as _json
                activities.append(_json.loads(line.decode() if isinstance(line, bytes) else line))
            except Exception:
                activities.append({"message": line.decode() if isinstance(line, bytes) else str(line)})
        return {"scan_id": scan_id, "activities": activities}
    except Exception:
        return {"scan_id": scan_id, "activities": []}


# ─── Chat endpoints (human ↔ agent communication) ───────────────────
import time as _time

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from modules.api.auth import get_current_user
from modules.api.models import User, Scan
from modules.config import AI_MODEL
from modules.api.database import get_db
from sqlalchemy.orm import Session


class ChatMessage(BaseModel):
    message: str
    role: str = "human"  # human or agent


@app.post("/api/scans/{scan_id}/chat")
def send_chat_message(
    scan_id: str,
    body: ChatMessage,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Send a chat message to the AI agent running a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        r = _redis.from_url(_REDIS_URL)
        msg = _json.dumps({
            "role": "human",
            "message": body.message,
            "timestamp": _time.strftime("%H:%M:%S"),
            "ts": _time.time(),
        })
        # Push to chat history (both sides read this)
        r.rpush(f"scan:chat:history:{scan_id}", msg)
        r.expire(f"scan:chat:history:{scan_id}", 86400)

        # ES dual-write
        try:
            from modules.infra.elasticsearch import index_doc
            index_doc("scanner-chat-messages", {
                "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                "user_id": user.id,
                "scan_id": scan_id,
                "role": "human",
                "message": body.message,
                "channel": "scan",
            })
        except Exception:
            pass

        if scan.status in ("running", "queued"):
            # Scan is active — push to inbox so the running agent picks it up
            r.rpush(f"scan:chat:inbox:{scan_id}", msg)
            r.expire(f"scan:chat:inbox:{scan_id}", 86400)
            return {"status": "sent", "mode": "live"}
        else:
            # Scan is finished — answer directly using Claude with report context
            _answer_chat_with_ai(scan_id, scan, body.message, r)
            return {"status": "sent", "mode": "ai_reply"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {e}")


def _answer_chat_with_ai(scan_id: str, scan, question: str, r):
    """Use Claude to answer a question about a completed/failed scan."""
    import threading

    def _do_reply():
        try:
            import anthropic
            from modules.infra import get_storage

            # Load scan report for context
            report_text = ""
            try:
                report = get_storage().get_json(f"scans/{scan_id}/report.json")
                if report:
                    report_text = _json.dumps(report, indent=2)
                    if len(report_text) > 40000:
                        report_text = report_text[:40000] + "\n... [truncated]"
            except Exception:
                pass

            # Load chat history for conversation continuity
            raw = r.lrange(f"scan:chat:history:{scan_id}", 0, -1)
            chat_history = []
            for item in raw:
                try:
                    chat_history.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
                except Exception:
                    pass

            # Build messages from chat history (last 20 messages for context)
            messages = []
            for m in chat_history[-20:]:
                role = "user" if m.get("role") == "human" else "assistant"
                messages.append({"role": role, "content": m.get("message", "")})

            # Ensure proper alternation — merge consecutive same-role messages
            merged = []
            for m in messages:
                if merged and merged[-1]["role"] == m["role"]:
                    merged[-1]["content"] += "\n" + m["content"]
                else:
                    merged.append(m)
            # Ensure starts with user
            if merged and merged[0]["role"] == "assistant":
                merged.insert(0, {"role": "user", "content": "(conversation start)"})
            # Ensure ends with user (should already since last msg was human)
            if merged and merged[-1]["role"] != "user":
                merged.append({"role": "user", "content": question})

            if not merged:
                merged = [{"role": "user", "content": question}]

            system = (
                f"You are a security scanning AI assistant. You previously ran a {scan.scan_type} scan "
                f"on target {scan.target}. The scan status is: {scan.status}.\n\n"
            )
            if report_text:
                system += f"Here is the full scan report:\n\n{report_text}\n\n"
            else:
                system += "No report data is available for this scan.\n\n"
            system += (
                "Answer the user's questions about this scan, its findings, recommendations, "
                "or security topics related to the target. Be specific, reference actual findings "
                "from the report when relevant. Be concise but thorough."
            )

            client = anthropic.Anthropic()
            response = client.messages.create(
                model=AI_MODEL,
                max_tokens=4000,
                system=system,
                messages=merged,
            )

            reply_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    reply_text += block.text

            if reply_text:
                agent_msg = _json.dumps({
                    "role": "agent",
                    "message": reply_text,
                    "type": "reply",
                    "timestamp": _time.strftime("%H:%M:%S"),
                    "ts": _time.time(),
                })
                r.rpush(f"scan:chat:history:{scan_id}", agent_msg)
                r.expire(f"scan:chat:history:{scan_id}", 86400)

        except Exception as e:
            # Post error as agent message
            error_msg = _json.dumps({
                "role": "agent",
                "message": f"Sorry, I couldn't generate a response: {e}",
                "type": "error",
                "timestamp": _time.strftime("%H:%M:%S"),
                "ts": _time.time(),
            })
            try:
                r.rpush(f"scan:chat:history:{scan_id}", error_msg)
                r.expire(f"scan:chat:history:{scan_id}", 86400)
            except Exception:
                pass

    # Run in background thread so the API responds immediately
    threading.Thread(target=_do_reply, daemon=True).start()


@app.get("/api/scans/{scan_id}/chat")
def get_chat_messages(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get chat history for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        r = _redis.from_url(_REDIS_URL)
        raw = r.lrange(f"scan:chat:history:{scan_id}", 0, -1)
        messages = []
        for item in raw:
            try:
                messages.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
            except Exception:
                pass
        return {"scan_id": scan_id, "messages": messages}
    except Exception:
        return {"scan_id": scan_id, "messages": []}


# ─── Global chat (central AI brain) ──────────────────────────────────

class GlobalChatMessage(BaseModel):
    message: str


@app.post("/api/chat")
def global_chat(
    body: GlobalChatMessage,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Global AI assistant — central brain for discussing scans, security, creating scans."""
    try:
        r = _redis.from_url(_REDIS_URL)
        msg = _json.dumps({
            "role": "human",
            "message": body.message,
            "timestamp": _time.strftime("%H:%M:%S"),
            "ts": _time.time(),
        })
        r.rpush(f"global:chat:{user.id}", msg)
        r.expire(f"global:chat:{user.id}", 86400 * 7)

        # Dual-write to ES
        try:
            from modules.infra.elasticsearch import index_doc
            index_doc("scanner-chat-messages", {
                "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                "user_id": user.id,
                "role": "human",
                "message": body.message,
                "channel": "global",
            })
        except Exception:
            pass

        # Answer in background thread
        _answer_global_chat(user, body.message, r, db)
        return {"status": "sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {e}")


@app.get("/api/chat")
def get_global_chat(
    user: User = Depends(get_current_user),
):
    """Get global chat history."""
    try:
        r = _redis.from_url(_REDIS_URL)
        raw = r.lrange(f"global:chat:{user.id}", 0, -1)
        messages = []
        for item in raw:
            try:
                messages.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
            except Exception:
                pass
        return {"messages": messages}
    except Exception:
        return {"messages": []}


@app.delete("/api/chat")
def clear_global_chat(
    user: User = Depends(get_current_user),
):
    """Clear global chat history."""
    try:
        r = _redis.from_url(_REDIS_URL)
        r.delete(f"global:chat:{user.id}")
        return {"status": "cleared"}
    except Exception:
        return {"status": "error"}


def _answer_global_chat(user, question: str, r, db):
    """Global AI Security Advisor with full access to scan history, findings, memory, and analytics."""
    import threading

    # Snapshot data before thread starts (db session is thread-local)
    user_id = user.id
    all_scans = db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.created_at.desc()).all()
    scans_summary = []
    for s in all_scans[:20]:
        scans_summary.append({
            "id": s.id,
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "risk_score": s.risk_score,
            "findings_count": s.findings_count,
            "created_at": str(s.created_at),
        })

    # Fetch scan_memory entries (cross-scan knowledge base)
    memory_entries = []
    try:
        from sqlalchemy import text as _sqltext
        from modules.api.database import engine as _db_engine
        with _db_engine.connect() as conn:
            rows = conn.execute(_sqltext(
                "SELECT content, memory_type, tags, target, created_at "
                "FROM scan_memory ORDER BY created_at DESC LIMIT 20"
            )).fetchall()
            for row in rows:
                memory_entries.append({
                    "content": row[0],
                    "type": row[1],
                    "tags": row[2] or [],
                    "target": row[3],
                })
    except Exception:
        pass

    def _do_reply():
        try:
            import anthropic
            from modules.infra import get_storage
            from modules.infra.elasticsearch import search as _es_search

            # Load report summaries for completed scans
            reports_context = ""
            for scan_info in scans_summary[:5]:
                if scan_info["status"] == "completed":
                    try:
                        report = get_storage().get_json(f"scans/{scan_info['id']}/report.json")
                        if report:
                            brief = {
                                "scan_id": scan_info["id"][:8],
                                "target": scan_info["target"],
                                "scan_type": scan_info["scan_type"],
                                "risk_score": report.get("risk_score"),
                                "summary": (report.get("summary") or "")[:600],
                                "findings_count": len(report.get("findings") or []),
                                "top_findings": [
                                    {
                                        "severity": f.get("severity"),
                                        "title": f.get("title"),
                                        "category": f.get("category"),
                                    }
                                    for f in (report.get("findings") or [])[:15]
                                ],
                            }
                            reports_context += _json.dumps(brief, indent=1) + "\n\n"
                    except Exception:
                        pass
            if len(reports_context) > 30000:
                reports_context = reports_context[:30000] + "\n... [truncated]"

            # ES analytics: top critical/high findings across all scans
            critical_findings_context = ""
            try:
                findings_result = _es_search(
                    "scanner-scan-findings",
                    {"bool": {"filter": [{"terms": {"severity": ["critical", "high"]}}]}},
                    size=20,
                    sort=[{"timestamp": "desc"}],
                )
                findings_hits = findings_result.get("hits", {}).get("hits", [])
                if findings_hits:
                    critical_findings_context = _json.dumps([
                        {
                            "severity": h["_source"].get("severity"),
                            "title": h["_source"].get("title"),
                            "target": h["_source"].get("target"),
                            "category": h["_source"].get("category"),
                            "description": (h["_source"].get("description") or "")[:200],
                            "remediation": (h["_source"].get("remediation") or "")[:150],
                        }
                        for h in findings_hits
                    ], indent=1)
            except Exception:
                pass

            # ES analytics: severity distribution, top categories, findings by target
            analytics_context = ""
            try:
                agg_result = _es_search(
                    "scanner-scan-findings",
                    {"match_all": {}},
                    size=0,
                    aggs={
                        "severity_dist": {"terms": {"field": "severity"}},
                        "by_target": {"terms": {"field": "target", "size": 10}},
                        "top_categories": {"terms": {"field": "category", "size": 10}},
                        "last_30d": {
                            "filter": {"range": {"timestamp": {"gte": "now-30d"}}},
                            "aggs": {"severity_dist": {"terms": {"field": "severity"}}},
                        },
                        "last_7d": {
                            "filter": {"range": {"timestamp": {"gte": "now-7d"}}},
                            "aggs": {"severity_dist": {"terms": {"field": "severity"}}},
                        },
                    },
                )
                aggs = agg_result.get("aggregations", {})
                analytics_context = _json.dumps({
                    "overall_severity_distribution": {
                        b["key"]: b["doc_count"]
                        for b in aggs.get("severity_dist", {}).get("buckets", [])
                    },
                    "findings_by_target": {
                        b["key"]: b["doc_count"]
                        for b in aggs.get("by_target", {}).get("buckets", [])
                    },
                    "top_vulnerability_categories": {
                        b["key"]: b["doc_count"]
                        for b in aggs.get("top_categories", {}).get("buckets", [])
                    },
                    "last_30d_by_severity": {
                        b["key"]: b["doc_count"]
                        for b in aggs.get("last_30d", {}).get("severity_dist", {}).get("buckets", [])
                    },
                    "last_7d_by_severity": {
                        b["key"]: b["doc_count"]
                        for b in aggs.get("last_7d", {}).get("severity_dist", {}).get("buckets", [])
                    },
                }, indent=1)
            except Exception:
                pass

            # Load chat history for conversation continuity
            raw = r.lrange(f"global:chat:{user_id}", 0, -1)
            chat_history = []
            for item in raw:
                try:
                    chat_history.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
                except Exception:
                    pass

            # Build messages with proper role alternation
            messages = []
            for m in chat_history[-30:]:
                role = "user" if m.get("role") == "human" else "assistant"
                messages.append({"role": role, "content": m.get("message", "")})

            merged = []
            for m in messages:
                if merged and merged[-1]["role"] == m["role"]:
                    merged[-1]["content"] += "\n" + m["content"]
                else:
                    merged.append(m)
            if merged and merged[0]["role"] == "assistant":
                merged.insert(0, {"role": "user", "content": "(conversation start)"})
            if merged and merged[-1]["role"] != "user":
                merged.append({"role": "user", "content": question})
            if not merged:
                merged = [{"role": "user", "content": question}]

            scan_types = "full, security, pentest, seo, performance, compliance, api_security, cloud, recon, privacy, uptime, owasp, chatbot"

            system = (
                "You are the AI Security Advisor — the central intelligence of a security scanning platform. "
                "You have full access to the user's complete scan history, findings database, "
                "security knowledge base, and real-time analytics.\n\n"
                "## Your Capabilities\n"
                "- **Risk Assessment**: Answer 'What's our biggest security risk right now?' with data-backed analysis\n"
                "- **Trend Analysis**: Compare security posture across time periods — 'Compare this month to last month'\n"
                "- **Remediation Plans**: Generate prioritized remediation plans for all critical/high findings\n"
                "- **Ad-hoc Reports**: Generate filtered reports — 'Show me all SQL injection findings'\n"
                "- **Scan Control**: Start, stop, retry, verify, and monitor scans in real-time\n"
                "- **Scan Troubleshooting**: Detect stuck scans and force-retry or force-fail them\n"
                "- **Cross-scan Analysis**: Identify patterns across multiple targets and scan types\n"
                "- **CVE Alerts**: Flag new CVEs affecting detected technology stacks\n"
                "- **Finding Validation**: Launch exploit PoC tasks to prove vulnerabilities are real\n\n"
                "## Actions\n"
                "Trigger platform actions by including JSON blocks in your response:\n\n"
                "### Create a scan\n"
                "```action\n"
                '{\"action\": \"create_scan\", \"target\": \"https://example.com\", \"scan_type\": \"full\"}\n'
                "```\n"
                f"Available scan types: {scan_types}\n\n"
                "### Generate an ad-hoc report\n"
                "When the user asks for a filtered findings report:\n"
                "```action\n"
                '{\"action\": \"generate_report\", \"title\": \"Critical SQL Injection Findings\", '
                '\"severity\": \"critical,high\", \"category\": \"injection\", \"target\": \"\"}\n'
                "```\n\n"
                "### Validate a finding (exploit PoC)\n"
                "```action\n"
                '{\"action\": \"validate_finding\", \"target\": \"https://example.com\", '
                '\"finding\": \"SQL injection in login form\", \"scan_id\": \"abc123\", '
                '\"goal\": \"Prove SQLi with working payload and extract sample data\"}\n'
                "```\n\n"
                "### Trigger CVE check\n"
                "When you detect known technologies, proactively check for CVEs:\n"
                "```action\n"
                '{\"action\": \"cve_check\", \"technologies\": [\"WordPress 6.0\", \"Apache 2.4.51\", \"OpenSSL 1.1.1\"]}\n'
                "```\n\n"
                "## Risk Assessment Guidelines\n"
                "When assessing risk, consider:\n"
                "- Critical findings always take top priority\n"
                "- Authentication/authorization flaws carry highest business risk\n"
                "- Injection vulnerabilities (SQLi, XSS, SSRF, RCE) are critical by default\n"
                "- Unpatched CVEs in detected tech stack compound risk significantly\n"
                "- Trends matter: increasing critical count signals deteriorating posture\n\n"
                "## Remediation Plan Format\n"
                "When generating remediation plans, structure them as:\n"
                "1. **Immediate (24-48h)**: Critical severity — patch/mitigate now\n"
                "2. **Short-term (1-2 weeks)**: High severity — schedule fixes\n"
                "3. **Medium-term (1 month)**: Medium severity — plan improvements\n"
                "4. **Long-term**: Process/tooling improvements to prevent recurrence\n\n"
                "## Scan Types\n"
                "- **full**: Comprehensive audit — security, performance, SEO, compliance\n"
                "- **security**: Vulnerability assessment — nuclei, nikto, headers, SSL\n"
                "- **pentest**: Aggressive pentesting — port scan, directory brute-force, SQLi, fuzzing\n"
                "- **owasp**: OWASP Top 10 systematic coverage\n"
                "- **chatbot**: AI/Chatbot security — prompt injection, jailbreaks, data leakage\n"
                "- **api_security**: API endpoint discovery, auth testing, rate limiting\n"
                "- **recon**: Passive recon — subdomains, DNS, WHOIS, tech detection\n"
                "- **compliance**: OWASP, GDPR, PCI-DSS, HIPAA standards\n"
                "- **cloud**: Cloud infrastructure security assessment\n\n"
                "## Scan Control Tools\n"
                "You have tools to control all aspects of scan management:\n\n"
                "### View & Monitor Scans\n"
                "- **list_user_scans**: Get all scans or filter by status (queued, running, completed, failed)\n"
                "  - Use when: 'What scans do I have?', 'Show me running scans', 'What's queued?'\n"
                "- **get_scan_status**: Get detailed status of a specific scan including progress and tokens used\n"
                "  - Use when: 'How's my scan progressing?', 'Check status of scan X'\n"
                "- **get_scan_report**: Fetch the full report from a completed scan\n"
                "  - Use when: 'Show me the report for scan X', 'What did scan X find?'\n\n"
                "### Start & Manage Scans\n"
                "- **start_scan**: Start a new scan on any target\n"
                "  - Use when: 'Scan example.com', 'Run a security scan on this URL'\n"
                "- **stop_scan**: Gracefully stop a running scan\n"
                "  - Use when: 'Stop scan X', 'Cancel the running scan'\n"
                "- **cancel_scan**: Cancel a queued scan (before it starts)\n"
                "  - Use when: 'Cancel the queued scan', 'Don't run scan X'\n\n"
                "### Retry & Recovery\n"
                "- **retry_scan**: Retry a failed or completed scan with previous context\n"
                "  - Use when: 'Retry scan X', 'Try scan X again'\n"
                "- **verify_scan**: Create a verification scan to test if findings are remediated\n"
                "  - Use when: 'Verify the findings were fixed', 'Check if we fixed scan X'\n\n"
                "### Troubleshoot Stuck Scans\n"
                "- **get_stuck_scans**: Identify scans that appear stuck (running but no heartbeat)\n"
                "  - Use when: 'Are any scans stuck?', 'Check for hung scans'\n"
                "- **force_retry_stuck_scan**: Force-retry a stuck scan with checkpoint resume\n"
                "  - Use when: 'Restart the stuck scan', 'Fix the hung scan'\n"
                "- **force_fail_scan**: Force-fail a completely unresponsive scan\n"
                "  - Use when: 'Fail the stuck scan', 'Give up on this scan'\n\n"
                f"## User's Scans ({len(scans_summary)} total)\n"
                f"{_json.dumps(scans_summary, indent=1)}\n\n"
            )

            if reports_context:
                system += f"## Recent Scan Reports (summaries)\n{reports_context}\n\n"

            if critical_findings_context:
                system += f"## Active Critical & High Findings\n{critical_findings_context}\n\n"

            if analytics_context:
                system += f"## Security Analytics\n{analytics_context}\n\n"

            if memory_entries:
                system += (
                    f"## Security Knowledge Base (from past scans)\n"
                    f"{_json.dumps(memory_entries[:15], indent=1)}\n\n"
                )

            system += (
                "Be concise but thorough. Reference specific scan data, findings, and analytics when relevant. "
                "When the user asks about risk, use the analytics data to give specific numbers. "
                "When generating remediation plans, reference actual findings with their severity and target. "
                "If the user mentions technologies, proactively suggest a cve_check action. "
                "When the user asks to validate or prove a finding, use the validate_finding action. "
                "When the user asks about running scans, use list_user_scans or get_scan_status. "
                "When the user wants to start, stop, or manage scans, use the scan control tools directly. "
                "When you detect stuck scans from get_stuck_scans, proactively ask if they should be force-retried or failed."
            )

            client = anthropic.Anthropic()
            response = client.messages.create(
                model=AI_MODEL,
                max_tokens=4000,
                system=system,
                messages=merged,
            )

            reply_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    reply_text += block.text

            if reply_text:
                agent_msg = _json.dumps({
                    "role": "agent",
                    "message": reply_text,
                    "type": "reply",
                    "timestamp": _time.strftime("%H:%M:%S"),
                    "ts": _time.time(),
                })
                r.rpush(f"global:chat:{user_id}", agent_msg)
                r.expire(f"global:chat:{user_id}", 86400 * 7)
                try:
                    from modules.infra.elasticsearch import index_doc
                    index_doc("scanner-chat-messages", {
                        "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                        "user_id": user_id,
                        "role": "agent",
                        "message": reply_text[:10000],
                        "channel": "global",
                        "msg_type": "reply",
                    })
                except Exception:
                    pass

        except Exception as e:
            error_msg = _json.dumps({
                "role": "agent",
                "message": f"Sorry, I couldn't generate a response: {e}",
                "type": "error",
                "timestamp": _time.strftime("%H:%M:%S"),
                "ts": _time.time(),
            })
            try:
                r.rpush(f"global:chat:{user_id}", error_msg)
                r.expire(f"global:chat:{user_id}", 86400 * 7)
            except Exception:
                pass

    threading.Thread(target=_do_reply, daemon=True).start()


def _execute_chat_actions(reply_text: str, user_id: str, db):
    """Parse and execute action blocks embedded in AI response text."""
    import re

    action_pattern = re.compile(r"```action\s*([\s\S]*?)```", re.MULTILINE)
    matches = action_pattern.findall(reply_text)
    if not matches:
        return

    for match in matches:
        try:
            action = _json.loads(match.strip())
            action_type = action.get("action")

            if action_type == "create_scan":
                target = action.get("target", "").strip()
                scan_type = action.get("scan_type", "security")
                config = action.get("config", {})
                if target and target != "https://example.com":
                    new_scan = Scan(
                        user_id=user_id,
                        target=target,
                        scan_type=scan_type,
                        config=config or None,
                    )
                    db.add(new_scan)
                    db.commit()
                    db.refresh(new_scan)
                    get_queue().send("scan-jobs", {
                        "scan_id": new_scan.id,
                        "target": new_scan.target,
                        "scan_type": new_scan.scan_type,
                        "config": new_scan.config or {},
                    })
        except Exception:
            pass


# ─── Chat: actions, ad-hoc reports, and proactive alerts ──────────────

class ChatActionRequest(BaseModel):
    action: str
    target: str = ""
    scan_type: str = "security"
    config: dict | None = None
    # generate_report params
    title: str = ""
    severity: str = ""
    category: str = ""
    # validate_finding params
    finding: str = ""
    scan_id: str = ""
    goal: str = ""
    # cve_check params
    technologies: list[str] = []


@app.post("/api/chat/actions")
def execute_chat_action(
    body: ChatActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Execute a structured action triggered from the AI chat (create scan, generate report, CVE check)."""
    if body.action == "create_scan":
        target = body.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target is required for create_scan")
        new_scan = Scan(
            user_id=user.id,
            target=target,
            scan_type=body.scan_type or "security",
            config=body.config or None,
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        get_queue().send("scan-jobs", {
            "scan_id": new_scan.id,
            "target": new_scan.target,
            "scan_type": new_scan.scan_type,
            "config": new_scan.config or {},
        })
        return {"action": "create_scan", "scan_id": new_scan.id, "status": "queued", "target": target}

    elif body.action == "generate_report":
        from modules.infra.elasticsearch import search as _es_search
        filters: list[dict] = []
        if body.severity:
            filters.append({"terms": {"severity": body.severity.split(",")}})
        if body.category:
            filters.append({"match": {"category": body.category}})
        if body.target:
            filters.append({"wildcard": {"target": f"*{body.target}*"}})
        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        result = _es_search("scanner-scan-findings", query, size=200, sort=[{"timestamp": "desc"}])
        hits = result.get("hits", {})
        findings = [h["_source"] for h in hits.get("hits", [])]
        return {
            "action": "generate_report",
            "title": body.title or "Ad-hoc Security Report",
            "total": hits.get("total", {}).get("value", 0),
            "findings": findings,
        }

    elif body.action == "cve_check":
        import threading

        techs = body.technologies
        if not techs:
            raise HTTPException(status_code=400, detail="technologies list is required for cve_check")

        user_id = user.id
        r = _redis.from_url(_REDIS_URL)

        def _do_cve_check():
            try:
                import anthropic
                client = anthropic.Anthropic()
                system = (
                    "You are a CVE intelligence analyst. Given a list of technologies and versions, "
                    "identify known CVEs, actively exploited vulnerabilities, and security advisories "
                    "from 2024-2026. For each finding, provide: CVE ID (if known), severity, "
                    "affected versions, brief description, and recommended action. "
                    "Focus on critical and high severity issues. Be concise and actionable."
                )
                tech_list = "\n".join(f"- {t}" for t in techs)
                response = client.messages.create(
                    model=AI_MODEL,
                    max_tokens=2000,
                    system=system,
                    messages=[{
                        "role": "user",
                        "content": f"Check for known CVEs and security issues for these technologies:\n{tech_list}",
                    }],
                )
                reply_text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        reply_text += block.text
                if reply_text:
                    alert_msg = _json.dumps({
                        "role": "agent",
                        "message": f"**Proactive CVE Alert**\n\nI checked the following technologies for known vulnerabilities:\n{tech_list}\n\n{reply_text}",
                        "type": "cve_alert",
                        "timestamp": _time.strftime("%H:%M:%S"),
                        "ts": _time.time(),
                    })
                    r.rpush(f"global:chat:{user_id}", alert_msg)
                    r.expire(f"global:chat:{user_id}", 86400 * 7)
            except Exception:
                pass

        threading.Thread(target=_do_cve_check, daemon=True).start()
        return {"action": "cve_check", "status": "checking", "technologies": techs}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")


@app.get("/api/chat/alerts")
def get_proactive_alerts(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate proactive security alerts based on detected tech stacks and recent findings."""
    import threading

    user_id = user.id
    all_scans = db.query(Scan).filter(
        Scan.user_id == user_id, Scan.status == "completed"
    ).order_by(Scan.created_at.desc()).limit(10).all()

    # Gather detected technologies from scan memories
    tech_stack: list[str] = []
    try:
        from sqlalchemy import text as _sqltext
        from modules.api.database import engine as _db_engine
        with _db_engine.connect() as conn:
            rows = conn.execute(_sqltext(
                "SELECT content FROM scan_memory WHERE memory_type = 'finding' "
                "AND content ILIKE '%version%' OR content ILIKE '%technology%' "
                "ORDER BY created_at DESC LIMIT 10"
            )).fetchall()
            for row in rows:
                tech_stack.append(row[0][:200])
    except Exception:
        pass

    # Get critical findings from ES for alert summary
    from modules.infra.elasticsearch import search as _es_search
    crit_result = _es_search(
        "scanner-scan-findings",
        {"bool": {"filter": [{"terms": {"severity": ["critical", "high"]}}]}},
        size=10,
        sort=[{"timestamp": "desc"}],
    )
    crit_hits = crit_result.get("hits", {}).get("hits", [])
    critical_findings = [
        {
            "severity": h["_source"].get("severity"),
            "title": h["_source"].get("title"),
            "target": h["_source"].get("target"),
        }
        for h in crit_hits
    ]

    return {
        "scans_analyzed": len(all_scans),
        "critical_findings_count": crit_result.get("hits", {}).get("total", {}).get("value", 0),
        "recent_critical_findings": critical_findings,
        "detected_tech_context": tech_stack[:5],
        "recommendation": (
            "Use POST /api/chat/actions with action=cve_check to check detected technologies for CVEs, "
            "or ask the AI advisor directly: 'Check for CVEs in our tech stack'"
        ) if not tech_stack else (
            "Tech stack detected from scan memory. Use the chat advisor to run a CVE check."
        ),
    }


# ─── Validation tasks ─────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    target: str
    finding: str
    scan_id: str = ""
    goal: str = "Validate and document this vulnerability with a proof of concept"


@app.post("/api/validate")
def start_validation(
    body: ValidateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a validation/exploit PoC task in the worker."""
    import uuid
    task_id = str(uuid.uuid4())

    # Load report context if scan_id provided
    report_context = ""
    if body.scan_id:
        try:
            from modules.infra import get_storage
            report = get_storage().get_json(f"scans/{body.scan_id}/report.json")
            if report:
                report_context = _json.dumps(report, indent=1)
                if len(report_context) > 15000:
                    report_context = report_context[:15000] + "\n... [truncated]"
        except Exception:
            pass

    get_queue().send("validation-jobs", {
        "task_id": task_id,
        "user_id": user.id,
        "target": body.target,
        "finding": body.finding,
        "scan_id": body.scan_id,
        "goal": body.goal,
        "report_context": report_context,
    })

    return {"task_id": task_id, "status": "queued"}


# ─── Dashboard UI ─────────────────────────────────────────────────────
_STATIC = os.path.join(os.path.dirname(__file__), "static")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    path = os.path.join(_STATIC, "dashboard.html")
    if os.path.exists(path):
        with open(path) as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    path = os.path.join(_STATIC, "admin.html")
    if os.path.exists(path):
        with open(path) as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Admin page not found</h1>", status_code=404)


@app.get("/analytics", response_class=HTMLResponse)
def analytics_page():
    path = os.path.join(_STATIC, "analytics.html")
    if os.path.exists(path):
        with open(path) as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Analytics page not found</h1>", status_code=404)


@app.get("/uptime", response_class=HTMLResponse)
def uptime_page():
    path = os.path.join(_STATIC, "uptime.html")
    if os.path.exists(path):
        with open(path) as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Uptime page not found</h1>", status_code=404)
