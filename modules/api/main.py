import os
import subprocess

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from modules.api.database import engine, Base
from modules.api.routes import scans, auth, monitors, schedules, notifications, reports, tools, search, campaigns
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
    """Global AI assistant with access to all user scans and reports."""
    import threading

    # Snapshot data we need before thread starts (db session is thread-local)
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

    def _do_reply():
        try:
            import anthropic
            from modules.infra import get_storage

            # Load reports for completed scans (summaries only to save tokens)
            reports_context = ""
            for scan_info in scans_summary[:5]:
                if scan_info["status"] == "completed":
                    try:
                        report = get_storage().get_json(f"scans/{scan_info['id']}/report.json")
                        if report:
                            brief = {
                                "scan_id": scan_info["id"][:8],
                                "target": scan_info["target"],
                                "risk_score": report.get("risk_score"),
                                "summary": (report.get("summary") or "")[:500],
                                "findings_count": len(report.get("findings") or []),
                                "top_findings": [
                                    {"severity": f.get("severity"), "title": f.get("title")}
                                    for f in (report.get("findings") or [])[:10]
                                ],
                            }
                            reports_context += _json.dumps(brief, indent=1) + "\n\n"
                    except Exception:
                        pass
            if len(reports_context) > 30000:
                reports_context = reports_context[:30000] + "\n... [truncated]"

            # Load chat history
            raw = r.lrange(f"global:chat:{user_id}", 0, -1)
            chat_history = []
            for item in raw:
                try:
                    chat_history.append(_json.loads(item.decode() if isinstance(item, bytes) else item))
                except Exception:
                    pass

            # Build messages
            messages = []
            for m in chat_history[-30:]:
                role = "user" if m.get("role") == "human" else "assistant"
                messages.append({"role": role, "content": m.get("message", "")})

            # Ensure proper alternation
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
                "You are the central AI brain of a security scanning platform. "
                "You help users plan, run, and analyze security scans.\n\n"
                "## Your Capabilities\n"
                "- Discuss security risks, vulnerabilities, and remediation strategies\n"
                "- Advise on which scan type to use for specific targets/goals\n"
                "- Analyze and explain findings from completed scans\n"
                "- Suggest scan configurations and improvements for specific environments\n"
                "- Compare results across multiple scans\n"
                "- Create new scans when the user asks\n"
                "- **Validate findings**: Launch exploit PoC tasks to prove vulnerabilities are real\n"
                "- Run OWASP Top 10 comprehensive testing\n"
                "- Test AI chatbots for prompt injection, data leakage, and abuse\n\n"
                "## Actions\n"
                "You can trigger actions by including JSON blocks in your response:\n\n"
                "### Create a scan\n"
                "```action\n"
                '{\"action\": \"create_scan\", \"target\": \"https://example.com\", \"scan_type\": \"full\"}\n'
                "```\n"
                f"Available scan types: {scan_types}\n\n"
                "### Validate a finding (exploit PoC)\n"
                "When the user asks to validate, prove, or test a specific vulnerability:\n"
                "```action\n"
                '{\"action\": \"validate_finding\", \"target\": \"https://example.com\", '
                '\"finding\": \"XSS in search parameter\", \"scan_id\": \"abc123\", '
                '\"goal\": \"Prove XSS is exploitable with a working payload\"}\n'
                "```\n"
                "This launches a sandboxed agent that writes exploit code, runs it, and "
                "documents a step-by-step proof of concept.\n\n"
                "## Scan Types\n"
                "- **full**: Comprehensive audit — security, performance, SEO, compliance\n"
                "- **security**: Vulnerability assessment — nuclei, nikto, headers, SSL\n"
                "- **pentest**: Aggressive pentesting — port scan, directory brute-force, SQLi, fuzzing\n"
                "- **owasp**: OWASP Top 10 focused testing — injection, broken auth, XSS, CSRF, "
                "SSRF, security misconfiguration, vulnerable components, broken access control, "
                "cryptographic failures, logging/monitoring gaps. Systematic coverage of all categories.\n"
                "- **chatbot**: AI/Chatbot security testing — prompt injection (direct & indirect), "
                "jailbreak attempts, data exfiltration via conversation, PII leakage, system prompt "
                "extraction, tool abuse, conversation history manipulation, training data extraction, "
                "denial of service via complex prompts, unauthorized action execution\n"
                "- **seo**: SEO and performance — Lighthouse, accessibility, broken links\n"
                "- **api_security**: API endpoint discovery, auth testing, rate limiting\n"
                "- **recon**: Passive reconnaissance — subdomains, DNS, WHOIS, tech detection\n"
                "- **compliance**: OWASP, GDPR, PCI-DSS, HIPAA standards checking\n"
                "- **privacy**: Cookie consent, tracking, data exposure checks\n"
                "- **cloud**: Cloud infrastructure security assessment\n"
                "- **performance**: Load testing, response time, bottleneck detection\n"
                "- **uptime**: Availability monitoring and alerting\n\n"
                "## Advice Approach\n"
                "Before starting a scan, discuss with the user:\n"
                "- What type of application is the target? (SaaS, e-commerce, API, WordPress, chatbot, etc.)\n"
                "- What are their security concerns? (compliance, pentesting, specific vulnerability classes)\n"
                "- Suggest the optimal scan type and configuration\n"
                "- If they have existing scan results, recommend follow-up actions\n"
                "- For chatbot targets, ask about the chatbot platform and what tools/actions it has access to\n\n"
                f"## User's Scans ({len(scans_summary)} total)\n"
                f"{_json.dumps(scans_summary, indent=1)}\n\n"
            )
            if reports_context:
                system += f"## Recent Scan Reports (summaries)\n{reports_context}\n\n"

            system += (
                "Be concise but thorough. Reference specific scan data when relevant. "
                "If the user asks about something not covered by existing scans, suggest running one. "
                "When the user asks to validate or prove a finding, use the validate_finding action."
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
                # ES dual-write
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
