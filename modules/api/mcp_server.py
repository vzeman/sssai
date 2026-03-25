"""MCP (Model Context Protocol) server for SSSAI Security Scanner.

Exposes security scanning capabilities as MCP tools accessible via SSE transport.
Mount at /mcp in the FastAPI app. Requires JWT authentication.
"""

import contextvars
import json
import logging

from jose import JWTError, jwt
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount

from modules.api.auth import SECRET_KEY, ALGORITHM, is_token_blacklisted
from modules.api.database import SessionLocal
from modules.api.models import Scan, User, ScheduledScan
from modules.infra import get_queue, get_storage

logger = logging.getLogger(__name__)

# ─── Auth ─────────────────────────────────────────────────────────────

_current_user: contextvars.ContextVar[User] = contextvars.ContextVar("current_user")


def _authenticate(token: str) -> User:
    """Validate JWT token and return User. Raises ValueError on failure."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise ValueError("Invalid or expired token")
    if payload.get("type") != "access":
        raise ValueError("Invalid token type")
    if is_token_blacklisted(token):
        raise ValueError("Token revoked")
    user_id = payload.get("sub")
    if not user_id:
        raise ValueError("Invalid token payload")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise ValueError("User not found or inactive")
        return user
    finally:
        db.close()


def _extract_token(request: Request) -> str | None:
    """Extract JWT from query param or Authorization header."""
    token = request.query_params.get("token")
    if token:
        return token
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


# ─── MCP Server ───────────────────────────────────────────────────────

mcp = Server("sssai-security-scanner")


@mcp.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_target",
            description="Start a security scan against a target URL or domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or domain to scan (e.g. https://example.com)"},
                    "scan_type": {
                        "type": "string",
                        "default": "security",
                        "enum": ["security", "adaptive", "quick", "api", "ssl", "headers", "recon", "vulnerability"],
                        "description": "Type of scan to run",
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="get_scan_status",
            description="Get current status, risk score, and findings count for a scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "UUID of the scan"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="get_scan_report",
            description="Get the full scan report including findings, risk score, and recommendations",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "UUID of the scan"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_scans",
            description="List security scans for the current user, sorted by newest first",
            inputSchema={
                "type": "object",
                "properties": {
                    "skip": {"type": "integer", "default": 0, "minimum": 0},
                    "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
                },
            },
        ),
        Tool(
            name="list_findings",
            description="List security findings across scans with optional filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Filter findings by scan ID"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Filter by severity level",
                    },
                    "size": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
                },
            },
        ),
        Tool(
            name="create_schedule",
            description="Create a recurring scheduled scan for a target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or domain to scan"},
                    "scan_type": {"type": "string", "default": "security"},
                    "cron_expression": {
                        "type": "string",
                        "default": "daily",
                        "description": "Frequency: hourly, daily, weekly, monthly, or interval (6h, 12h, 30m)",
                    },
                    "max_runs": {"type": "integer", "description": "Max number of runs (omit for unlimited)"},
                },
                "required": ["target"],
            },
        ),
    ]


@mcp.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        user = _current_user.get()
    except LookupError:
        return [TextContent(type="text", text=json.dumps({"error": "Not authenticated"}))]

    handlers = {
        "scan_target": _tool_scan_target,
        "get_scan_status": _tool_get_scan_status,
        "get_scan_report": _tool_get_scan_report,
        "list_scans": _tool_list_scans,
        "list_findings": _tool_list_findings,
        "create_schedule": _tool_create_schedule,
    }

    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

    try:
        result = handler(user, arguments)
        return [TextContent(type="text", text=json.dumps(result, default=str))]
    except Exception as e:
        logger.error(f"MCP tool {name} error: {e}")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


# ─── Tool Handlers ────────────────────────────────────────────────────

def _tool_scan_target(user: User, args: dict) -> dict:
    target = args.get("target")
    if not target:
        raise ValueError("target is required")
    scan_type = args.get("scan_type", "security")

    db = SessionLocal()
    try:
        scan = Scan(user_id=user.id, target=target, scan_type=scan_type)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        get_queue().send("scan-jobs", {
            "scan_id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "config": scan.config or {},
        })

        return {
            "scan_id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "message": f"Scan queued for {target}",
        }
    finally:
        db.close()


def _tool_get_scan_status(user: User, args: dict) -> dict:
    scan_id = args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id is required")

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
        if not scan:
            raise ValueError("Scan not found")
        return {
            "scan_id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "findings_count": scan.findings_count,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
        }
    finally:
        db.close()


def _tool_get_scan_report(user: User, args: dict) -> dict:
    scan_id = args.get("scan_id")
    if not scan_id:
        raise ValueError("scan_id is required")

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
        if not scan:
            raise ValueError("Scan not found")
    finally:
        db.close()

    report = get_storage().get_json(f"scans/{scan_id}/report.json")
    if not report:
        return {"error": "Report not ready yet", "scan_id": scan_id, "status": scan.status}
    return report


def _tool_list_scans(user: User, args: dict) -> dict:
    skip = max(0, args.get("skip", 0))
    limit = min(100, max(1, args.get("limit", 20)))

    db = SessionLocal()
    try:
        query = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc())
        total = query.count()
        scans = query.offset(skip).limit(limit).all()
        return {
            "items": [
                {
                    "scan_id": s.id,
                    "target": s.target,
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "risk_score": s.risk_score,
                    "findings_count": s.findings_count,
                    "created_at": s.created_at,
                }
                for s in scans
            ],
            "total": total,
            "skip": skip,
            "limit": limit,
        }
    finally:
        db.close()


def _tool_list_findings(user: User, args: dict) -> dict:
    scan_id = args.get("scan_id")
    severity = args.get("severity")
    size = min(200, max(1, args.get("size", 50)))

    # Build ES query
    filters = []
    if scan_id:
        # Verify ownership
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
            if not scan:
                raise ValueError("Scan not found")
        finally:
            db.close()
        filters.append({"term": {"scan_id": scan_id}})
    if severity:
        filters.append({"term": {"severity": severity}})

    es_query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    try:
        from modules.infra.elasticsearch import search as es_search
        result = es_search("scanner-scan-findings", es_query, size=size)
        hits = result.get("hits", {}).get("hits", [])
        findings = [h["_source"] for h in hits]
        return {
            "findings": findings,
            "total": result.get("hits", {}).get("total", {}).get("value", len(findings)),
            "size": size,
        }
    except Exception as e:
        return {"findings": [], "total": 0, "error": f"Search unavailable: {e}"}


def _tool_create_schedule(user: User, args: dict) -> dict:
    target = args.get("target")
    if not target:
        raise ValueError("target is required")

    scan_type = args.get("scan_type", "security")
    cron_expression = args.get("cron_expression", "daily")
    max_runs = args.get("max_runs")

    from modules.api.routes.schedules import calc_first_run

    db = SessionLocal()
    try:
        schedule = ScheduledScan(
            user_id=user.id,
            target=target,
            scan_type=scan_type,
            cron_expression=cron_expression,
            max_runs=max_runs,
            next_run_at=calc_first_run(cron_expression),
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        return {
            "schedule_id": schedule.id,
            "target": schedule.target,
            "scan_type": schedule.scan_type,
            "cron_expression": schedule.cron_expression,
            "next_run_at": schedule.next_run_at,
            "message": f"Scheduled {cron_expression} scan for {target}",
        }
    finally:
        db.close()


# ─── SSE Transport ────────────────────────────────────────────────────

sse_transport = SseServerTransport("/messages/")


async def handle_sse(request: Request):
    """SSE endpoint — authenticate via ?token= query param, then stream."""
    token = _extract_token(request)
    if not token:
        return JSONResponse({"error": "Authentication required. Pass ?token=<jwt>"}, status_code=401)
    try:
        user = _authenticate(token)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    _current_user.set(user)
    logger.info(f"MCP SSE connection for user {user.email}")
    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp.run(streams[0], streams[1], mcp.create_initialization_options())


async def handle_messages(request: Request):
    """Message endpoint — authenticate via Bearer header or ?token= param."""
    token = _extract_token(request)
    if not token:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    try:
        user = _authenticate(token)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
    _current_user.set(user)
    return await sse_transport.handle_post_message(request.scope, request.receive, request._send)


mcp_app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Route("/messages/", endpoint=handle_messages, methods=["POST"]),
    ],
)
