"""
AI scan agent — drives security tools autonomously using Claude.

Inspired by PentAGI architecture:
- Sub-agent delegation (pentester, searcher, coder)
- Loop detection & execution monitor
- Chain summarization for long scans
- Planning step before execution
- Reflector pattern for reliability
- Web search integration
"""

import json
import logging
import os
import subprocess
import time
from collections import Counter
from pathlib import Path

import anthropic
import httpx

from modules.agent.tools import TOOLS, SUBAGENT_TOOLS
from modules.agent.prompts import get_prompt
from modules.infra import get_storage, get_queue

log = logging.getLogger(__name__)

MAX_OUTPUT_LEN = 50_000
MAX_ITERATIONS = 100
MONITOR_INTERVAL = 10          # check progress every N tool calls
SAME_TOOL_LIMIT = 3            # max identical calls before flagging
SUMMARIZE_THRESHOLD = 80_000   # chars before summarizing old messages
KEEP_RECENT = 6                # messages to keep un-summarized

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")


# ── Tool handlers ────────────────────────────────────────────────────────

def handle_tool(name: str, input: dict, scan_context: dict | None = None) -> str:
    """Execute a tool and return the result string."""

    if name == "run_command":
        try:
            result = subprocess.run(
                input["command"],
                shell=True,
                capture_output=True,
                text=True,
                timeout=input.get("timeout", 300),
            )
            output = (result.stdout + result.stderr).strip()
            if len(output) > MAX_OUTPUT_LEN:
                return output[:MAX_OUTPUT_LEN] + "\n... [truncated]"
            return output or "(no output)"
        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out"
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "read_file":
        try:
            content = Path(input["path"]).read_text()
            if len(content) > MAX_OUTPUT_LEN:
                return content[:MAX_OUTPUT_LEN] + "\n... [truncated]"
            return content
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "write_file":
        try:
            p = Path(input["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(input["content"])
            return f"Written to {input['path']}"
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "http_request":
        try:
            url = input["url"]
            method = input.get("method", "GET")
            headers = input.get("headers", {})
            follow = input.get("follow_redirects", True)

            with httpx.Client(follow_redirects=follow, timeout=30) as client:
                resp = client.request(method, url, headers=headers)

            output_parts = [
                f"HTTP/{resp.http_version} {resp.status_code} {resp.reason_phrase}",
                "",
                "--- Response Headers ---",
            ]
            for k, v in resp.headers.items():
                output_parts.append(f"{k}: {v}")

            body = resp.text[:10000] if len(resp.text) > 10000 else resp.text
            output_parts.extend(["", "--- Body (first 10KB) ---", body])

            output = "\n".join(output_parts)
            if len(output) > MAX_OUTPUT_LEN:
                return output[:MAX_OUTPUT_LEN] + "\n... [truncated]"
            return output
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "dns_lookup":
        try:
            domain = input["domain"]
            record_type = input.get("record_type", "ANY")
            result = subprocess.run(
                f"dig {domain} {record_type} +noall +answer +authority",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.strip() or "(no records found)"
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "parse_json":
        try:
            path = input["path"]
            query = input.get("query", ".")
            result = subprocess.run(
                f"jq '{query}' {path}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout.strip()
            if result.returncode != 0:
                return f"jq error: {result.stderr.strip()}"
            if len(output) > MAX_OUTPUT_LEN:
                return output[:MAX_OUTPUT_LEN] + "\n... [truncated]"
            return output or "(empty result)"
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "compare_results":
        try:
            current = json.loads(Path(input["current_file"]).read_text())
            previous = json.loads(Path(input["previous_file"]).read_text())

            current_titles = {f.get("title") for f in current.get("findings", [])}
            previous_titles = {f.get("title") for f in previous.get("findings", [])}

            new_findings = current_titles - previous_titles
            resolved = previous_titles - current_titles
            unchanged = current_titles & previous_titles

            result = {
                "new_findings": list(new_findings),
                "resolved_findings": list(resolved),
                "unchanged": len(unchanged),
                "current_risk_score": current.get("risk_score", 0),
                "previous_risk_score": previous.get("risk_score", 0),
                "risk_delta": current.get("risk_score", 0) - previous.get("risk_score", 0),
            }
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "screenshot":
        try:
            url = input["url"]
            output_path = input.get("output_path", "/output/screenshot.png")
            width = input.get("width", 1920)
            height = input.get("height", 1080)
            mobile = input.get("mobile", False)

            if mobile:
                width, height = 375, 812

            cmd = (
                f"chromium-browser --headless --disable-gpu --no-sandbox "
                f"--screenshot={output_path} "
                f"--window-size={width},{height} "
                f"'{url}'"
            )
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60,
            )
            if Path(output_path).exists():
                return f"Screenshot saved to {output_path}"
            return f"Screenshot may have failed: {result.stderr[:500]}"
        except Exception as e:
            return f"ERROR: {e}"

    elif name == "web_search":
        return _handle_web_search(input)

    elif name == "exploit_search":
        return _handle_exploit_search(input)

    elif name == "delegate_to_pentester":
        return _handle_subagent("pentester", input, scan_context)

    elif name == "delegate_to_searcher":
        return _handle_subagent("searcher", input, scan_context)

    elif name == "delegate_to_coder":
        return _handle_subagent("coder", input, scan_context)

    elif name == "search_memory":
        return _handle_search_memory(input, scan_context)

    elif name == "store_memory":
        return _handle_store_memory(input, scan_context)

    elif name == "ask_human":
        return _handle_ask_human(input, scan_context)

    elif name == "report":
        return "__REPORT__"

    return "Unknown tool"


# ── Web search ───────────────────────────────────────────────────────────

def _handle_web_search(input: dict) -> str:
    """Search the web using DuckDuckGo HTML (no API key needed)."""
    try:
        query = input["query"]
        max_results = input.get("max_results", 5)

        # Use DuckDuckGo HTML version
        resp = httpx.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            timeout=15,
            follow_redirects=True,
        )

        # Parse results from HTML
        results = []
        text = resp.text
        import re
        # Extract result snippets
        links = re.findall(
            r'<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)</a>',
            text,
        )
        snippets = re.findall(
            r'<a class="result__snippet"[^>]*>(.*?)</a>',
            text,
        )

        for i, (url, title) in enumerate(links[:max_results]):
            title_clean = re.sub(r"<[^>]+>", "", title).strip()
            snippet = re.sub(r"<[^>]+>", "", snippets[i]).strip() if i < len(snippets) else ""
            results.append(f"{i+1}. {title_clean}\n   URL: {url}\n   {snippet}")

        if not results:
            return f"No search results found for: {query}"
        return f"Search results for '{query}':\n\n" + "\n\n".join(results)
    except Exception as e:
        return f"ERROR: Web search failed: {e}"


def _handle_exploit_search(input: dict) -> str:
    """Search for exploits/CVEs using multiple sources."""
    try:
        query = input["query"]
        results = []

        # Search NVD for CVEs
        try:
            resp = httpx.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "resultsPerPage": 5},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", [])[:5]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc_list = cve.get("descriptions", [])
                    desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
                    metrics = cve.get("metrics", {})
                    score = ""
                    for m in metrics.get("cvssMetricV31", []):
                        score = f" (CVSS: {m['cvssData']['baseScore']})"
                        break
                    results.append(f"- {cve_id}{score}: {desc[:200]}")
        except Exception:
            pass

        # Search Exploit-DB via Google
        try:
            resp = httpx.get(
                "https://html.duckduckgo.com/html/",
                params={"q": f"site:exploit-db.com {query}"},
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
                timeout=15,
                follow_redirects=True,
            )
            import re
            links = re.findall(
                r'<a rel="nofollow" class="result__a" href="([^"]*exploit-db[^"]*)"[^>]*>(.*?)</a>',
                resp.text,
            )
            for url, title in links[:3]:
                title_clean = re.sub(r"<[^>]+>", "", title).strip()
                results.append(f"- ExploitDB: {title_clean}\n  {url}")
        except Exception:
            pass

        if not results:
            return f"No exploits/CVEs found for: {query}"
        return f"Exploit/CVE search results for '{query}':\n\n" + "\n".join(results)
    except Exception as e:
        return f"ERROR: Exploit search failed: {e}"


# ── Sub-agent delegation ─────────────────────────────────────────────────

_SUBAGENT_PROMPTS = {
    "pentester": (
        "You are a specialized penetration testing agent. You have been delegated a specific task "
        "by the primary scanning agent. Focus exclusively on this task using the available tools.\n\n"
        "Rules:\n"
        "- Only scan the authorized target: {target}\n"
        "- Be thorough but focused on the delegated task\n"
        "- Save output files to /output/\n"
        "- When done, provide a clear summary of what you found\n"
        "- Think like an attacker — what attack chains are possible?\n"
    ),
    "searcher": (
        "You are a specialized research agent. You have been delegated a research task "
        "by the primary scanning agent. Search for information about vulnerabilities, CVEs, "
        "exploits, and security best practices relevant to the task.\n\n"
        "Rules:\n"
        "- Use web_search and exploit_search tools to find relevant information\n"
        "- Synthesize findings into a clear, actionable summary\n"
        "- Include specific CVE IDs, CVSS scores, and exploit references when available\n"
        "- Focus on practical, exploitable vulnerabilities\n"
    ),
    "coder": (
        "You are a specialized coding agent. You have been delegated a task that requires "
        "writing code, scripts, or custom tooling. This might include:\n"
        "- Writing custom exploit scripts\n"
        "- Creating configuration files for scanning tools\n"
        "- Processing or analyzing scan output data\n"
        "- Writing automation scripts\n\n"
        "Rules:\n"
        "- Write clean, working code\n"
        "- Save scripts to /output/\n"
        "- Test your code when possible\n"
    ),
}

# Tools available to each sub-agent type
_SUBAGENT_TOOL_ACCESS = {
    "pentester": ["run_command", "read_file", "write_file", "http_request", "dns_lookup",
                   "parse_json", "screenshot"],
    "searcher": ["web_search", "exploit_search", "http_request", "read_file"],
    "coder": ["run_command", "read_file", "write_file"],
}


def _handle_subagent(agent_type: str, input: dict, scan_context: dict | None) -> str:
    """Run a specialized sub-agent with limited tools."""
    try:
        task = input["task"]
        context = input.get("context", "")
        target = scan_context.get("target", "") if scan_context else ""

        system_prompt = _SUBAGENT_PROMPTS[agent_type].format(target=target)
        if context:
            system_prompt += f"\n\nAdditional context from primary agent:\n{context}"

        # Filter tools for this sub-agent type
        allowed = _SUBAGENT_TOOL_ACCESS[agent_type]
        agent_tools = [t for t in TOOLS + SUBAGENT_TOOLS if t["name"] in allowed]

        client = anthropic.Anthropic()
        messages = [{"role": "user", "content": f"Task: {task}"}]

        max_iterations = 20
        all_output = []

        for _ in range(max_iterations):
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=8000,
                system=system_prompt,
                tools=agent_tools,
                messages=messages,
            )

            if response.stop_reason == "end_turn":
                text = "".join(b.text for b in response.content if hasattr(b, "text"))
                all_output.append(text)
                break

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        result = handle_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })
                        # Log sub-agent activity
                        if scan_context and scan_context.get("scan_id"):
                            _log_activity(scan_context["scan_id"], {
                                "type": "subagent",
                                "agent": agent_type,
                                "tool": block.name,
                                "input": str(block.input)[:150],
                                "timestamp": time.strftime("%H:%M:%S"),
                            })

                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        # Extract final text from the sub-agent
        if not all_output:
            all_output = ["(sub-agent produced no text output)"]

        result = f"[{agent_type.upper()} SUB-AGENT RESULT]\n" + "\n".join(all_output)
        if len(result) > MAX_OUTPUT_LEN:
            result = result[:MAX_OUTPUT_LEN] + "\n... [truncated]"
        return result

    except Exception as e:
        return f"ERROR: Sub-agent ({agent_type}) failed: {e}"


# ── Cross-scan memory (pgvector) ─────────────────────────────────────────

def _get_memory_db():
    """Get a connection to pgvector for memory operations."""
    try:
        from sqlalchemy import create_engine, text
        db_url = os.environ.get("DATABASE_URL", "")
        if not db_url:
            return None
        engine = create_engine(db_url)
        return engine
    except Exception:
        return None


def _handle_search_memory(input: dict, scan_context: dict | None) -> str:
    """Search cross-scan memory for relevant guides and findings."""
    try:
        engine = _get_memory_db()
        if not engine:
            return "(memory not available — no database)"

        from sqlalchemy import text
        query = input["query"]
        memory_type = input.get("type", "guide")  # guide, finding, answer

        with engine.connect() as conn:
            # Check if memory table exists
            exists = conn.execute(text(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'scan_memory')"
            )).scalar()
            if not exists:
                return "(no memory stored yet)"

            # Simple text search (upgrade to vector similarity later)
            rows = conn.execute(text(
                "SELECT content, memory_type, metadata, created_at "
                "FROM scan_memory "
                "WHERE memory_type = :mtype "
                "AND content ILIKE :query "
                "ORDER BY created_at DESC LIMIT 5"
            ), {"mtype": memory_type, "query": f"%{query}%"}).fetchall()

            if not rows:
                return f"No {memory_type} memories found matching: {query}"

            results = []
            for row in rows:
                results.append(f"[{row[1]}] {row[0][:500]}")
            return f"Found {len(results)} memories:\n\n" + "\n---\n".join(results)

    except Exception as e:
        return f"ERROR: Memory search failed: {e}"


def _handle_store_memory(input: dict, scan_context: dict | None) -> str:
    """Store a reusable guide, finding, or answer in cross-scan memory."""
    try:
        engine = _get_memory_db()
        if not engine:
            return "(memory not available — no database)"

        from sqlalchemy import text
        content = input["content"]
        memory_type = input.get("type", "guide")
        tags = input.get("tags", [])

        with engine.connect() as conn:
            # Create table if not exists
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

            scan_id = scan_context.get("scan_id", "") if scan_context else ""
            target = scan_context.get("target", "") if scan_context else ""

            conn.execute(text("""
                INSERT INTO scan_memory (content, memory_type, tags, scan_id, target)
                VALUES (:content, :mtype, :tags, :scan_id, :target)
            """), {
                "content": content,
                "mtype": memory_type,
                "tags": tags,
                "scan_id": scan_id,
                "target": target,
            })
            conn.commit()

        return f"Stored {memory_type} memory ({len(content)} chars)"
    except Exception as e:
        return f"ERROR: Memory store failed: {e}"


# ── Human chat interaction ───────────────────────────────────────────────

def _handle_ask_human(input: dict, scan_context: dict | None) -> str:
    """Agent asks the human a question and waits for a response."""
    try:
        question = input["question"]
        scan_id = scan_context.get("scan_id", "") if scan_context else ""
        if not scan_id:
            return "ERROR: No scan context for human interaction"

        import redis
        r = redis.from_url(_REDIS_URL)

        # Post agent's question to chat history
        agent_msg = json.dumps({
            "role": "agent",
            "message": question,
            "type": "question",
            "timestamp": time.strftime("%H:%M:%S"),
            "ts": time.time(),
        })
        r.rpush(f"scan:chat:history:{scan_id}", agent_msg)
        r.expire(f"scan:chat:history:{scan_id}", 86400)

        # Log it as activity
        _log_activity(scan_id, {
            "type": "chat",
            "direction": "agent_ask",
            "message": question[:200],
            "timestamp": time.strftime("%H:%M:%S"),
        })

        # Wait for human response (poll inbox, max 5 minutes)
        timeout = input.get("timeout", 300)
        start = time.time()
        while time.time() - start < timeout:
            reply = r.lpop(f"scan:chat:inbox:{scan_id}")
            if reply:
                data = json.loads(reply.decode() if isinstance(reply, bytes) else reply)
                human_msg = data.get("message", "")
                log.info("Scan %s: received human response: %s", scan_id, human_msg[:100])
                return f"[HUMAN RESPONSE]: {human_msg}"
            time.sleep(2)  # poll every 2 seconds

        return "[HUMAN RESPONSE]: (no response within timeout — continue autonomously)"

    except Exception as e:
        return f"ERROR: ask_human failed: {e}"


def _check_human_messages(scan_id: str) -> str | None:
    """Check if the human sent any chat messages. Non-blocking."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        msg = r.lpop(f"scan:chat:inbox:{scan_id}")
        if msg:
            data = json.loads(msg.decode() if isinstance(msg, bytes) else msg)
            return data.get("message", "")
        return None
    except Exception:
        return None


def _post_agent_chat(scan_id: str, message: str, msg_type: str = "info"):
    """Post an agent message to the chat history."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        agent_msg = json.dumps({
            "role": "agent",
            "message": message,
            "type": msg_type,
            "timestamp": time.strftime("%H:%M:%S"),
            "ts": time.time(),
        })
        r.rpush(f"scan:chat:history:{scan_id}", agent_msg)
        r.expire(f"scan:chat:history:{scan_id}", 86400)
    except Exception:
        pass


# ── Loop detection ───────────────────────────────────────────────────────

class LoopDetector:
    """Tracks tool calls and detects repetitive patterns."""

    def __init__(self):
        self.call_log = []         # [(name, input_hash)]
        self.call_counter = Counter()  # {(name, hash): count}

    def record(self, name: str, input: dict) -> str | None:
        """Record a tool call. Returns a warning if loop detected."""
        # Create a stable hash of the call
        key = (name, json.dumps(input, sort_keys=True)[:500])
        self.call_log.append(key)
        self.call_counter[key] += 1

        count = self.call_counter[key]
        if count >= SAME_TOOL_LIMIT:
            return (
                f"WARNING: You have called '{name}' with the same arguments {count} times. "
                f"This looks like a loop. Try a different approach or tool."
            )

        # Check for oscillation patterns (A→B→A→B)
        if len(self.call_log) >= 6:
            recent = self.call_log[-6:]
            if recent[0] == recent[2] == recent[4] and recent[1] == recent[3] == recent[5]:
                return (
                    "WARNING: Detected oscillating pattern in your tool calls. "
                    "You are alternating between the same two actions. Break the pattern."
                )

        return None

    @property
    def total_calls(self):
        return len(self.call_log)

    def summary(self) -> str:
        """Summarize tool usage for the execution monitor."""
        tool_counts = Counter(name for name, _ in self.call_log)
        parts = [f"{name}: {count}" for name, count in tool_counts.most_common()]
        return ", ".join(parts)


# ── Execution monitor ────────────────────────────────────────────────────

def _run_execution_monitor(client, messages: list, loop_detector: LoopDetector,
                           target: str, scan_type: str) -> str | None:
    """Run a separate LLM call to review agent progress and suggest pivots."""
    try:
        summary = loop_detector.summary()
        total = loop_detector.total_calls

        # Collect recent tool names and results
        recent_actions = []
        for msg in messages[-10:]:
            content = msg.get("content", "")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "tool_result":
                            text = str(item.get("content", ""))[:200]
                            recent_actions.append(f"  Result: {text}")
                    elif hasattr(item, "name"):
                        recent_actions.append(f"  Tool: {item.name}")

        monitor_prompt = (
            f"You are an execution monitor reviewing the progress of a {scan_type} scan against {target}.\n\n"
            f"Tool call summary ({total} total calls): {summary}\n\n"
            f"Recent actions:\n" + "\n".join(recent_actions[-20:]) + "\n\n"
            f"Assess:\n"
            f"1. Is the agent making progress or stuck in a loop?\n"
            f"2. Are there important scan areas being missed?\n"
            f"3. Should the agent change strategy?\n\n"
            f"Provide a brief (2-3 sentence) recommendation. If the agent is doing well, say so."
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": monitor_prompt}],
        )

        text = "".join(b.text for b in response.content if hasattr(b, "text"))
        return f"[EXECUTION MONITOR]: {text}" if text else None

    except Exception as e:
        log.warning("Execution monitor failed: %s", e)
        return None


# ── Chain summarization ──────────────────────────────────────────────────

def _estimate_chain_size(messages: list) -> int:
    """Estimate total character size of the message chain."""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    total += len(str(item.get("content", "")))
                else:
                    total += len(str(item))
    return total


def _find_safe_split(messages: list, keep_recent: int) -> int:
    """Find a safe split point that doesn't break tool_use/tool_result pairs.

    Returns the index where 'to_keep' should start. The message at this index
    must be a 'user' message with plain text content (not tool_results), so
    the Anthropic API sees a clean conversation boundary.
    """
    # Start from the desired split point and walk backwards to find a safe boundary
    ideal_split = max(1, len(messages) - keep_recent)

    for i in range(ideal_split, 0, -1):
        msg = messages[i]
        content = msg.get("content", "")
        # Safe if it's a user message with plain string content (not tool_results)
        if msg.get("role") == "user" and isinstance(content, str):
            return i
        # Also safe if it's an assistant message with plain text (no tool_use blocks)
        if msg.get("role") == "assistant" and isinstance(content, str):
            return i

    return ideal_split  # fallback


def _summarize_chain(client, messages: list) -> list:
    """Summarize older messages to reduce context size, keeping recent ones intact.

    Critical: maintains tool_use/tool_result pairing in the kept portion to avoid
    Anthropic API 400 errors ('unexpected tool_use_id found in tool_result blocks').
    """
    if len(messages) <= KEEP_RECENT + 1:
        return messages

    # Find a safe split point that doesn't break tool_use/tool_result pairs
    split_idx = _find_safe_split(messages, KEEP_RECENT)

    to_summarize = messages[1:split_idx]  # skip first user message
    to_keep = messages[split_idx:]

    if not to_summarize:
        return messages  # nothing to summarize

    # Build a text representation of old messages
    old_text_parts = []
    for msg in to_summarize:
        role = msg.get("role", "?")
        content = msg.get("content", "")
        if isinstance(content, str):
            old_text_parts.append(f"[{role}]: {content[:2000]}")
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "tool_result":
                        old_text_parts.append(f"[tool_result]: {str(item.get('content', ''))[:1000]}")
                elif hasattr(item, "name"):
                    old_text_parts.append(f"[tool_use: {item.name}]: {str(getattr(item, 'input', ''))[:500]}")

    old_text = "\n".join(old_text_parts)
    if len(old_text) > 30000:
        old_text = old_text[:30000] + "\n... [older history truncated]"

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{
                "role": "user",
                "content": (
                    "Summarize the following scan agent conversation history. "
                    "Preserve: key findings, tools run and their results, vulnerabilities discovered, "
                    "and any important decisions. Be concise but complete.\n\n"
                    f"{old_text}"
                ),
            }],
        )
        summary = "".join(b.text for b in response.content if hasattr(b, "text"))
    except Exception:
        summary = old_text[:3000] + "\n... [summarization failed, truncated]"

    # Reconstruct: original user msg + summary pair + kept messages
    # Ensure alternating user/assistant pattern
    summarized_messages = [
        messages[0],  # original user message
        {"role": "assistant", "content": f"[CONVERSATION SUMMARY — earlier actions compressed]\n{summary}"},
        {"role": "user", "content": (
            "This is a summary of your earlier work. Continue the scan from where you left off. "
            "Do NOT repeat tools you have already run. Focus on areas not yet covered."
        )},
    ]

    # Only append to_keep if it starts with an assistant message (to maintain alternation)
    if to_keep and to_keep[0].get("role") == "assistant":
        summarized_messages.extend(to_keep)
    elif to_keep and to_keep[0].get("role") == "user":
        # Merge the first user message into our summary prompt
        first_content = to_keep[0].get("content", "")
        if isinstance(first_content, str):
            summarized_messages[-1]["content"] += "\n\n" + first_content
        summarized_messages.extend(to_keep[1:])
    else:
        summarized_messages.extend(to_keep)

    log.info("Chain summarized: %d messages → %d messages (split at %d)",
             len(messages), len(summarized_messages), split_idx)
    return summarized_messages


# ── Reflector pattern ────────────────────────────────────────────────────

def _run_reflector(client, text_output: str, system_prompt: str, tools: list) -> list | None:
    """When agent produces text instead of tool calls, redirect back to tool use."""
    try:
        reflector_prompt = (
            "The scanning agent produced text output instead of using a tool. "
            "As the reflector, analyze the agent's output and determine what tool call "
            "it should make next. If the agent seems to be done scanning, it should use "
            "the 'report' tool. If it needs to continue, determine the most appropriate "
            "next tool call.\n\n"
            f"Agent's text output:\n{text_output[:3000]}\n\n"
            "Respond with a brief instruction telling the agent what to do next."
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": reflector_prompt}],
        )

        redirect = "".join(b.text for b in response.content if hasattr(b, "text"))
        return redirect

    except Exception:
        return None


# ── Planning step ────────────────────────────────────────────────────────

def _generate_plan(client, target: str, scan_type: str, config: dict) -> str:
    """Generate a structured scan plan before execution."""
    try:
        plan_prompt = (
            f"You are planning a {scan_type} scan of {target}.\n\n"
            f"Create a focused plan with 3-7 steps. For each step, specify:\n"
            f"1. What to check/scan\n"
            f"2. Which tools to use\n"
            f"3. What findings to look for\n\n"
            f"Be specific and actionable. Order steps from broad reconnaissance to deep analysis.\n"
            f"Config: {json.dumps(config) if config else 'default'}"
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": plan_prompt}],
        )

        plan = "".join(b.text for b in response.content if hasattr(b, "text"))
        return plan

    except Exception:
        return ""


# ── Activity logging ─────────────────────────────────────────────────────

def _log_activity(scan_id: str, activity: dict):
    """Push scan activity to Redis for live dashboard + index to ES."""
    try:
        import redis
        r = redis.from_url(_REDIS_URL)
        r.rpush(f"scan:activity:{scan_id}", json.dumps(activity))
        r.ltrim(f"scan:activity:{scan_id}", -500, -1)
        r.expire(f"scan:activity:{scan_id}", 86400)
    except Exception:
        pass
    # Dual-write to Elasticsearch
    try:
        from modules.infra.elasticsearch import index_doc
        from datetime import datetime, timezone
        es_doc = {**activity, "scan_id": scan_id, "timestamp": datetime.now(timezone.utc).isoformat()}
        index_doc("scanner-scan-activity", es_doc)
    except Exception:
        pass


# ── Main scan loop ───────────────────────────────────────────────────────

def run_scan(scan_id: str, target: str, scan_type: str, config: dict | None = None):
    """Run an AI-driven scan against a target with PentAGI-inspired features."""
    client = anthropic.Anthropic()
    storage = get_storage()
    queue = get_queue()
    config = config or {}

    scan_context = {
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type,
    }

    # ── Planning step ──
    _log_activity(scan_id, {
        "type": "phase",
        "phase": "planning",
        "message": "Generating scan plan...",
        "timestamp": time.strftime("%H:%M:%S"),
    })

    plan = _generate_plan(client, target, scan_type, config)
    log.info("Scan %s: plan generated (%d chars)", scan_id, len(plan))

    # ── Build system prompt with plan ──
    system_prompt = get_prompt(scan_type, target=target, config=config)
    if plan:
        system_prompt += (
            f"\n\n## Scan Plan\n"
            f"Follow this plan, adapting as you discover new information:\n\n{plan}\n\n"
            f"After each major step, assess whether the plan needs adjustment."
        )

    # Add summarization awareness
    system_prompt += (
        "\n\n## Context Management\n"
        "If you see a [CONVERSATION SUMMARY], it means your earlier actions were compressed "
        "to save context space. Trust the summary — do NOT re-run tools already mentioned in it. "
        "Continue from where the summary leaves off."
    )

    # Add chat/human interaction awareness
    system_prompt += (
        "\n\n## Human Interaction\n"
        "A human operator may send you messages during the scan. These appear as "
        "[HUMAN MESSAGE]: in the conversation. Respond to them appropriately — they may "
        "provide guidance, ask questions, or request changes to your approach.\n\n"
        "You can also proactively ask the human for input using the `ask_human` tool when:\n"
        "- You find a critical vulnerability that needs immediate attention\n"
        "- You need permission before running aggressive/intrusive tests\n"
        "- You're unsure about scope or want to suggest alternative approaches\n"
        "- You want to offer the human a choice of next steps\n"
        "Keep scanning while waiting — don't block on non-critical questions."
    )

    # Post initial agent message to chat
    _post_agent_chat(scan_id, f"Starting {scan_type} scan of {target}. I'll keep you updated on progress.", "status")

    # All tools including sub-agents, search, and memory
    all_tools = TOOLS + SUBAGENT_TOOLS

    messages = [{"role": "user", "content": f"Begin scanning {target} now."}]

    start_time = time.time()
    report = None
    commands_executed = 0
    loop_detector = LoopDetector()
    reflector_attempts = 0
    max_reflector_attempts = 3

    _log_activity(scan_id, {
        "type": "phase",
        "phase": "scanning",
        "message": "Starting scan execution...",
        "timestamp": time.strftime("%H:%M:%S"),
    })

    iteration = 0
    while iteration < MAX_ITERATIONS:
        iteration += 1

        # ── Chain summarization ──
        chain_size = _estimate_chain_size(messages)
        if chain_size > SUMMARIZE_THRESHOLD:
            _log_activity(scan_id, {
                "type": "system",
                "message": f"Summarizing conversation ({chain_size} chars → compressed)",
                "timestamp": time.strftime("%H:%M:%S"),
            })
            messages = _summarize_chain(client, messages)

        # ── Execution monitor ──
        if loop_detector.total_calls > 0 and loop_detector.total_calls % MONITOR_INTERVAL == 0:
            monitor_msg = _run_execution_monitor(
                client, messages, loop_detector, target, scan_type,
            )
            if monitor_msg:
                _log_activity(scan_id, {
                    "type": "monitor",
                    "message": monitor_msg,
                    "timestamp": time.strftime("%H:%M:%S"),
                })
                # Inject monitor feedback into the conversation
                messages.append({"role": "user", "content": monitor_msg})

        # ── Check for human chat messages ──
        human_msg = _check_human_messages(scan_id)
        if human_msg:
            log.info("Scan %s: injecting human message: %s", scan_id, human_msg[:100])
            _log_activity(scan_id, {
                "type": "chat",
                "direction": "human",
                "message": human_msg[:200],
                "timestamp": time.strftime("%H:%M:%S"),
            })
            # Ensure proper message alternation
            if messages and messages[-1].get("role") == "user":
                # Append to existing user message
                last_content = messages[-1].get("content", "")
                if isinstance(last_content, str):
                    messages[-1]["content"] = last_content + f"\n\n[HUMAN MESSAGE]: {human_msg}"
                else:
                    # tool_results list — add a new user message pair
                    messages.append({"role": "assistant", "content": "Acknowledged. Let me address the human's message."})
                    messages.append({"role": "user", "content": f"[HUMAN MESSAGE]: {human_msg}"})
            else:
                messages.append({"role": "user", "content": f"[HUMAN MESSAGE]: {human_msg}"})

        # ── Main LLM call ──
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=16000,
            system=system_prompt,
            tools=all_tools,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            reflector_attempts = 0  # reset on successful tool use
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    # ── Loop detection ──
                    loop_warning = loop_detector.record(block.name, block.input)
                    if loop_warning:
                        _log_activity(scan_id, {
                            "type": "warning",
                            "message": loop_warning,
                            "timestamp": time.strftime("%H:%M:%S"),
                        })

                    if block.name == "run_command":
                        commands_executed += 1
                        cmd = block.input.get("command", "")[:200]
                        queue.publish(f"scan-progress:{scan_id}", {
                            "scan_id": scan_id,
                            "status": "running",
                            "command": cmd,
                            "commands_executed": commands_executed,
                            "iteration": iteration,
                        })
                        _log_activity(scan_id, {
                            "type": "command",
                            "tool": block.name,
                            "command": cmd,
                            "index": commands_executed,
                            "timestamp": time.strftime("%H:%M:%S"),
                        })
                    elif block.name.startswith("delegate_to_"):
                        agent_type = block.name.replace("delegate_to_", "")
                        _log_activity(scan_id, {
                            "type": "delegation",
                            "agent": agent_type,
                            "task": str(block.input.get("task", ""))[:200],
                            "timestamp": time.strftime("%H:%M:%S"),
                        })
                    elif block.name in ("web_search", "exploit_search"):
                        _log_activity(scan_id, {
                            "type": "search",
                            "tool": block.name,
                            "query": str(block.input.get("query", ""))[:200],
                            "timestamp": time.strftime("%H:%M:%S"),
                        })
                    elif block.name in ("search_memory", "store_memory"):
                        _log_activity(scan_id, {
                            "type": "memory",
                            "tool": block.name,
                            "input": str(block.input)[:200],
                            "timestamp": time.strftime("%H:%M:%S"),
                        })
                    elif block.name == "ask_human":
                        _log_activity(scan_id, {
                            "type": "chat",
                            "direction": "agent_ask",
                            "message": str(block.input.get("question", ""))[:200],
                            "timestamp": time.strftime("%H:%M:%S"),
                        })
                    elif block.name != "report":
                        _log_activity(scan_id, {
                            "type": "tool",
                            "tool": block.name,
                            "input": str(block.input)[:200],
                            "timestamp": time.strftime("%H:%M:%S"),
                        })

                    result = handle_tool(block.name, block.input, scan_context)

                    # Append loop warning to tool result if detected
                    if loop_warning:
                        result = f"{result}\n\n{loop_warning}"

                    if result == "__REPORT__":
                        report = block.input
                        report["scan_metadata"] = {
                            **report.get("scan_metadata", {}),
                            "duration_seconds": int(time.time() - start_time),
                            "commands_executed": commands_executed,
                            "total_tool_calls": loop_detector.total_calls,
                            "scan_id": scan_id,
                            "target": target,
                            "scan_type": scan_type,
                        }
                        if plan:
                            report["scan_metadata"]["plan"] = plan[:2000]
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Report submitted successfully.",
                        })
                    else:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

            if report:
                break

        elif response.stop_reason == "end_turn":
            text = "".join(
                b.text for b in response.content if hasattr(b, "text")
            )

            # Post agent's text to chat so human can see it
            if text.strip():
                _post_agent_chat(scan_id, text[:1000], "thinking")

            # ── Reflector pattern ──
            if not report and reflector_attempts < max_reflector_attempts:
                reflector_attempts += 1
                _log_activity(scan_id, {
                    "type": "reflector",
                    "message": f"Agent produced text instead of tool call (attempt {reflector_attempts})",
                    "timestamp": time.strftime("%H:%M:%S"),
                })

                redirect = _run_reflector(client, text, system_prompt, all_tools)
                if redirect:
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": (
                        f"{redirect}\n\n"
                        "You MUST use a tool now. If you are done scanning, call the 'report' tool "
                        "with your structured findings. Do not respond with text only."
                    )})
                    continue

            # If reflector exhausted or no report, create fallback report
            if not report:
                report = {
                    "summary": text,
                    "risk_score": 0,
                    "findings": [],
                    "scan_metadata": {
                        "duration_seconds": int(time.time() - start_time),
                        "commands_executed": commands_executed,
                        "total_tool_calls": loop_detector.total_calls,
                        "scan_id": scan_id,
                        "target": target,
                        "scan_type": scan_type,
                    },
                }
            break

    # ── Approaching limit warning ──
    if iteration >= MAX_ITERATIONS and not report:
        log.warning("Scan %s hit max iterations (%d)", scan_id, MAX_ITERATIONS)
        report = {
            "summary": "Scan reached maximum iteration limit. Partial results below.",
            "risk_score": 0,
            "findings": [],
            "scan_metadata": {
                "duration_seconds": int(time.time() - start_time),
                "commands_executed": commands_executed,
                "total_tool_calls": loop_detector.total_calls,
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "warning": "max iterations reached",
            },
        }

    # ── Store report ──
    storage.put_json(f"scans/{scan_id}/report.json", report)

    # ── Index findings to Elasticsearch ──
    try:
        from modules.infra.elasticsearch import bulk_index
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        es_findings = []
        for f in report.get("findings", []):
            es_findings.append({
                "timestamp": now,
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "severity": f.get("severity"),
                "title": f.get("title"),
                "description": f.get("description", ""),
                "category": f.get("category", ""),
                "remediation": f.get("remediation", ""),
                "cvss_score": f.get("cvss_score"),
                "cve_id": f.get("cve_id"),
                "tool": f.get("tool"),
                "evidence": f.get("evidence", ""),
                "risk_score": report.get("risk_score"),
            })
        if es_findings:
            bulk_index("scanner-scan-findings", es_findings)
    except Exception:
        pass

    # Store conversation log
    conv_log = [{"role": m["role"], "content": str(m["content"])[:5000]} for m in messages]
    storage.put_json(f"scans/{scan_id}/agent_log.json", conv_log)

    # Generate HTML report
    try:
        from modules.reports.generator import ReportGenerator
        generator = ReportGenerator()
        html_report = generator.generate_html(report, {
            "target": target,
            "scan_type": scan_type,
            "scan_id": scan_id,
        })
        storage.put(f"scans/{scan_id}/report.html", html_report)
    except Exception:
        pass

    # Send notifications
    try:
        from modules.notifications.dispatcher import NotificationDispatcher, build_scan_notification
        import asyncio

        notification_channels = json.loads(os.getenv("NOTIFICATION_CHANNELS", "[]"))
        if notification_channels:
            dispatcher = NotificationDispatcher(notification_channels)
            notification = build_scan_notification(scan_id, target, report)
            asyncio.run(dispatcher.dispatch(notification))
    except Exception:
        pass

    # Notify completion
    queue.publish(f"scan-progress:{scan_id}", {
        "scan_id": scan_id,
        "status": "completed",
        "risk_score": report.get("risk_score", 0),
        "findings_count": len(report.get("findings", [])),
        "total_tool_calls": loop_detector.total_calls,
    })

    log.info(
        "Scan %s completed: %d findings, risk %s, %d tool calls in %ds",
        scan_id,
        len(report.get("findings", [])),
        report.get("risk_score", 0),
        loop_detector.total_calls,
        int(time.time() - start_time),
    )

    return report


# ── Validation / Exploit Proof-of-Concept Agent ─────────────────────────

VALIDATION_TOOLS = [
    {
        "name": "run_command",
        "description": (
            "Execute a shell command in the sandbox environment. "
            "You have access to: python3, curl, nmap, sqlmap, nuclei, nikto, "
            "openssl, dig, whois, and all standard Linux tools. "
            "Use this to run exploit scripts, test payloads, or verify vulnerabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 120},
            },
            "required": ["command"],
        },
    },
    {
        "name": "write_file",
        "description": "Write a file (exploit script, PoC code, config file, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from the filesystem.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "http_request",
        "description": "Make an HTTP request to test endpoints, submit payloads, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "default": {}},
                "body": {"type": "string", "description": "Request body"},
                "follow_redirects": {"type": "boolean", "default": True},
            },
            "required": ["url"],
        },
    },
    {
        "name": "submit_result",
        "description": (
            "Submit your validation result. Call this when done with your analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "validated": {
                    "type": "boolean",
                    "description": "True if vulnerability was confirmed exploitable",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Assessed severity after validation",
                },
                "summary": {
                    "type": "string",
                    "description": "Summary of what was tested and found",
                },
                "proof_of_concept": {
                    "type": "string",
                    "description": "Step-by-step PoC instructions to reproduce",
                },
                "commands_used": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Commands/scripts used during validation",
                },
                "evidence": {
                    "type": "string",
                    "description": "Raw output/screenshots proving the vulnerability",
                },
                "remediation": {
                    "type": "string",
                    "description": "Specific remediation steps",
                },
                "risk_rating": {
                    "type": "string",
                    "description": "CVSS-like risk assessment",
                },
            },
            "required": ["validated", "summary", "proof_of_concept"],
        },
    },
]


def run_validation(task_id: str, user_id: str, request: dict):
    """
    Run a validation/exploit PoC task.

    The AI agent attempts to validate a specific security finding by:
    1. Analyzing the vulnerability details
    2. Writing and running exploit/test scripts
    3. Documenting exact reproduction steps
    4. Producing a PoC report

    Results are streamed to the global chat via Redis.
    """
    import redis
    r = redis.from_url(_REDIS_URL)
    chat_key = f"global:chat:{user_id}"

    def _post_chat(message, msg_type="progress"):
        msg = json.dumps({
            "role": "agent",
            "message": message,
            "type": msg_type,
            "task_id": task_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "ts": time.time(),
        })
        r.rpush(chat_key, msg)
        r.expire(chat_key, 86400 * 7)

    target = request.get("target", "")
    finding = request.get("finding", "")
    scan_id = request.get("scan_id", "")
    goal = request.get("goal", "Validate and document this vulnerability with a proof of concept")
    report_context = request.get("report_context", "")

    _post_chat(f"Starting validation task for: **{finding[:100]}**\nTarget: {target}")

    client = anthropic.Anthropic()

    system_prompt = (
        "You are an expert penetration tester and security researcher. "
        "Your task is to VALIDATE a specific security finding by attempting to exploit it "
        "in a controlled manner. You must document everything precisely.\n\n"
        f"## Target\n{target}\n\n"
        f"## Finding to Validate\n{finding}\n\n"
        f"## Goal\n{goal}\n\n"
    )
    if report_context:
        system_prompt += f"## Scan Report Context\n{report_context[:10000]}\n\n"

    system_prompt += (
        "## Rules of Engagement\n"
        "1. Only test the SPECIFIC vulnerability described — do not expand scope\n"
        "2. Use the minimum necessary payload to prove exploitability\n"
        "3. Do NOT cause data loss, service disruption, or permanent changes\n"
        "4. Document every step so it can be reproduced\n"
        "5. Write Python/bash scripts for complex exploit chains\n"
        "6. If you cannot validate, explain WHY (false positive, patched, etc.)\n"
        "7. Include raw command output as evidence\n\n"
        "## Approach\n"
        "1. Analyze the vulnerability and plan your validation approach\n"
        "2. Verify the target is reachable and identify the exact component\n"
        "3. Craft and send test payloads\n"
        "4. Capture evidence of success or failure\n"
        "5. Write a PoC script that can reproduce the finding\n"
        "6. Call submit_result with your complete findings\n\n"
        "Think step by step. Be thorough but focused."
    )

    messages = [{"role": "user", "content": f"Validate this finding: {finding}\n\nTarget: {target}\n\nGoal: {goal}"}]

    start_time = time.time()
    max_iterations = 40
    result = None

    for iteration in range(max_iterations):
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=8000,
                system=system_prompt,
                tools=VALIDATION_TOOLS,
                messages=messages,
            )
        except Exception as e:
            _post_chat(f"Error calling AI: {e}", "error")
            break

        if response.stop_reason == "tool_use":
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    if block.name == "submit_result":
                        result = block.input
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Result submitted.",
                        })
                    else:
                        # Log progress to chat
                        if block.name == "run_command":
                            cmd = block.input.get("command", "")
                            _post_chat(f"`$ {cmd[:200]}`", "command")
                        elif block.name == "write_file":
                            _post_chat(f"Writing: `{block.input.get('path', '')}`", "file")

                        tool_result = handle_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": tool_result,
                        })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

            if result:
                break

        elif response.stop_reason == "end_turn":
            text = "".join(b.text for b in response.content if hasattr(b, "text"))
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": (
                "You must call submit_result with your findings, even if you could not validate "
                "the vulnerability. Explain what you tested and what the outcome was."
            )})
            if iteration > max_iterations - 3:
                break

    # Build final response
    duration = int(time.time() - start_time)

    if result:
        validated = result.get("validated", False)
        status_emoji = "CONFIRMED" if validated else "NOT CONFIRMED"
        severity = result.get("severity", "unknown")

        report_msg = f"## Validation Complete: {status_emoji}\n\n"
        report_msg += f"**Severity:** {severity}\n"
        report_msg += f"**Duration:** {duration}s\n\n"
        report_msg += f"### Summary\n{result.get('summary', 'N/A')}\n\n"
        report_msg += f"### Proof of Concept\n{result.get('proof_of_concept', 'N/A')}\n\n"

        if result.get("commands_used"):
            report_msg += "### Commands Used\n"
            for cmd in result["commands_used"]:
                report_msg += f"```\n{cmd}\n```\n"
            report_msg += "\n"

        if result.get("evidence"):
            report_msg += f"### Evidence\n```\n{result['evidence'][:3000]}\n```\n\n"

        if result.get("remediation"):
            report_msg += f"### Remediation\n{result['remediation']}\n"

        _post_chat(report_msg, "validation_result")

        # Store validation result
        storage = get_storage()
        storage.put_json(f"validations/{task_id}/result.json", {
            "task_id": task_id,
            "target": target,
            "finding": finding,
            "result": result,
            "duration_seconds": duration,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    else:
        _post_chat(
            f"Validation task completed after {duration}s but no structured result was produced. "
            "The agent may have encountered issues during testing.",
            "error",
        )

    return result
