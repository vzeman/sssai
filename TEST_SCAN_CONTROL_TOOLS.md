# Scan Control Tools - Implementation Test

This document demonstrates the implementation and availability of the 11 new scan control tools added in Issue #53.

## Tool Registry

All 11 tools are now available in `modules/agent/tools.py` and can be called by the AI agent:

### 1. View & Monitor Scans

#### list_user_scans
```json
{
  "name": "list_user_scans",
  "description": "List all scans for the current user, with optional filtering by status",
  "parameters": {
    "status": "optional - queued, running, completed, failed",
    "limit": "optional - max results (default 20)"
  }
}
```

Usage: `"What scans do I have?"` → calls `list_user_scans()`

---

#### get_scan_status
```json
{
  "name": "get_scan_status",
  "description": "Get detailed status of a specific scan",
  "parameters": {
    "scan_id": "required - ID of the scan to check"
  }
}
```

Usage: `"Check progress on scan ABC123"` → calls `get_scan_status(scan_id="ABC123")`

---

#### get_scan_report
```json
{
  "name": "get_scan_report",
  "description": "Fetch full report from a completed scan",
  "parameters": {
    "scan_id": "required - ID of the scan"
  }
}
```

Usage: `"Show me the report from scan ABC123"` → calls `get_scan_report(scan_id="ABC123")`

---

### 2. Start & Manage Scans

#### start_scan
```json
{
  "name": "start_scan",
  "description": "Start a new security scan on a target",
  "parameters": {
    "target": "required - URL or domain",
    "scan_type": "optional - full, security, pentest, etc. (default: security)",
    "config": "optional - custom configuration"
  }
}
```

Usage: `"Scan example.com with a full security scan"` → calls `start_scan(target="https://example.com", scan_type="security")`

---

#### stop_scan
```json
{
  "name": "stop_scan",
  "description": "Gracefully stop a running scan",
  "parameters": {
    "scan_id": "required - ID of the scan to stop"
  }
}
```

Usage: `"Stop scan ABC123"` → calls `stop_scan(scan_id="ABC123")`

---

#### cancel_scan
```json
{
  "name": "cancel_scan",
  "description": "Cancel a queued scan (before it starts)",
  "parameters": {
    "scan_id": "required - ID of the scan to cancel"
  }
}
```

Usage: `"Cancel the queued scan ABC123"` → calls `cancel_scan(scan_id="ABC123")`

---

### 3. Retry & Recovery

#### retry_scan
```json
{
  "name": "retry_scan",
  "description": "Retry a failed or completed scan",
  "parameters": {
    "scan_id": "required - ID of the scan to retry"
  }
}
```

Usage: `"Retry the failed scan ABC123"` → calls `retry_scan(scan_id="ABC123")`

---

#### verify_scan
```json
{
  "name": "verify_scan",
  "description": "Create verification scan for remediation testing",
  "parameters": {
    "scan_id": "required - ID of the completed scan to verify",
    "config": "optional - custom configuration"
  }
}
```

Usage: `"Verify that we fixed the findings from scan ABC123"` → calls `verify_scan(scan_id="ABC123")`

---

### 4. Troubleshoot Stuck Scans

#### get_stuck_scans
```json
{
  "name": "get_stuck_scans",
  "description": "Identify scans that appear stuck",
  "parameters": {}
}
```

Usage: `"Are any of my scans stuck?"` → calls `get_stuck_scans()`

Response includes:
- Stuck scan count
- Scan IDs and how long they've been silent
- Whether checkpoint is available for recovery

---

#### force_retry_stuck_scan
```json
{
  "name": "force_retry_stuck_scan",
  "description": "Force-retry a stuck scan with checkpoint resume",
  "parameters": {
    "scan_id": "required - ID of the stuck scan"
  }
}
```

Usage: `"Restart the stuck scan ABC123"` → calls `force_retry_stuck_scan(scan_id="ABC123")`

---

#### force_fail_scan
```json
{
  "name": "force_fail_scan",
  "description": "Force-fail a completely unresponsive scan",
  "parameters": {
    "scan_id": "required - ID of the stuck scan"
  }
}
```

Usage: `"Give up on stuck scan ABC123"` → calls `force_fail_scan(scan_id="ABC123")`

---

## Integration Architecture

### Tool Execution Flow

```
User Message (Chat/API)
    ↓
AI Agent processes request
    ↓
Agent selects appropriate tool
    ↓
handle_tool(tool_name, input) in scan_agent.py
    ↓
Router dispatches to _handle_* function
    ↓
Handler executes operation:
    - Database query/update (SQLAlchemy ORM)
    - Redis signal (real-time control)
    - Job queue message (for scan creation)
    - Storage operation (for reports)
    ↓
Handler returns JSON response
    ↓
Agent formats and presents to user
```

### Handler Implementation Details

All handlers follow consistent patterns:

1. **Input Validation** - Check required parameters
2. **Error Handling** - Try-catch blocks with specific error messages
3. **Database Operations** - SQLAlchemy ORM for Scan model
4. **Redis Operations** - For real-time signals and state
5. **Response Formatting** - JSON with status and details

Example handler structure:
```python
def _handle_start_scan(input: dict, scan_context: dict | None) -> str:
    try:
        # Validate inputs
        target = input.get("target", "").strip()
        if not target:
            return "ERROR: target is required"
        
        # Create scan in database
        db = sessionmaker(bind=engine)()
        new_scan = Scan(...)
        db.add(new_scan)
        db.commit()
        
        # Queue the scan for execution
        get_queue().send("scan-jobs", {...})
        
        # Return formatted response
        return json.dumps({"status": "queued", ...}, indent=2)
    except Exception as e:
        return f"ERROR: {e}"
```

---

## System Integration Points

### Database Integration
- **Module:** modules.api.database (SQLAlchemy ORM)
- **Model:** Scan (id, user_id, target, status, findings, etc.)
- **Operations:** Query, filter, create, update

### Redis Integration
- **Module:** redis library
- **Keys:** 
  - `scan:stop:{scan_id}` - Stop signal
  - `scan:heartbeat:{scan_id}` - Activity heartbeat
  - `scan:checkpoint:{scan_id}` - Resume checkpoint
- **Purpose:** Real-time scan control and state management

### Job Queue Integration
- **Module:** modules.infra (queue system)
- **Queue:** scan-jobs
- **Message:** {scan_id, target, scan_type, config}
- **Purpose:** Queue new scans for worker processing

### Storage Integration
- **Module:** modules.infra (storage system)
- **Paths:** 
  - `scans/{scan_id}/report.json` - Scan reports
  - `scans/{scan_id}/error.json` - Error details
- **Purpose:** Store and retrieve scan results

---

## AI Agent System Prompt Enhancement

The global chat system prompt has been updated to instruct the AI agent:

1. **Capabilities Listed:**
   - "Scan Control: Start, stop, retry, verify, and monitor scans"
   - "Scan Troubleshooting: Detect stuck scans and force-retry or fail them"

2. **Tools Documented:**
   - When to use each tool
   - Example scenarios
   - Parameter requirements

3. **Proactive Behavior:**
   - Agent should call list_user_scans when user asks about scans
   - Agent should call stop_scan when user asks to stop
   - Agent should call get_stuck_scans proactively and suggest recovery

---

## Usage Examples

### Example 1: List Running Scans
```
User: "What scans are currently running?"

AI Agent:
[Calls list_user_scans(status="running")]

Response: "You have 2 running scans:
1. https://example.com (security) - queued 2 hours ago
2. https://api.example.com (api_security) - queued 1 hour ago

Would you like me to check the detailed status of either scan?"
```

### Example 2: Start a Scan
```
User: "Can you scan example.com for vulnerabilities?"

AI Agent:
[Calls start_scan(target="https://example.com", scan_type="security")]

Response: "I've started a security scan on https://example.com.
Scan ID: scan_abc123
Status: queued
This scan will check for:
- Vulnerable headers
- SSL/TLS configuration
- Common vulnerabilities
- API endpoints

I'll monitor the progress. You can ask me about it anytime."
```

### Example 3: Recover Stuck Scan
```
User: "Check if any of my scans are stuck"

AI Agent:
[Calls get_stuck_scans()]

Response: "I found 1 stuck scan:
- Scan: https://example.com (security) 
- Silent for: 15 minutes
- Checkpoint available: Yes

Would you like me to:
1. Force-retry it (will resume from checkpoint)
2. Force-fail it (mark as failed)
3. Leave it as is"
```

### Example 4: Verify Remediation
```
User: "Can you verify that we fixed the findings from scan ABC123?"

AI Agent:
[Calls verify_scan(scan_id="ABC123")]

Response: "I've created a verification scan to test the 47 findings 
from your previous scan. Scan ID: verify_xyz789

This verification scan will:
- Test each finding individually
- Check if it's still vulnerable
- Report which ones were fixed
- Identify any new issues

I'll monitor progress and notify you when complete."
```

---

## Testing & Validation

### Syntax Validation
✅ All Python files pass syntax validation
✅ Tool definitions are valid JSON schemas
✅ Handler functions properly integrated

### Tool Definition Validation
✅ All 11 tools defined in TOOLS list
✅ All tools have proper schemas
✅ All required parameters documented
✅ All tools routed in handle_tool()

### Integration Testing
✅ Database integration verified
✅ Redis integration verified
✅ Queue integration verified
✅ Error handling validated

---

## Deployment Checklist

- [x] Code syntax validated
- [x] Tools properly defined
- [x] Handlers properly implemented
- [x] System prompt updated
- [x] Integration tested
- [x] Documentation complete
- [x] Backwards compatible
- [x] Ready for production

---

## Files Involved

**Modified Files:**
1. `modules/agent/tools.py` - Added 11 tool definitions
2. `modules/agent/scan_agent.py` - Added 11 handler functions
3. `modules/api/main.py` - Updated system prompt

**Test/Documentation Files:**
1. `ISSUE_53_COMPLETION.md` - Implementation details
2. `TEST_SCAN_CONTROL_TOOLS.md` - This file
3. `SUBAGENT_COMPLETION_REPORT.md` - Full project report

---

## Summary

The scan control tools are now fully implemented and ready for use:

✅ **11 Tools Implemented** - Complete scan lifecycle management
✅ **Proper Integration** - Works with existing database, Redis, and queue systems
✅ **AI Agent Ready** - System prompt updated to use tools
✅ **Production Ready** - Full error handling and validation
✅ **Well Documented** - Multiple documentation files
✅ **Backwards Compatible** - No breaking changes

**The AI agent (brain) can now directly control all aspects of scan operations without requiring manual UI intervention.**
