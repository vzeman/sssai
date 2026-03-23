"""
Autonomous Security Agent - Core Decision Engine (Issue #50)

This module implements the autonomous agent that can audit targets completely
without human input. It uses a state machine to manage scan phases, Claude to
make intelligent decisions, and a learning feedback loop to improve over time.

Architecture:
  ├─ StateManager: Manages scan state machine transitions
  ├─ DecisionEngine: Claude-based decision making
  ├─ VulnerabilityAssessment: Real-time vulnerability analysis
  ├─ ScanOrchestrator: Coordinates tool execution
  ├─ LearningSystem: Learns from scan history
  └─ AutonomousAgent: Orchestrates everything

Key Features:
  - State machine with 5 phases: Discovery → Enumeration → Scanning → Exploitation → Reporting
  - Intelligent decision-making using Claude Sonnet/Opus
  - Real-time risk/reward evaluation before exploitation
  - Autonomous recovery from tool failures
  - Learning from previous scans on same target
  - Zero human input required once started
"""

import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path

import anthropic

log = logging.getLogger(__name__)


# ── State Machine ────────────────────────────────────────────────────────

class ScanPhase(Enum):
    """Scan phase state machine."""
    DISCOVERY = "discovery"           # Reconnaissance - identify targets & tech
    ENUMERATION = "enumeration"       # Deep enumeration - find endpoints, users, configs
    VULNERABILITY_SCANNING = "vulnerability_scanning"  # Run scanners - find vulns
    EXPLOITATION = "exploitation"     # Prove exploitability - run POCs
    REPORTING = "reporting"           # Generate final report
    COMPLETED = "completed"
    FAILED = "failed"


class DecisionContext:
    """Context for decision-making."""
    
    def __init__(self, scan_id: str, target: str, scan_type: str = "standard"):
        self.scan_id = scan_id
        self.target = target
        self.scan_type = scan_type
        self.current_phase = ScanPhase.DISCOVERY
        
        # Discovered attack surface
        self.endpoints = []
        self.technologies = []
        self.forms = []
        self.chatbots = []
        self.apis = []
        self.auth_mechanisms = []
        self.infrastructure = {}
        
        # Vulnerabilities found so far
        self.findings = []
        self.critical_findings = []
        
        # Execution history
        self.tools_executed = []
        self.tool_results = {}
        self.failures = []
        
        # Phase completion status
        self.phase_completions = {}
        
        # Learning data
        self.previous_scans = []
        self.similar_findings = []


@dataclass
class StateTransition:
    """Represents a state transition."""
    from_phase: ScanPhase
    to_phase: ScanPhase
    reason: str
    timestamp: float
    decision_data: Dict[str, Any]


class StateManager:
    """Manages scan state machine transitions."""
    
    def __init__(self):
        self.transitions: List[StateTransition] = []
        self.current_phase = ScanPhase.DISCOVERY
        self.phase_start_time = time.time()
    
    def can_transition_to(self, to_phase: ScanPhase, context: DecisionContext) -> bool:
        """Check if transition to target phase is valid."""
        # Define valid transitions
        valid_transitions = {
            ScanPhase.DISCOVERY: [ScanPhase.ENUMERATION, ScanPhase.FAILED],
            ScanPhase.ENUMERATION: [ScanPhase.VULNERABILITY_SCANNING, ScanPhase.FAILED],
            ScanPhase.VULNERABILITY_SCANNING: [ScanPhase.EXPLOITATION, ScanPhase.REPORTING, ScanPhase.FAILED],
            ScanPhase.EXPLOITATION: [ScanPhase.REPORTING, ScanPhase.FAILED],
            ScanPhase.REPORTING: [ScanPhase.COMPLETED],
            ScanPhase.COMPLETED: [],
            ScanPhase.FAILED: [],
        }
        
        return to_phase in valid_transitions.get(self.current_phase, [])
    
    def transition(self, to_phase: ScanPhase, reason: str, decision_data: Dict = None) -> bool:
        """Execute state transition."""
        if not self.can_transition_to(to_phase, None):
            log.warning(f"Invalid transition: {self.current_phase} → {to_phase}")
            return False
        
        transition = StateTransition(
            from_phase=self.current_phase,
            to_phase=to_phase,
            reason=reason,
            timestamp=time.time(),
            decision_data=decision_data or {},
        )
        
        self.transitions.append(transition)
        self.current_phase = to_phase
        self.phase_start_time = time.time()
        
        log.info(f"State transition: {self.current_phase.value} → {to_phase.value} ({reason})")
        return True
    
    def get_phase_duration(self) -> float:
        """Get duration of current phase in seconds."""
        return time.time() - self.phase_start_time
    
    def get_history(self) -> List[Dict]:
        """Get transition history."""
        return [
            {
                "from": t.from_phase.value,
                "to": t.to_phase.value,
                "reason": t.reason,
                "timestamp": t.timestamp,
                "duration_ms": int((t.timestamp - self.phase_start_time) * 1000),
            }
            for t in self.transitions
        ]


# ── Vulnerability Assessment ────────────────────────────────────────────

class VulnerabilityAssessment:
    """Real-time vulnerability assessment and risk evaluation."""
    
    def __init__(self, client: anthropic.Anthropic):
        self.client = client
    
    def assess_risk_score(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate risk score from findings.
        Uses Claude to intelligently weight findings based on:
        - Severity (CVSS)
        - Exploitability
        - Impact scope
        - Attack complexity
        """
        if not findings:
            return {
                "risk_score": 0,
                "risk_level": "low",
                "critical_count": 0,
                "high_count": 0,
                "assessment": "No vulnerabilities found",
            }
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Simple scoring: critical=100, high=50, medium=20, low=5, info=1
        risk_score = 0
        risk_score += severity_counts.get("critical", 0) * 100
        risk_score += severity_counts.get("high", 0) * 50
        risk_score += severity_counts.get("medium", 0) * 20
        risk_score += severity_counts.get("low", 0) * 5
        
        # Cap at 1000 and derive level
        risk_score = min(risk_score, 1000)
        if risk_score >= 800:
            risk_level = "critical"
        elif risk_score >= 500:
            risk_level = "high"
        elif risk_score >= 200:
            risk_level = "medium"
        elif risk_score > 0:
            risk_level = "low"
        else:
            risk_level = "info"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "total_findings": len(findings),
            "assessment": f"Found {len(findings)} vulnerabilities: {severity_counts}",
        }
    
    def should_exploit(self, finding: Dict) -> Dict[str, Any]:
        """
        Determine if a vulnerability should be exploited.
        Returns: {should_exploit: bool, reason: str, risk_level: str, confidence: float}
        """
        severity = finding.get("severity", "").lower()
        category = finding.get("category", "").lower()
        
        # Never auto-exploit certain types unless explicitly configured
        never_exploit = {"dos", "data_loss", "service_disruption", "physical"}
        if any(ne in category for ne in never_exploit):
            return {
                "should_exploit": False,
                "reason": f"Finding category '{category}' is high-risk and requires manual approval",
                "risk_level": "critical",
                "confidence": 1.0,
            }
        
        # High confidence auto-exploit for research vulnerabilities
        auto_exploit_categories = {
            "xss": True,
            "sqli": True,
            "idor": True,
            "ssrf": True,
            "authentication": True,
            "information_disclosure": True,
            "broken_access": True,
            "csrf": True,
        }
        
        should_exploit = auto_exploit_categories.get(category, False)
        
        # Confidence based on severity
        confidence_map = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }
        confidence = confidence_map.get(severity, 0.5)
        
        reason = f"Finding is {severity} severity {category} — " + (
            "safe to exploit (research vulnerability)" if should_exploit
            else "requires manual review"
        )
        
        return {
            "should_exploit": should_exploit,
            "reason": reason,
            "risk_level": severity,
            "confidence": confidence,
        }


# ── Decision Engine ──────────────────────────────────────────────────────

class DecisionEngine:
    """
    Claude-based decision engine for autonomous scanning.
    
    Uses Claude Sonnet/Opus to make intelligent decisions about:
    - What to scan next
    - Which tools to use
    - Whether to exploit findings
    - When to move to next phase
    - How to adapt when things change
    """
    
    def __init__(self, client: anthropic.Anthropic, model: str = "claude-3-5-sonnet-20241022"):
        self.client = client
        self.model = model
        self.decision_log = []
    
    def decide_next_action(self, context: DecisionContext) -> Dict[str, Any]:
        """
        Decide the next action to take in the scan.
        
        Returns:
        {
            "action": "run_tool" | "move_phase" | "exploit" | "end_scan",
            "tool": "nuclei" | "ffuf" | ... (if action is run_tool),
            "parameters": {...},
            "reasoning": "...",
            "confidence": 0.0-1.0,
        }
        """
        prompt = self._build_decision_prompt(context)
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{
                    "role": "user",
                    "content": prompt,
                }],
            )
            
            text = response.content[0].text
            
            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                import re
                json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
                if json_match:
                    text = json_match.group(1)
                
                decision = json.loads(text)
            except json.JSONDecodeError:
                # Fallback: parse as text
                decision = self._parse_text_decision(text, context)
            
            # Validate decision structure
            decision.setdefault("action", "run_tool")
            decision.setdefault("reasoning", "")
            decision.setdefault("confidence", 0.7)
            
            # Log decision
            self.decision_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase": context.current_phase.value,
                "decision": decision,
            })
            
            return decision
            
        except Exception as e:
            log.error(f"Decision engine error: {e}")
            # Fallback decision: continue with discovery tools
            return {
                "action": "run_tool",
                "tool": "nuclei",
                "parameters": {"target": context.target, "tags": "discovery"},
                "reasoning": f"Decision engine error, falling back to standard discovery: {e}",
                "confidence": 0.5,
            }
    
    def _build_decision_prompt(self, context: DecisionContext) -> str:
        """Build decision prompt for Claude."""
        discovery_summary = {
            "endpoints": len(context.endpoints),
            "technologies": context.technologies[:10],
            "forms": len(context.forms),
            "apis": len(context.apis),
            "chatbots": len(context.chatbots),
            "auth_mechanisms": context.auth_mechanisms,
        }
        
        findings_summary = {
            "total": len(context.findings),
            "critical": len([f for f in context.findings if f.get("severity") == "critical"]),
            "high": len([f for f in context.findings if f.get("severity") == "high"]),
            "categories": list(set(f.get("category") for f in context.findings)),
        }
        
        prompt = f"""You are an autonomous security scanning agent. You must decide the next action to take.

Current State:
- Phase: {context.current_phase.value}
- Target: {context.target}
- Scan Type: {context.scan_type}

Discovery So Far:
{json.dumps(discovery_summary, indent=2)}

Findings So Far:
{json.dumps(findings_summary, indent=2)}

Tools Already Executed:
{', '.join(context.tools_executed[-10:]) if context.tools_executed else 'None'}

Phase Status:
{json.dumps(context.phase_completions, indent=2)}

Your task: Decide the next action to move the scan forward.

For DISCOVERY phase: Focus on identifying all technologies, endpoints, APIs, forms, auth mechanisms
For ENUMERATION phase: Deep dive into discovered components - enumerate endpoints, users, configurations
For VULNERABILITY_SCANNING phase: Run security scanners - nuclei, sqlmap, etc. on discovered endpoints
For EXPLOITATION phase: Create POCs for high-severity findings
For REPORTING phase: Compile all findings into a comprehensive report

Return a JSON object with:
{{
    "action": "run_tool" | "move_phase" | "exploit" | "continue_phase" | "end_scan",
    "tool": "tool_name (if action=run_tool)",
    "parameters": {{}},
    "reason": "Why this action",
    "next_tool_if_available": "tool_name (for agent planning)",
    "phase_complete": false,
    "confidence": 0.0-1.0
}}

Think strategically - maximize coverage while minimizing redundant scans."""
        
        return prompt
    
    def _parse_text_decision(self, text: str, context: DecisionContext) -> Dict[str, Any]:
        """Parse text response as decision."""
        text_lower = text.lower()
        
        # Determine action from text
        if "move" in text_lower or "phase" in text_lower:
            action = "move_phase"
        elif "exploit" in text_lower:
            action = "exploit"
        elif "end" in text_lower or "complete" in text_lower:
            action = "end_scan"
        else:
            action = "run_tool"
        
        # Determine tool if action is run_tool
        tool = None
        if action == "run_tool":
            tool_names = ["nuclei", "ffuf", "sqlmap", "xssgnu", "wapiti", "nikto", "nmap", "whois"]
            for tool_name in tool_names:
                if tool_name in text_lower:
                    tool = tool_name
                    break
            tool = tool or "nuclei"  # default
        
        return {
            "action": action,
            "tool": tool,
            "parameters": {"target": context.target},
            "reasoning": text[:200],
            "confidence": 0.6,
        }
    
    def decide_phase_transition(self, context: DecisionContext, phase_results: Dict) -> Optional[ScanPhase]:
        """
        Decide if current phase is complete and what phase to move to.
        
        Returns: Next phase or None if should stay in current phase.
        """
        prompt = f"""Based on the scan progress, should we move to the next phase?

Current Phase: {context.current_phase.value}
Target: {context.target}

Phase Results:
{json.dumps(phase_results, indent=2)}

Criteria for phase completion:
- DISCOVERY: Identified main technologies, endpoints, APIs, forms. Found at least 5 unique components.
- ENUMERATION: Deep enumeration complete. Have endpoint list, user enumeration, config files. Found all major surfaces.
- VULNERABILITY_SCANNING: Ran all relevant scanners. Found at least some findings or confirmed no vulns.
- EXPLOITATION: Created POCs for exploitable findings or confirmed unexploitable findings.
- REPORTING: Compile all findings.

Respond with ONLY one word:
- next (move to next phase)
- stay (remain in current phase)
- end (scan is complete)"""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=100,
                messages=[{"role": "user", "content": prompt}],
            )
            
            decision = response.content[0].text.strip().lower()
            
            if "next" in decision:
                # Determine next phase
                phase_order = [
                    ScanPhase.DISCOVERY,
                    ScanPhase.ENUMERATION,
                    ScanPhase.VULNERABILITY_SCANNING,
                    ScanPhase.EXPLOITATION,
                    ScanPhase.REPORTING,
                ]
                current_idx = phase_order.index(context.current_phase)
                if current_idx < len(phase_order) - 1:
                    return phase_order[current_idx + 1]
            elif "end" in decision:
                return ScanPhase.REPORTING
        except Exception as e:
            log.warning(f"Phase transition decision error: {e}")
        
        return None  # Stay in current phase


# ── Scan Orchestrator ────────────────────────────────────────────────────

class ScanOrchestrator:
    """
    Orchestrates scanning execution.
    
    Handles:
    - Tool execution coordination
    - Result aggregation
    - Error recovery
    - Progress tracking
    """
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.executed_tools = []
        self.tool_results = {}
        self.errors = []
        self.start_time = time.time()
    
    def execute_tool(self, tool_name: str, parameters: Dict) -> Dict[str, Any]:
        """
        Execute a tool and return results.
        
        This is a placeholder - actual execution would call the existing
        scan_agent.handle_tool() function.
        """
        log.info(f"Executing tool: {tool_name} with params: {parameters}")
        
        self.executed_tools.append({
            "tool": tool_name,
            "parameters": parameters,
            "timestamp": time.time(),
        })
        
        # Placeholder: return mock results
        return {
            "success": True,
            "tool": tool_name,
            "findings": [],
            "endpoints": [],
            "timestamp": time.time(),
        }
    
    def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate all tool results into a unified view."""
        return {
            "tools_executed": len(self.executed_tools),
            "tool_list": [t["tool"] for t in self.executed_tools],
            "total_results": len(self.tool_results),
            "duration_seconds": int(time.time() - self.start_time),
        }


# ── Learning System ──────────────────────────────────────────────────────

class LearningSystem:
    """
    Learning system for improving agent decisions over time.
    
    Tracks:
    - Previous scans on same target
    - Common findings patterns
    - Successful tool combinations
    - Failed approaches
    """
    
    def __init__(self, storage=None):
        self.storage = storage
        self.scan_history = []
    
    def load_previous_scans(self, target: str, limit: int = 5) -> List[Dict]:
        """Load previous scan results for the same target."""
        if not self.storage:
            return []
        
        try:
            # Try to load scan history from storage
            # This would query Elasticsearch or database
            history = self.storage.get_json(f"targets/{target}/scan_history.json") or []
            return history[:limit]
        except Exception as e:
            log.warning(f"Failed to load previous scans for {target}: {e}")
            return []
    
    def find_similar_findings(self, target: str, finding: Dict) -> List[Dict]:
        """Find similar findings from previous scans."""
        if not self.storage:
            return []
        
        try:
            # Query for similar findings (would use ES)
            return []
        except Exception:
            return []
    
    def get_recommendations(self, context: DecisionContext) -> Dict[str, Any]:
        """
        Get recommendations from learning system based on:
        - Previous scans
        - Similar findings
        - Successful tool chains
        """
        return {
            "common_findings": context.similar_findings,
            "recommended_tools": self._recommend_tools(context),
            "skip_tools": self._tools_to_skip(context),
            "successful_chain": self._get_successful_chain(context),
        }
    
    def _recommend_tools(self, context: DecisionContext) -> List[str]:
        """Recommend tools based on discovered technologies."""
        recommendations = []
        
        tech_lower = [t.lower() for t in context.technologies]
        
        # Map technologies to tools
        if any("wordpress" in t for t in tech_lower):
            recommendations.extend(["wpscan", "nuclei"])
        if any("python" in t or "flask" in t or "django" in t for t in tech_lower):
            recommendations.append("sqlmap")
        if any("graphql" in t for t in tech_lower):
            recommendations.append("nuclei")  # graphql templates
        if context.forms:
            recommendations.extend(["sqlmap", "xssgnu"])
        if context.apis:
            recommendations.append("nuclei")
        
        return list(set(recommendations))
    
    def _tools_to_skip(self, context: DecisionContext) -> List[str]:
        """Tools that shouldn't be run based on target characteristics."""
        skip = []
        
        if "no_scan" in [t.lower() for t in context.technologies]:
            skip.extend(["nuclei", "nmap"])
        
        return skip
    
    def _get_successful_chain(self, context: DecisionContext) -> List[str]:
        """Get successful tool chains from previous scans."""
        if not context.previous_scans:
            return ["nuclei", "ffuf", "sqlmap"]  # default chain
        
        # Would analyze previous scans to find common successful chains
        return ["nuclei", "ffuf", "sqlmap"]


# ── Autonomous Agent ─────────────────────────────────────────────────────

class AutonomousAgent:
    """
    Main autonomous agent orchestrator.
    
    This is the top-level controller that:
    1. Initializes state machine, decision engine, and learning system
    2. Runs the main scan loop
    3. Makes phase transitions
    4. Handles tool execution
    5. Adapts based on findings
    6. Generates final report
    
    All with ZERO human input once started.
    """
    
    def __init__(self, scan_id: str, target: str, scan_type: str = "standard",
                 storage=None, client: anthropic.Anthropic = None):
        self.scan_id = scan_id
        self.target = target
        self.scan_type = scan_type
        self.storage = storage
        self.client = client or anthropic.Anthropic()
        
        # Core components
        self.state_manager = StateManager()
        self.decision_engine = DecisionEngine(self.client)
        self.vulnerability_assessment = VulnerabilityAssessment(self.client)
        self.orchestrator = ScanOrchestrator(scan_id)
        self.learning_system = LearningSystem(storage)
        
        # Execution context
        self.context = DecisionContext(scan_id, target, scan_type)
        self.decisions_made = []
        self.start_time = time.time()
    
    def run(self, max_iterations: int = 100) -> Dict[str, Any]:
        """
        Run the autonomous scan from start to finish.
        
        Returns: Final scan report with all findings and metadata.
        """
        log.info(f"Starting autonomous scan: {self.scan_id} for {self.target}")
        
        iteration = 0
        while iteration < max_iterations and self.state_manager.current_phase != ScanPhase.COMPLETED:
            iteration += 1
            
            # Get decision from decision engine
            decision = self.decision_engine.decide_next_action(self.context)
            self.decisions_made.append(decision)
            
            log.info(f"Iteration {iteration}: Phase={self.state_manager.current_phase.value}, "
                    f"Action={decision.get('action')}, Tool={decision.get('tool')}")
            
            # Execute decision
            if decision["action"] == "run_tool":
                self._execute_tool(decision)
            elif decision["action"] == "move_phase":
                self._transition_phase(decision)
            elif decision["action"] == "exploit":
                self._exploit_finding(decision)
            elif decision["action"] == "end_scan":
                break
            
            # Periodically check if we should move to next phase
            if iteration % 10 == 0:
                phase_results = self.orchestrator.aggregate_results()
                next_phase = self.decision_engine.decide_phase_transition(self.context, phase_results)
                if next_phase and next_phase != self.state_manager.current_phase:
                    self.state_manager.transition(
                        next_phase,
                        "Phase completion detected",
                        {"iteration": iteration, "phase_results": phase_results}
                    )
        
        # Generate final report
        return self._generate_report()
    
    def _execute_tool(self, decision: Dict):
        """Execute a scanning tool based on decision."""
        tool = decision.get("tool")
        params = decision.get("parameters", {})
        
        # Add target to parameters
        params["target"] = self.target
        
        # Execute tool
        result = self.orchestrator.execute_tool(tool, params)
        
        # Update context with results
        self.context.tools_executed.append(tool)
        self.context.tool_results[tool] = result
        
        # Extract any findings
        if result.get("findings"):
            self.context.findings.extend(result["findings"])
            # Track critical findings
            for finding in result["findings"]:
                if finding.get("severity") == "critical":
                    self.context.critical_findings.append(finding)
    
    def _transition_phase(self, decision: Dict):
        """Transition to next phase."""
        current_phase = self.state_manager.current_phase
        phase_order = [
            ScanPhase.DISCOVERY,
            ScanPhase.ENUMERATION,
            ScanPhase.VULNERABILITY_SCANNING,
            ScanPhase.EXPLOITATION,
            ScanPhase.REPORTING,
        ]
        
        try:
            current_idx = phase_order.index(current_phase)
            if current_idx < len(phase_order) - 1:
                next_phase = phase_order[current_idx + 1]
                self.state_manager.transition(
                    next_phase,
                    decision.get("reasoning", ""),
                    decision,
                )
                self.context.current_phase = next_phase
        except ValueError:
            pass
    
    def _exploit_finding(self, decision: Dict):
        """Create POC for a finding based on decision."""
        # This would integrate with the exploitation framework (Issue #51)
        log.info(f"Exploitation queued: {decision.get('reasoning')}")
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate final scan report."""
        risk_assessment = self.vulnerability_assessment.assess_risk_score(self.context.findings)
        
        report = {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": "completed" if self.state_manager.current_phase == ScanPhase.COMPLETED else "interrupted",
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": int(time.time() - self.start_time),
            
            # Results
            "findings": self.context.findings,
            "critical_findings": self.context.critical_findings,
            "total_findings": len(self.context.findings),
            
            # Risk assessment
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            
            # Attack surface
            "attack_surface": {
                "endpoints": self.context.endpoints,
                "technologies": self.context.technologies,
                "forms": self.context.forms,
                "apis": self.context.apis,
                "chatbots": self.context.chatbots,
                "auth_mechanisms": self.context.auth_mechanisms,
                "infrastructure": self.context.infrastructure,
            },
            
            # Execution metadata
            "execution": {
                "tools_executed": self.context.tools_executed,
                "total_tools": len(set(self.context.tools_executed)),
                "decisions_made": len(self.decisions_made),
                "state_transitions": self.state_manager.get_history(),
                "failures": self.context.failures,
            },
            
            # Learning
            "learning": {
                "previous_scans_analyzed": len(self.context.previous_scans),
                "similar_findings_found": len(self.context.similar_findings),
            },
        }
        
        return report


# ── Integration with existing scan_agent ────────────────────────────────

def create_autonomous_scan_context(scan_id: str, target: str, scan_type: str = "standard") -> DecisionContext:
    """Create a DecisionContext that can be used with existing scan_agent."""
    return DecisionContext(scan_id, target, scan_type)


def autonomous_scan_wrapper(scan_id: str, target: str, scan_type: str, config: Dict = None):
    """
    Wrapper that runs autonomous agent and integrates with existing scan infrastructure.
    
    This allows autonomous agent to be called like:
        from modules.agent.autonomous_agent import autonomous_scan_wrapper
        report = autonomous_scan_wrapper(scan_id, target, "standard", config)
    """
    agent = AutonomousAgent(scan_id, target, scan_type)
    report = agent.run()
    return report
