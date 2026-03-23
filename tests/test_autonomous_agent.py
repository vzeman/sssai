"""
Tests for autonomous_agent module (Issue #50).

Tests cover:
- State machine transitions
- Decision engine
- Vulnerability assessment
- Scan orchestration
- Learning system
- End-to-end autonomous scans
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from modules.agent.autonomous_agent import (
    ScanPhase,
    StateManager,
    StateTransition,
    VulnerabilityAssessment,
    DecisionContext,
    DecisionEngine,
    ScanOrchestrator,
    LearningSystem,
    AutonomousAgent,
)


# ──────────────────────────────────────────────────────────────────────────
# STATE MACHINE TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestStateManager:
    """Test the state machine."""
    
    def test_initial_state(self):
        """Test that initial state is DISCOVERY."""
        sm = StateManager()
        assert sm.current_phase == ScanPhase.DISCOVERY
    
    def test_valid_transition_discovery_to_enumeration(self):
        """Test valid transition from DISCOVERY to ENUMERATION."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        assert sm.can_transition_to(ScanPhase.ENUMERATION, context)
        success = sm.transition(ScanPhase.ENUMERATION, "Discovery complete")
        assert success
        assert sm.current_phase == ScanPhase.ENUMERATION
    
    def test_valid_transition_sequence(self):
        """Test full valid transition sequence."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        phases = [
            ScanPhase.ENUMERATION,
            ScanPhase.VULNERABILITY_SCANNING,
            ScanPhase.EXPLOITATION,
            ScanPhase.REPORTING,
            ScanPhase.COMPLETED,
        ]
        
        for phase in phases:
            success = sm.transition(phase, f"Move to {phase.value}")
            assert success, f"Failed to transition to {phase.value}"
        
        assert sm.current_phase == ScanPhase.COMPLETED
    
    def test_invalid_transition_backward(self):
        """Test that backward transitions are invalid."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        sm.transition(ScanPhase.ENUMERATION, "Move to ENUMERATION")
        
        # Try to go backward — should fail
        success = sm.transition(ScanPhase.DISCOVERY, "Go back")
        assert not success
        assert sm.current_phase == ScanPhase.ENUMERATION
    
    def test_invalid_transition_skip_phases(self):
        """Test that skipping phases is invalid."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        # Try to skip from DISCOVERY directly to VULNERABILITY_SCANNING
        success = sm.transition(ScanPhase.VULNERABILITY_SCANNING, "Skip ahead")
        assert not success
        assert sm.current_phase == ScanPhase.DISCOVERY
    
    def test_transition_history(self):
        """Test that transition history is recorded."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        sm.transition(ScanPhase.ENUMERATION, "First transition")
        sm.transition(ScanPhase.VULNERABILITY_SCANNING, "Second transition")
        
        history = sm.get_history()
        assert len(history) == 2
        assert history[0]["from"] == "discovery"
        assert history[0]["to"] == "enumeration"
        assert history[1]["from"] == "enumeration"
        assert history[1]["to"] == "vulnerability_scanning"
    
    def test_phase_duration(self):
        """Test phase duration tracking."""
        sm = StateManager()
        context = DecisionContext("test_scan", "test.com")
        
        start = time.time()
        time.sleep(0.1)
        duration = sm.get_phase_duration()
        
        assert duration >= 0.1
        assert duration < 1.0  # Should be quick in test


# ──────────────────────────────────────────────────────────────────────────
# VULNERABILITY ASSESSMENT TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestVulnerabilityAssessment:
    """Test vulnerability assessment and risk scoring."""
    
    @pytest.fixture
    def mock_client(self):
        """Mock Anthropic client."""
        return Mock()
    
    def test_empty_findings_risk_score(self, mock_client):
        """Test risk score for empty findings."""
        assessment = VulnerabilityAssessment(mock_client)
        result = assessment.assess_risk_score([])
        
        assert result["risk_score"] == 0
        assert result["risk_level"] == "low"
        assert result["critical_count"] == 0
        assert result["total_findings"] == 0
    
    def test_critical_findings_risk_score(self, mock_client):
        """Test risk score with critical findings."""
        assessment = VulnerabilityAssessment(mock_client)
        
        findings = [
            {"severity": "critical", "title": "RCE"},
            {"severity": "critical", "title": "SQLi"},
        ]
        
        result = assessment.assess_risk_score(findings)
        
        assert result["risk_score"] >= 200
        assert result["risk_level"] == "critical"
        assert result["critical_count"] == 2
    
    def test_mixed_severity_risk_score(self, mock_client):
        """Test risk score with mixed severities."""
        assessment = VulnerabilityAssessment(mock_client)
        
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        
        result = assessment.assess_risk_score(findings)
        
        assert result["critical_count"] == 1
        assert result["high_count"] == 2
        assert result["medium_count"] == 1
        assert result["total_findings"] == 4
    
    def test_should_exploit_safe_vulnerability(self, mock_client):
        """Test that safe vulnerabilities are marked for exploitation."""
        assessment = VulnerabilityAssessment(mock_client)
        
        findings = [
            {
                "severity": "high",
                "category": "XSS",
                "title": "Reflected XSS",
            },
            {
                "severity": "critical",
                "category": "SQLi",
                "title": "SQL Injection",
            },
        ]
        
        for finding in findings:
            result = assessment.should_exploit(finding)
            assert result["should_exploit"] is True
            assert result["confidence"] >= 0.7
    
    def test_should_not_exploit_dangerous_finding(self, mock_client):
        """Test that dangerous findings are not auto-exploited."""
        assessment = VulnerabilityAssessment(mock_client)
        
        finding = {
            "severity": "high",
            "category": "Denial of Service",
            "title": "Memory exhaustion",
        }
        
        result = assessment.should_exploit(finding)
        assert result["should_exploit"] is False
    
    def test_exploit_confidence_by_severity(self, mock_client):
        """Test that confidence scales with severity."""
        assessment = VulnerabilityAssessment(mock_client)
        
        confidences = {}
        severities = ["critical", "high", "medium", "low"]
        
        for severity in severities:
            finding = {"severity": severity, "category": "XSS"}
            result = assessment.should_exploit(finding)
            confidences[severity] = result["confidence"]
        
        # Higher severity should have higher confidence
        assert confidences["critical"] > confidences["high"]
        assert confidences["high"] > confidences["medium"]
        assert confidences["medium"] > confidences["low"]


# ──────────────────────────────────────────────────────────────────────────
# DECISION ENGINE TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestDecisionEngine:
    """Test the decision engine."""
    
    @pytest.fixture
    def mock_client(self):
        """Mock Anthropic client."""
        client = Mock()
        return client
    
    def test_decision_engine_initialization(self, mock_client):
        """Test decision engine initialization."""
        engine = DecisionEngine(mock_client, "claude-3-5-sonnet-20241022")
        assert engine.model == "claude-3-5-sonnet-20241022"
        assert len(engine.decision_log) == 0
    
    @patch('modules.agent.autonomous_agent.DecisionEngine._build_decision_prompt')
    def test_decide_next_action_discovery_phase(self, mock_prompt, mock_client):
        """Test decision for discovery phase."""
        mock_prompt.return_value = "Mock prompt"
        
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = [Mock(text='{"action": "run_tool", "tool": "nuclei", "confidence": 0.9}')]
        mock_client.messages.create.return_value = mock_response
        
        engine = DecisionEngine(mock_client)
        context = DecisionContext("scan1", "test.com")
        context.current_phase = ScanPhase.DISCOVERY
        
        decision = engine.decide_next_action(context)
        
        assert decision["action"] == "run_tool"
        assert decision["tool"] == "nuclei"
        assert "confidence" in decision
        assert len(engine.decision_log) == 1
    
    @patch('modules.agent.autonomous_agent.DecisionEngine._build_decision_prompt')
    def test_decide_phase_transition_to_next(self, mock_prompt, mock_client):
        """Test phase transition decision."""
        mock_prompt.return_value = "Mock prompt"
        
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = [Mock(text='next')]
        mock_client.messages.create.return_value = mock_response
        
        engine = DecisionEngine(mock_client)
        context = DecisionContext("scan1", "test.com")
        context.current_phase = ScanPhase.DISCOVERY
        
        phase_results = {"discoveries": 10, "endpoints": 5}
        next_phase = engine.decide_phase_transition(context, phase_results)
        
        assert next_phase == ScanPhase.ENUMERATION
    
    @patch('modules.agent.autonomous_agent.DecisionEngine._build_decision_prompt')
    def test_decide_phase_transition_stay(self, mock_prompt, mock_client):
        """Test phase transition decision to stay."""
        mock_prompt.return_value = "Mock prompt"
        
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = [Mock(text='stay')]
        mock_client.messages.create.return_value = mock_response
        
        engine = DecisionEngine(mock_client)
        context = DecisionContext("scan1", "test.com")
        context.current_phase = ScanPhase.DISCOVERY
        
        phase_results = {"discoveries": 2}
        next_phase = engine.decide_phase_transition(context, phase_results)
        
        assert next_phase is None  # Stay in current phase


# ──────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestScanOrchestrator:
    """Test scan orchestration."""
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        orchestrator = ScanOrchestrator("scan1")
        assert orchestrator.scan_id == "scan1"
        assert len(orchestrator.executed_tools) == 0
    
    def test_execute_tool(self):
        """Test tool execution."""
        orchestrator = ScanOrchestrator("scan1")
        result = orchestrator.execute_tool("nuclei", {"target": "test.com", "tags": "discovery"})
        
        assert result["success"]
        assert result["tool"] == "nuclei"
        assert len(orchestrator.executed_tools) == 1
    
    def test_execute_multiple_tools(self):
        """Test executing multiple tools."""
        orchestrator = ScanOrchestrator("scan1")
        
        orchestrator.execute_tool("nuclei", {"target": "test.com"})
        orchestrator.execute_tool("ffuf", {"target": "test.com"})
        orchestrator.execute_tool("sqlmap", {"target": "test.com"})
        
        assert len(orchestrator.executed_tools) == 3
    
    def test_aggregate_results(self):
        """Test result aggregation."""
        orchestrator = ScanOrchestrator("scan1")
        
        orchestrator.execute_tool("nuclei", {"target": "test.com"})
        orchestrator.execute_tool("ffuf", {"target": "test.com"})
        
        agg = orchestrator.aggregate_results()
        
        assert agg["tools_executed"] == 2
        assert "nuclei" in agg["tool_list"]
        assert "ffuf" in agg["tool_list"]


# ──────────────────────────────────────────────────────────────────────────
# LEARNING SYSTEM TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestLearningSystem:
    """Test the learning system."""
    
    def test_learning_system_initialization(self):
        """Test learning system initialization."""
        learning = LearningSystem()
        assert len(learning.scan_history) == 0
    
    def test_get_recommendations_with_technologies(self):
        """Test tool recommendations based on discovered technologies."""
        learning = LearningSystem()
        context = DecisionContext("scan1", "test.com")
        context.technologies = ["WordPress", "PHP", "Apache"]
        
        recommendations = learning.get_recommendations(context)
        
        assert "wpscan" in recommendations["recommended_tools"]
        assert isinstance(recommendations["recommended_tools"], list)
    
    def test_get_recommendations_with_apis(self):
        """Test recommendations when APIs are found."""
        learning = LearningSystem()
        context = DecisionContext("scan1", "test.com")
        context.apis = [{"endpoint": "/api/users", "method": "GET"}]
        
        recommendations = learning.get_recommendations(context)
        
        assert "nuclei" in recommendations["recommended_tools"]
    
    def test_get_recommendations_with_forms(self):
        """Test recommendations when forms are found."""
        learning = LearningSystem()
        context = DecisionContext("scan1", "test.com")
        context.forms = [{"action": "/login", "type": "login"}]
        
        recommendations = learning.get_recommendations(context)
        
        # Should recommend tools for form testing
        assert len(recommendations["recommended_tools"]) > 0


# ──────────────────────────────────────────────────────────────────────────
# AUTONOMOUS AGENT INTEGRATION TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestAutonomousAgent:
    """Test the autonomous agent."""
    
    @pytest.fixture
    def mock_client(self):
        """Mock Anthropic client."""
        return Mock()
    
    def test_agent_initialization(self, mock_client):
        """Test agent initialization."""
        agent = AutonomousAgent("scan1", "test.com", "standard", client=mock_client)
        
        assert agent.scan_id == "scan1"
        assert agent.target == "test.com"
        assert agent.context.current_phase == ScanPhase.DISCOVERY
        assert len(agent.decisions_made) == 0
    
    def test_decision_context_initialization(self):
        """Test decision context initialization."""
        context = DecisionContext("scan1", "test.com", "standard")
        
        assert context.scan_id == "scan1"
        assert context.target == "test.com"
        assert context.current_phase == ScanPhase.DISCOVERY
        assert len(context.findings) == 0
        assert len(context.endpoints) == 0
    
    @patch('modules.agent.autonomous_agent.DecisionEngine.decide_next_action')
    def test_agent_run_with_mocked_decisions(self, mock_decide, mock_client):
        """Test agent run with mocked decisions."""
        # Mock decision sequence
        mock_decide.side_effect = [
            {
                "action": "run_tool",
                "tool": "nuclei",
                "parameters": {"tags": "discovery"},
                "reasoning": "Discovery phase",
                "confidence": 0.9,
            },
            {
                "action": "move_phase",
                "reasoning": "Discovery complete",
                "confidence": 0.8,
            },
            {
                "action": "end_scan",
                "reasoning": "Scan complete",
                "confidence": 0.9,
            },
        ]
        
        agent = AutonomousAgent("scan1", "test.com", "standard", client=mock_client)
        report = agent.run(max_iterations=3)
        
        assert report["scan_id"] == "scan1"
        assert report["target"] == "test.com"
        assert "findings" in report
        assert "risk_score" in report


# ──────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestIntegration:
    """Integration tests for full autonomous scan."""
    
    def test_full_state_machine_flow(self):
        """Test full state machine flow from discovery to reporting."""
        sm = StateManager()
        context = DecisionContext("scan1", "test.com")
        
        phases = [
            ScanPhase.ENUMERATION,
            ScanPhase.VULNERABILITY_SCANNING,
            ScanPhase.EXPLOITATION,
            ScanPhase.REPORTING,
            ScanPhase.COMPLETED,
        ]
        
        for phase in phases:
            success = sm.transition(phase, f"Transition to {phase.value}")
            assert success
        
        history = sm.get_history()
        assert len(history) == 5
        assert history[-1]["to"] == "completed"
    
    def test_vulnerability_assessment_workflow(self):
        """Test complete vulnerability assessment workflow."""
        client = Mock()
        assessment = VulnerabilityAssessment(client)
        
        # Simulate findings from a scan
        findings = [
            {
                "severity": "critical",
                "category": "RCE",
                "title": "Remote Code Execution",
            },
            {
                "severity": "high",
                "category": "SQLi",
                "title": "SQL Injection",
            },
            {
                "severity": "medium",
                "category": "XSS",
                "title": "Stored XSS",
            },
        ]
        
        # Assess risk
        risk = assessment.assess_risk_score(findings)
        assert risk["risk_level"] == "critical"
        assert risk["critical_count"] == 1
        
        # Check if each should be exploited
        for finding in findings:
            exploit_decision = assessment.should_exploit(finding)
            if "dos" not in finding["category"].lower():
                assert exploit_decision["should_exploit"] is True


# ──────────────────────────────────────────────────────────────────────────
# PERFORMANCE TESTS
# ──────────────────────────────────────────────────────────────────────────

class TestPerformance:
    """Performance tests for autonomous agent components."""
    
    def test_state_transitions_performance(self):
        """Test that state transitions are fast."""
        sm = StateManager()
        context = DecisionContext("scan1", "test.com")
        
        start = time.time()
        
        for i in range(100):
            sm.transition(ScanPhase.ENUMERATION, "Test")
            sm.transition(ScanPhase.VULNERABILITY_SCANNING, "Test")
            sm.transition(ScanPhase.EXPLOITATION, "Test")
            sm.transition(ScanPhase.REPORTING, "Test")
            sm.transition(ScanPhase.COMPLETED, "Test")
        
        duration = time.time() - start
        
        # 500 transitions should take < 1 second
        assert duration < 1.0
    
    def test_risk_scoring_performance(self):
        """Test that risk scoring is fast."""
        client = Mock()
        assessment = VulnerabilityAssessment(client)
        
        # Create 1000 findings
        findings = [
            {"severity": "critical" if i % 10 == 0 else "high" if i % 5 == 0 else "medium"}
            for i in range(1000)
        ]
        
        start = time.time()
        result = assessment.assess_risk_score(findings)
        duration = time.time() - start
        
        # Should score 1000 findings in < 100ms
        assert duration < 0.1
        assert result["total_findings"] == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
