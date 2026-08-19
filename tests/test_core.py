"""Basic tests for PEN-AI core components."""

import pytest
from uuid import UUID

from core.state.engagement_state import (
    EngagementState,
    Host,
    Service,
    AccessLevel,
)
from core.scope.rules import RulesOfEngagement, ScopeValidator
from core.events.models import Event, EventType, EventChain
from ai.planner import Planner, CandidateAction, ActionType, ActionPriority
from ai.reasoner import Reasoner, Hypothesis, HypothesisConfidence
from ai.memory import AIMemory
from ai.tool_registry import ToolRegistry, ToolDefinition, ToolCategory
from findings.engine import FindingsEngine, Severity, FindingStatus
from objectives.tracker import ObjectiveTracker, ObjectiveStatus
from pivoting.manager import PivotManager, PivotStatus
from attack_graph.graph import AttackGraph, GraphNode, GraphEdge


class TestEngagementState:
    """Tests for EngagementState."""

    def test_create_state(self):
        state = EngagementState(name="Test Engagement")
        assert state.name == "Test Engagement"
        assert state.hosts_discovered == 0
        assert state.current_access == AccessLevel.NONE

    def test_add_host(self):
        state = EngagementState()
        host = Host(ip="192.168.1.1")
        state.add_host(host)
        assert state.hosts_discovered == 1
        assert len(state.hosts) == 1

    def test_add_service(self):
        state = EngagementState()
        host = Host(ip="192.168.1.1")
        service = Service(host_id=host.id, port=80, service_name="http")
        state.add_service(service)
        assert state.services_discovered == 1

    def test_get_host_by_ip(self):
        state = EngagementState()
        host = Host(ip="192.168.1.1")
        state.add_host(host)
        found = state.get_host_by_ip("192.168.1.1")
        assert found is not None
        assert found.ip == "192.168.1.1"

    def test_record_failure(self):
        state = EngagementState()
        state.record_failure("test_action", "test_reason")
        assert len(state.failed_actions) == 1


class TestRulesOfEngagement:
    """Tests for RulesOfEngagement."""

    def test_host_in_scope(self):
        roe = RulesOfEngagement(allowed_networks=["192.168.1.0/24"])
        assert roe.is_host_allowed("192.168.1.1") is True
        assert roe.is_host_allowed("10.0.0.1") is False

    def test_host_excluded(self):
        roe = RulesOfEngagement(
            allowed_networks=["192.168.1.0/24"],
            excluded_hosts=["192.168.1.1"],
        )
        assert roe.is_host_allowed("192.168.1.1") is False
        assert roe.is_host_allowed("192.168.1.2") is True

    def test_port_allowed(self):
        roe = RulesOfEngagement(allowed_ports=[80, 443])
        assert roe.is_port_allowed(80) is True
        assert roe.is_port_allowed(22) is False

    def test_can_pivot(self):
        roe = RulesOfEngagement(max_pivots=3)
        assert roe.can_pivot(0) is True
        assert roe.can_pivot(2) is True
        assert roe.can_pivot(3) is False


class TestScopeValidator:
    """Tests for ScopeValidator."""

    def test_validate_target(self):
        roe = RulesOfEngagement(allowed_networks=["192.168.1.0/24"])
        validator = ScopeValidator(roe)

        valid, msg = validator.validate_target("192.168.1.1")
        assert valid is True

        valid, msg = validator.validate_target("10.0.0.1")
        assert valid is False
        assert msg is not None


class TestEventSystem:
    """Tests for event system."""

    def test_create_event(self):
        event = Event(
            event_type=EventType.HOST_DISCOVERED,
            action="Host discovered",
            target="192.168.1.1",
        )
        assert event.event_type == EventType.HOST_DISCOVERED
        assert event.target == "192.168.1.1"

    def test_event_chain(self):
        chain = EventChain()
        event1 = Event(event_type=EventType.HOST_DISCOVERED, action="Discovery")
        event2 = Event(event_type=EventType.SERVICE_FOUND, action="Service found")

        chain.add_event(event1)
        chain.add_event(event2)

        assert len(chain.events) == 2
        assert chain.events[1].parent_event_id == chain.events[0].id


class TestPlanner:
    """Tests for Planner."""

    def test_generate_actions(self):
        planner = Planner()
        state = EngagementState()
        actions = planner.generate_actions(state, None, [])
        assert isinstance(actions, list)

    def test_action_scoring(self):
        action = CandidateAction(
            name="test",
            action_type=ActionType.RECON,
            description="Test action",
            priority=ActionPriority.HIGH,
            confidence=0.8,
            information_gain=0.7,
        )
        assert action.score > 0


class TestReasoner:
    """Tests for Reasoner."""

    def test_hypothesize(self):
        reasoner = Reasoner()
        state = EngagementState()
        hypotheses = reasoner.hypothesize(state, None)
        assert isinstance(hypotheses, list)

    def test_observe(self):
        reasoner = Reasoner()
        reasoner.observe("Test observation")
        assert len(reasoner._reasoning_chain) == 1


class TestMemory:
    """Tests for memory system."""

    def test_short_term_memory(self):
        memory = AIMemory()
        memory.short_term.add("Test memory")
        assert len(memory.short_term._entries) == 1

    def test_engagement_memory(self):
        memory = AIMemory()
        memory.engagement.add_discovery("Found host")
        assert len(memory.engagement._discoveries) == 1

    def test_clear_short_term(self):
        memory = AIMemory()
        memory.short_term.add("Test")
        memory.clear_short_term()
        assert len(memory.short_term._entries) == 0


class TestToolRegistry:
    """Tests for tool registry."""

    def test_register_tool(self):
        registry = ToolRegistry()
        tool = ToolDefinition(
            name="test_tool",
            description="Test tool",
            category=ToolCategory.RECON,
        )
        registry.register(tool)
        assert registry.has_tool("test_tool")

    def test_get_schemas(self):
        registry = ToolRegistry()
        tool = ToolDefinition(
            name="test_tool",
            description="Test tool",
            category=ToolCategory.RECON,
        )
        registry.register(tool)
        schemas = registry.get_schemas()
        assert len(schemas) == 1


class TestFindingsEngine:
    """Tests for findings engine."""

    def test_add_finding(self):
        engine = FindingsEngine()
        finding = engine.add_finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH

    def test_get_statistics(self):
        engine = FindingsEngine()
        engine.add_finding("F1", Severity.HIGH, "Desc1")
        engine.add_finding("F2", Severity.LOW, "Desc2")
        stats = engine.get_statistics()
        assert stats["total"] == 2


class TestObjectiveTracker:
    """Tests for objective tracker."""

    def test_add_objective(self):
        tracker = ObjectiveTracker()
        obj = tracker.add_objective(name="Capture Flag")
        assert obj.name == "Capture Flag"
        assert obj.status == ObjectiveStatus.DISCOVERED

    def test_complete_objective(self):
        tracker = ObjectiveTracker()
        obj = tracker.add_objective(name="Capture Flag")
        result = tracker.complete_objective(obj.id, flag="flag{test123}")
        assert result is True
        assert obj.status == ObjectiveStatus.COMPLETED


class TestPivotManager:
    """Tests for pivot manager."""

    def test_can_pivot(self):
        manager = PivotManager(max_depth=3)
        assert manager.can_pivot() is True

    def test_get_depth(self):
        manager = PivotManager()
        assert manager.get_current_depth() == 0


class TestAttackGraph:
    """Tests for attack graph."""

    def test_add_node(self):
        graph = AttackGraph()
        node = GraphNode(label="Test Host", node_type="host")
        graph.add_node(node)
        stats = graph.get_statistics()
        assert stats["nodes"] == 1

    def test_to_dict(self):
        graph = AttackGraph()
        node = GraphNode(label="Test", node_type="host")
        graph.add_node(node)
        data = graph.to_dict()
        assert "nodes" in data
