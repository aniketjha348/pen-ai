"""Tests for LLM integration."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import json

from ai.llm_client import LLMClient, Message, MessageRole, ToolCall, LLMResponse
from ai.master_agent import MasterAgent
from core.state.engagement_state import EngagementState
from core.scope.rules import RulesOfEngagement


class TestLLMClient:
    """Tests for LLM client."""

    def test_create_client(self):
        client = LLMClient(
            api_key="test-key",
            base_url="https://api.example.com/v1",
            model="test-model",
        )
        assert client.api_key == "test-key"
        assert client.model == "test-model"

    def test_message_to_dict(self):
        msg = Message(role=MessageRole.USER, content="Hello")
        d = msg.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "Hello"

    def test_message_with_tool_calls(self):
        msg = Message(
            role=MessageRole.ASSISTANT,
            content=None,
            tool_calls=[{"id": "123", "function": {"name": "test", "arguments": "{}"}}],
        )
        d = msg.to_dict()
        assert "tool_calls" in d

    def test_parse_response_basic(self):
        client = LLMClient(api_key="test", model="test")
        data = {
            "choices": [
                {
                    "message": {"content": "Hello", "role": "assistant"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        response = client._parse_response(data)
        assert response.content == "Hello"
        assert response.finish_reason == "stop"
        assert len(response.tool_calls) == 0

    def test_parse_response_with_tool_calls(self):
        client = LLMClient(api_key="test", model="test")
        data = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "function": {
                                    "name": "nmap_host_scan",
                                    "arguments": json.dumps({"target": "192.168.1.0/24"}),
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
        response = client._parse_response(data)
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "nmap_host_scan"
        assert response.tool_calls[0].arguments["target"] == "192.168.1.0/24"

    def test_system_prompt(self):
        client = LLMClient(api_key="test", model="test")
        client.set_system_prompt("Test prompt")
        assert client._system_prompt == "Test prompt"
        assert len(client._history) == 1
        assert client._history[0].role == MessageRole.SYSTEM

    def test_history_management(self):
        client = LLMClient(api_key="test", model="test")
        client.set_system_prompt("System")
        client.add_to_history(Message(role=MessageRole.USER, content="User msg"))
        assert len(client._history) == 2

        client.clear_history()
        assert len(client._history) == 1  # System prompt remains


class TestMasterAgentLLM:
    """Tests for MasterAgent with LLM integration."""

    def setup_method(self):
        self.state = EngagementState()
        self.roe = RulesOfEngagement(allowed_networks=["192.168.1.0/24"])

    def test_create_agent_without_llm(self):
        agent = MasterAgent(state=self.state, roe=self.roe)
        assert agent.llm is None
        assert agent.brain is not None

    def test_create_agent_with_llm(self):
        llm = LLMClient(api_key="test", model="test")
        agent = MasterAgent(state=self.state, roe=self.roe, llm_client=llm)
        assert agent.llm is not None
        assert agent.brain.llm is llm

    def test_build_state_summary(self):
        agent = MasterAgent(state=self.state, roe=self.roe)
        summary = agent._build_state_summary()
        assert "Hosts Discovered" in summary
        assert "Current Access Level" in summary

    def test_build_state_summary_includes_brain_lessons(self, tmp_path):
        agent = MasterAgent(state=self.state, roe=self.roe)
        agent.brain.memory = agent.brain.memory.__class__(target="192.168.1.0_24", memory_dir=tmp_path)
        agent.brain.memory.record("nmap -sV 192.168.1.10", success=True, reasoning="found web")
        summary = agent._build_state_summary()
        assert "AI Brain Lessons" in summary
        assert "nmap -sV 192.168.1.10" in summary

    def test_format_hypotheses(self):
        from ai.reasoner import Hypothesis, HypothesisConfidence
        agent = MasterAgent(state=self.state, roe=self.roe)
        hypotheses = [
            Hypothesis(
                statement="Test hypothesis",
                confidence=HypothesisConfidence.HIGH,
            )
        ]
        formatted = agent._format_hypotheses(hypotheses)
        assert "Test hypothesis" in formatted
        assert "high" in formatted

    def test_format_actions(self):
        from ai.planner import CandidateAction, ActionType, ActionPriority
        agent = MasterAgent(state=self.state, roe=self.roe)
        actions = [
            CandidateAction(
                name="test_action",
                action_type=ActionType.RECON,
                description="Test action",
                priority=ActionPriority.HIGH,
                tool_name="nmap_host_scan",
            )
        ]
        formatted = agent._format_actions(actions)
        assert "test_action" in formatted
        assert "nmap_host_scan" in formatted

    def test_format_actions_includes_brain_suggestions(self):
        from ai.planner import CandidateAction, ActionType, ActionPriority

        agent = MasterAgent(state=self.state, roe=self.roe)
        actions = [
            CandidateAction(
                name="test_action",
                action_type=ActionType.RECON,
                description="Test action",
                priority=ActionPriority.HIGH,
                tool_name="nmap_host_scan",
            )
        ]
        formatted = agent._format_actions(actions)
        assert "AI Brain Suggested Safe Next Steps" in formatted


class TestOrchestratorWithLLM:
    """Tests for LLM client creation for orchestrator."""

    def test_create_llm_default_model(self):
        from app.config.models import get_model_config
        config = get_model_config("mimo")
        llm = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", ""),
            model=config.get("model_id", "mimo-v2.5-free"),
        )
        assert llm is not None
        assert llm.model == "mimo-v2.5-free"

    def test_create_llm_custom_model(self):
        llm = LLMClient(api_key="test", model="custom-model")
        assert llm is not None
        assert llm.model == "custom-model"


class TestLLMResponse:
    """Tests for LLM response parsing."""

    def test_tool_call_creation(self):
        tc = ToolCall(
            id="call_123",
            name="test_tool",
            arguments={"param": "value"},
        )
        assert tc.id == "call_123"
        assert tc.name == "test_tool"
        assert tc.arguments["param"] == "value"

    def test_llm_response_creation(self):
        resp = LLMResponse(
            content="Test content",
            tool_calls=[],
            finish_reason="stop",
        )
        assert resp.content == "Test content"
        assert resp.finish_reason == "stop"
