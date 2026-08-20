"""Tests for the AI Brain v3 module (ai/ai_brain.py)."""

import asyncio
import json

import pytest

from ai.ai_brain import (
    AIBrain,
    BrainAnalysis,
    BrainDecision,
    BrainFinding,
    BrainMemory,
)

TMP_TARGET = "10.99.99.10"  # unlikely to collide in real engagements


def canned_analysis_payload() -> dict:
    """A realistic LLM analysis response for tests."""
    return {
        "hypothesis": "target exposes a web service",
        "findings": [
            {
                "category": "sqli",
                "severity": "high",
                "title": "SQLi in /i",
                "evidence": "sqlalchemy error",
                "exploitable": True,
                "chain_with": ["/admin"],
            }
        ],
        "next_actions": [
            {
                "command": "sqlmap -u http://10.99.99.99:80 --batch",
                "reasoning": "/id is injectable",
                "priority": "high",
                "confidence": 0.9,
                "category": "exploit",
                "expected_outcome": "database access",
                "alternatives": ["curl probe"],
            }
        ],
        "new_hosts": ["10.99.99.99"],
        "new_services": [["10.99.99.99", "80", "http", ""]],
        "new_credentials": [],
        "phase": "exploitation",
        "done": False,
        "lesson": "check /id payloads fast",
    }


class FakeLLM:
    """Minimal stand-in for LLMClient that returns canned JSON."""

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = []

    async def chat(self, messages):
        self.calls.append([m.to_dict() for m in messages])
        from ai.llm_client import LLMResponse

        return LLMResponse(content=json.dumps(self.payload))


class TestRobustJson:
    """The brain must survive messy LLM output."""

    def test_plain_json(self):
        assert AIBrain._robust_json('{"a": 1}') == {"a": 1}

    def test_fenced_json(self):
        text = 'Here you go:\n```json\n{"a": 2}\n```\nDone.'
        assert AIBrain._robust_json(text) == {"a": 2}

    def test_trailing_commas(self):
        assert AIBrain._robust_json('{"a": 3,}') == {"a": 3}

    def test_garbage(self):
        assert AIBrain._robust_json("no json here") == {}

    def test_nested(self):
        text = 'prefix {"next_actions": [{"command": "nmap -sV x"}]} suffix'
        parsed = AIBrain._robust_json(text)
        assert parsed["next_actions"][0]["command"] == "nmap -sV x"


class TestBrainMemory:
    def test_record_and_reload(self, tmp_path):
        mem = BrainMemory(target=TMP_TARGET, memory_dir=tmp_path)
        mem.record("nmap -sV 1.2.3.4", success=True, reasoning="found services")
        mem.record("hydra -l root -P x ssh://1.2.3.4", success=False)
        assert mem.stats()["lessons_recorded"] == 2

        # Reload from disk
        mem2 = BrainMemory(target=TMP_TARGET, memory_dir=tmp_path)
        assert mem2.stats()["lessons_recorded"] == 2

    def test_avoid_failed_technique(self, tmp_path):
        mem = BrainMemory(target=TMP_TARGET, memory_dir=tmp_path)
        mem.record("nmap -sV 1.2.3.4", success=False)
        assert mem.avoid("nmap -sV 1.2.3.4") is True
        assert mem.avoid("curl -s http://1.2.3.4/") is False

    def test_corrupt_file_tolerated(self, tmp_path):
        f = tmp_path / f"{TMP_TARGET}.json"
        f.write_text("{not json")
        mem = BrainMemory(target=TMP_TARGET, memory_dir=tmp_path)
        assert mem.stats()["lessons_recorded"] == 0
class TestAIBrainHeuristic:
    @pytest.mark.asyncio
    async def test_analyze_recon_output_extracts_hosts(self, tmp_path):
        brain = AIBrain(target="10.99.0.0/16", memory_dir=tmp_path)
        analysis = await brain.analyze_output(
            "nmap -sn 10.99.0.0/16",
            "Nmap scan report for 10.99.1.1",
            0,
        )
        assert isinstance(analysis, BrainAnalysis)
        assert "10.99.1.1" in brain.hosts

    @pytest.mark.asyncio
    async def test_decide_next_never_empty(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        decisions = await brain.decide_next()
        assert decisions
        assert all(isinstance(d, BrainDecision) for d in decisions)
        assert all(d.command for d in decisions)

    @pytest.mark.asyncio
    async def test_decide_next_skips_failed_techniques(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        brain.memory.record("nmap -sn -T4 10.99.0.1", success=False)
        decisions = await brain.decide_next()
        assert not any("nmap -sn" in d.command for d in decisions)

    @pytest.mark.asyncio
    async def test_adaptive_alternatives_for_nmap(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        alts = await brain.suggest_alternatives("nmap -sV 10.99.0.1")
        assert alts
        assert any("masscan" in a or "rustscan" in a for a in alts)

    @pytest.mark.asyncio
    async def test_adaptive_alternatives_for_bruteforce(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        alts = await brain.suggest_alternatives("hydra -l root -P rockyou ssh://10.99.0.1")
        assert alts
        assert any("crackmapexec" in a for a in alts)

    def test_starts_in_recon_phase(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        assert brain.phase == "recon"


class TestAIBrainWithLLM:
    @pytest.mark.asyncio
    async def test_analyze_output_with_llm(self, tmp_path):
        llm = FakeLLM(canned_analysis_payload())
        brain = AIBrain(llm=llm, target="10.99.0.1", memory_dir=tmp_path)
        analysis = await brain.analyze_output(
            "curl -i http://10.99.0.1/", "HTTP/1.1 200 OK", 0
        )

        assert llm.calls, "LLM should have been called"
        assert analysis.hypothesis == "target exposes a web service"
        assert any(f.category == "sqli" for f in analysis.findings)
        assert analysis.next_actions
        assert analysis.next_actions[0].command.startswith("sqlmap")
        # phase updated from the LLM
        assert brain.phase == "exploitation"
        # facts absorbed regardless of the LLM
        assert "10.99.99.99" in brain.hosts

    @pytest.mark.asyncio
    async def test_decide_next_with_llm(self, tmp_path):
        llm = FakeLLM(
            {
                "next_actions": [
                    {
                        "command": "nmap -p- 10.99.0.1",
                        "reasoning": "full port sweep",
                        "priority": "high",
                        "confidence": 0.8,
                        "category": "enumerate",
                        "expected_outcome": "all ports",
                        "alternatives": [],
                    }
                ]
            }
        )
        brain = AIBrain(llm=llm, target="10.99.0.1", memory_dir=tmp_path)
        decisions = await brain.decide_next()
        assert decisions
        assert decisions[0].command == "nmap -p- 10.99.0.1"

    @pytest.mark.asyncio
    async def test_suggest_alternatives_with_llm(self, tmp_path):
        llm = FakeLLM(
            {
                "alternatives": [
                    {"command": "crackmapexec smb x", "reasoning": "smb is better"},
                    {"command": "hydra -l admin", "reasoning": "different creds"},
                    {"command": "nmap --script vuln", "reasoning": "script scan"},
                ]
            }
        )
        brain = AIBrain(llm=llm, target="10.99.0.1", memory_dir=tmp_path)
        alts = await brain.suggest_alternatives("hydra -l root ssh")
        assert len(alts) == 3
        assert "crackmapexec" in alts[0]

    @pytest.mark.asyncio
    async def test_llm_garbage_is_tolerated(self, tmp_path):
        llm = FakeLLM({})  # payload that yields no useful JSON
        brain = AIBrain(llm=llm, target="10.99.0.1", memory_dir=tmp_path)
        analysis = await brain.analyze_output("nmap -sn 10.99.0.0/24", "nothing useful", 0)
        # Falls back gracefully, no exception, analysis is still a valid object
        assert isinstance(analysis, BrainAnalysis)


class TestBrainChain:
    @pytest.mark.asyncio
    async def test_heuristic_chain_from_findings(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        brain.findings.append(
            BrainFinding(category="sqli", severity="high", title="SQLi",
                         exploitable=True, target="10.99.0.1")
        )
        brain.credentials.append({"username": "admin", "value": "hunter2"})
        chain = await brain.plan_attack_chain()
        assert chain
        combined = " ".join(s.get("step", "") for s in chain)
        assert "attack" in combined

    @pytest.mark.asyncio
    async def test_chain_empty_without_findings(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        assert await brain.plan_attack_chain() == []

    def test_status_print(self, tmp_path):
        brain = AIBrain(target="10.99.0.1", memory_dir=tmp_path)
        status = brain.print_status()
        assert "AI BRAIN STATUS" in status