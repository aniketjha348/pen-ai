"""Tests for safe REPL AI Brain modes."""

from unittest.mock import AsyncMock

import pytest

from ai.ai_brain import BrainDecision
from app.terminal.repl import PenAIRepl


class TestReplBrainModes:
    @pytest.mark.asyncio
    async def test_think_without_target(self, capsys):
        repl = PenAIRepl()
        await repl._cmd_think()
        out = capsys.readouterr().out
        assert "No target set" in out

    @pytest.mark.asyncio
    async def test_think_run_executes_only_top_decision(self):
        repl = PenAIRepl()
        repl.target = "10.10.10.5"
        repl.brain.set_target(repl.target)
        repl.brain.decide_next = AsyncMock(
            return_value=[
                BrainDecision(
                    command="echo safe-step",
                    reasoning="single-step safe test",
                    priority="high",
                    category="recon",
                    expected_outcome="verify top execution",
                ),
                BrainDecision(command="echo second-step", reasoning="should not auto-run"),
            ]
        )
        repl.brain.plan_attack_chain = AsyncMock(return_value=[])
        repl._cmd_run = AsyncMock()

        await repl._cmd_think("run")

        repl._cmd_run.assert_awaited_once_with("echo safe-step")

    @pytest.mark.asyncio
    async def test_think_simulate_does_not_execute(self):
        repl = PenAIRepl()
        repl.target = "10.10.10.5"
        repl.brain.set_target(repl.target)
        repl.brain.decide_next = AsyncMock(
            return_value=[
                BrainDecision(
                    command="echo simulated",
                    reasoning="dry run",
                    priority="medium",
                    category="recon",
                    expected_outcome="show only",
                    alternatives=["echo fallback"],
                )
            ]
        )
        repl.brain.plan_attack_chain = AsyncMock(return_value=[])
        repl._cmd_run = AsyncMock()

        await repl._cmd_think("simulate")

        repl._cmd_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_think_auto_is_single_step_alias(self):
        repl = PenAIRepl()
        repl.target = "10.10.10.5"
        repl.brain.set_target(repl.target)
        repl.brain.decide_next = AsyncMock(
            return_value=[BrainDecision(command="echo alias-step", reasoning="alias")]
        )
        repl.brain.plan_attack_chain = AsyncMock(return_value=[])
        repl._cmd_run = AsyncMock()

        await repl._cmd_think("auto")

        repl._cmd_run.assert_awaited_once_with("echo alias-step")