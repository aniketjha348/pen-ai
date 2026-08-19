"""Main Orchestrator - Autonomous LLM-driven engagement loop."""

import asyncio
from typing import Optional

from ai.autonomous_agent import AutonomousAgent
from ai.llm_client import LLMClient
from app.config.models import get_model_config


async def run_engagement(
    target: str,
    scope: Optional[str] = None,
    model: str = "mimo",
    api_key: str = "",
    base_url: str = "",
    max_cycles: int = 500,
):
    """Run an autonomous engagement. The LLM decides everything."""

    # Get model configuration
    model_config = get_model_config(model)

    # Initialize LLM client
    llm = LLMClient(
        api_key=api_key or model_config.get("api_key", ""),
        base_url=base_url or model_config.get("base_url", "https://opencode.ai/zen/v1"),
        model=model_config.get("model_id", "mimo-v2.5-free"),
        temperature=0.3,
        max_tokens=4096,
    )

    # Create autonomous agent
    agent = AutonomousAgent(llm_client=llm)

    # Run engagement
    await agent.engage(target, scope)

    # Return report
    return agent.get_report()
