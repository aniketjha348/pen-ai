"""Configuration Loader - Loads and validates PEN-AI configuration."""

import os
from pathlib import Path
from typing import Optional

from app.config.settings import settings, LLMConfig


def load_config_from_env() -> LLMConfig:
    """Load LLM configuration from environment variables."""
    return LLMConfig(
        model=os.getenv("PENAI_LLM_MODEL", settings.llm.model),
        api_key=os.getenv("PENAI_LLM_API_KEY", settings.llm.api_key),
        base_url=os.getenv("PENAI_LLM_BASE_URL", settings.llm.base_url),
        temperature=float(os.getenv("PENAI_LLM_TEMPERATURE", str(settings.llm.temperature))),
        max_tokens=int(os.getenv("PENAI_LLM_MAX_TOKENS", str(settings.llm.max_tokens))),
        timeout=int(os.getenv("PENAI_LLM_TIMEOUT", str(settings.llm.timeout))),
    )


def create_env_file(path: str = ".env") -> None:
    """Create a template .env file."""
    template = """# PEN-AI Configuration
# Copy this file to .env and fill in your values

# LLM Configuration
PENAI_LLM_MODEL=gpt-4o
PENAI_LLM_API_KEY=your-api-key-here
PENAI_LLM_BASE_URL=https://api.openai.com/v1
PENAI_LLM_TEMPERATURE=0.3
PENAI_LLM_MAX_TOKENS=4096
PENAI_LLM_TIMEOUT=120

# Recon Configuration
PENAI_RECON_MAX_THREADS=50
PENAI_RECON_TIMEOUT=30

# Engagement Configuration
PENAI_ENGAGEMENT_BASE_DIR=engagements

# Scope Configuration
PENAI_SCOPE_MAX_PIVOTS=3
PENAI_SCOPE_REQUIRE_APPROVAL=false
"""
    Path(path).write_text(template)
    print(f"Created template config at {path}")


def validate_config() -> tuple[bool, list[str]]:
    """Validate the current configuration."""
    errors = []

    if not settings.llm.api_key:
        errors.append("LLM API key not configured (set PENAI_LLM_API_KEY)")

    if settings.llm.temperature < 0 or settings.llm.temperature > 2:
        errors.append("LLM temperature must be between 0 and 2")

    if settings.llm.max_tokens < 100:
        errors.append("LLM max_tokens must be at least 100")

    return len(errors) == 0, errors


def get_config_summary() -> str:
    """Get a summary of current configuration."""
    valid, errors = validate_config()

    summary = f"""PEN-AI Configuration Summary
{'=' * 40}

LLM Configuration:
  Model: {settings.llm.model}
  Base URL: {settings.llm.base_url or 'https://api.openai.com/v1'}
  API Key: {'configured' if settings.llm.api_key else 'NOT CONFIGURED'}
  Temperature: {settings.llm.temperature}
  Max Tokens: {settings.llm.max_tokens}
  Timeout: {settings.llm.timeout}s

Recon Configuration:
  Max Threads: {settings.recon.max_threads}
  Timeout: {settings.recon.timeout}s

Scope Configuration:
  Max Pivots: {settings.scope.max_pivots}
  Require Approval: {settings.scope.require_approval}

Status: {'✓ Valid' if valid else '✗ Invalid'}
"""
    if errors:
        summary += "\nErrors:\n"
        for error in errors:
            summary += f"  - {error}\n"

    return summary
