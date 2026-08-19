"""Model Registry - Best free models for PEN-AI."""

from dataclasses import dataclass
from enum import Enum


class ModelProvider(str, Enum):
    """LLM providers."""

    OPENCODE = "opencode"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


@dataclass
class ModelInfo:
    """Information about an LLM model."""

    id: str
    name: str
    provider: ModelProvider
    base_url: str
    api_key_required: bool = False
    supports_tools: bool = True
    max_tokens: int = 4096
    description: str = ""
    tier: str = "free"  # free, pro, enterprise


# OpenCode.ai Free Models - Best 3 Only
OPENCODE_BASE_URL = "https://opencode.ai/zen/v1"

# ============================================================
# RECOMMENDED MODELS (Best Free Tier)
# ============================================================

RECOMMENDED_MODELS = {
    "mimo-v2.5-free": ModelInfo(
        id="mimo-v2.5-free",
        name="MiMo-V2.5 Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=8192,
        description="MiMo V2.5 - Best overall free model",
        tier="free",
    ),
    "deepseek-v4-flash-free": ModelInfo(
        id="deepseek-v4-flash-free",
        name="DeepSeek V4 Flash Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=8192,
        description="DeepSeek V4 Flash - Fast and capable",
        tier="free",
    ),
    "hy3-free": ModelInfo(
        id="hy3-free",
        name="Hy3 Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=8192,
        description="Hy3 - Strong reasoning model",
        tier="free",
    ),
}

# ============================================================
# ALL MODELS (Including other free options)
# ============================================================

ALL_MODELS = {
    **RECOMMENDED_MODELS,
    "laguna-s-2.1-free": ModelInfo(
        id="laguna-s-2.1-free",
        name="Laguna S 2.1 Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=4096,
        description="Laguna S 2.1 - Alternative free model",
        tier="free",
    ),
    "nemotron-3-ultra-free": ModelInfo(
        id="nemotron-3-ultra-free",
        name="Nemotron 3 Ultra Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=4096,
        description="Nemotron 3 Ultra - Alternative free model",
        tier="free",
    ),
    "nemotron-3.5-lightning-free": ModelInfo(
        id="nemotron-3.5-lightning-free",
        name="Nemotron 3.5 Lightning Free",
        provider=ModelProvider.OPENCODE,
        base_url=OPENCODE_BASE_URL,
        api_key_required=False,
        supports_tools=True,
        max_tokens=4096,
        description="Nemotron 3.5 Lightning - Alternative free model",
        tier="free",
    ),
}

# Default model - MiMo V2.5 is the best overall
DEFAULT_MODEL = "mimo-v2.5-free"

# Model aliases for easy selection
MODEL_ALIASES = {
    "mimo": "mimo-v2.5-free",
    "deepseek": "deepseek-v4-flash-free",
    "hy3": "hy3-free",
    "fast": "deepseek-v4-flash-free",  # DeepSeek is fastest
    "best": "mimo-v2.5-free",  # MiMo is best overall
    "reasoning": "hy3-free",  # Hy3 is best for reasoning
}


def get_model(model_id: str) -> ModelInfo:
    """Get model info by ID or alias."""
    # Check aliases first
    if model_id in MODEL_ALIASES:
        model_id = MODEL_ALIASES[model_id]

    if model_id in ALL_MODELS:
        return ALL_MODELS[model_id]
    raise ValueError(f"Unknown model: {model_id}. Available: {list(ALL_MODELS.keys())}")


def list_models(recommended_only: bool = False) -> list[ModelInfo]:
    """List available models."""
    if recommended_only:
        return list(RECOMMENDED_MODELS.values())
    return list(ALL_MODELS.values())


def get_free_models() -> list[ModelInfo]:
    """Get all free models."""
    return [m for m in ALL_MODELS.values() if not m.api_key_required]


def get_recommended_models() -> list[ModelInfo]:
    """Get recommended models."""
    return list(RECOMMENDED_MODELS.values())


def get_model_by_alias(alias: str) -> ModelInfo:
    """Get model by alias."""
    if alias in MODEL_ALIASES:
        return get_model(MODEL_ALIASES[alias])
    return get_model(alias)


def get_model_config(model_alias: str) -> dict:
    """Get model configuration as dict for LLM client."""
    try:
        model = get_model(model_alias)
        return {
            "model_id": model.id,
            "name": model.name,
            "base_url": model.base_url,
            "api_key": "",
            "max_tokens": model.max_tokens,
        }
    except ValueError:
        # Default fallback
        return {
            "model_id": "mimo-v2.5-free",
            "name": "MiMo V2.5 Free",
            "base_url": OPENCODE_BASE_URL,
            "api_key": "",
            "max_tokens": 8192,
        }
