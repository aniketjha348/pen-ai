"""Tests for free model configuration."""

import pytest

from app.config.models import (
    RECOMMENDED_MODELS,
    ALL_MODELS,
    DEFAULT_MODEL,
    MODEL_ALIASES,
    get_model,
    list_models,
    get_free_models,
    get_recommended_models,
    ModelInfo,
    ModelProvider,
)
from app.config.settings import settings, LLMConfig, OPENCODE_BASE_URL
from ai.llm_client import LLMClient


class TestRecommendedModels:
    """Tests for recommended models."""

    def test_recommended_models_count(self):
        assert len(RECOMMENDED_MODELS) == 3

    def test_recommended_models_are_free(self):
        for model in RECOMMENDED_MODELS.values():
            assert model.api_key_required is False

    def test_mimo_in_recommended(self):
        assert "mimo-v2.5-free" in RECOMMENDED_MODELS

    def test_deepseek_in_recommended(self):
        assert "deepseek-v4-flash-free" in RECOMMENDED_MODELS

    def test_hy3_in_recommended(self):
        assert "hy3-free" in RECOMMENDED_MODELS

    def test_default_model_is_mimo(self):
        assert DEFAULT_MODEL == "mimo-v2.5-free"


class TestModelAliases:
    """Tests for model aliases."""

    def test_alias_mimo(self):
        model = get_model("mimo")
        assert model.id == "mimo-v2.5-free"

    def test_alias_deepseek(self):
        model = get_model("deepseek")
        assert model.id == "deepseek-v4-flash-free"

    def test_alias_hy3(self):
        model = get_model("hy3")
        assert model.id == "hy3-free"

    def test_alias_fast(self):
        model = get_model("fast")
        assert model.id == "deepseek-v4-flash-free"

    def test_alias_best(self):
        model = get_model("best")
        assert model.id == "mimo-v2.5-free"

    def test_alias_reasoning(self):
        model = get_model("reasoning")
        assert model.id == "hy3-free"


class TestAllModels:
    """Tests for all models."""

    def test_all_models_count(self):
        assert len(ALL_MODELS) == 6

    def test_get_model(self):
        model = get_model("mimo-v2.5-free")
        assert model.id == "mimo-v2.5-free"
        assert model.name == "MiMo-V2.5 Free"
        assert model.provider == ModelProvider.OPENCODE

    def test_get_model_invalid(self):
        with pytest.raises(ValueError):
            get_model("invalid-model")

    def test_list_models(self):
        models = list_models()
        assert len(models) == 6

    def test_list_recommended_only(self):
        models = list_models(recommended_only=True)
        assert len(models) == 3

    def test_free_models(self):
        free_models = get_free_models()
        assert len(free_models) == 6
        for model in free_models:
            assert model.api_key_required is False

    def test_recommended_models(self):
        models = get_recommended_models()
        assert len(models) == 3

    def test_model_base_url(self):
        for model in ALL_MODELS.values():
            assert model.base_url == OPENCODE_BASE_URL

    def test_model_supports_tools(self):
        for model in ALL_MODELS.values():
            assert model.supports_tools is True


class TestLLMConfig:
    """Tests for LLM configuration."""

    def test_default_config(self):
        config = LLMConfig()
        assert config.model == "mimo-v2.5-free"
        assert config.base_url == OPENCODE_BASE_URL
        assert config.api_key == ""

    def test_free_tier_enabled(self):
        config = LLMConfig()
        assert config.free_tier is True


class TestLLMClientFreeModels:
    """Tests for LLM client with free models."""

    def test_create_client_free_model(self):
        client = LLMClient(
            api_key="",
            base_url=OPENCODE_BASE_URL,
            model="mimo-v2.5-free",
        )
        assert client.api_key == ""
        assert client.model == "mimo-v2.5-free"
        assert client.base_url == OPENCODE_BASE_URL

    def test_create_client_no_auth_header(self):
        """Free models should not require Authorization header."""
        client = LLMClient(api_key="")
        # Check that Authorization header is not set
        assert "Authorization" not in client._client.headers

    def test_rate_limit_config(self):
        client = LLMClient(rate_limit_delay=2.0)
        assert client.rate_limit_delay == 2.0


class TestOrchestratorFreeModels:
    """Tests for orchestrator with free models."""

    def test_orchestrator_default_model(self):
        from ai.llm_client import LLMClient
        from app.config.models import get_model_config
        config = get_model_config("mimo")
        client = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", ""),
            model=config.get("model_id", "mimo-v2.5-free"),
        )
        assert client.model == "mimo-v2.5-free"

    def test_orchestrator_specific_model(self):
        from ai.llm_client import LLMClient
        from app.config.models import get_model_config
        config = get_model_config("deepseek")
        client = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", ""),
            model=config.get("model_id", "deepseek-v4-flash-free"),
        )
        assert client.model == "deepseek-v4-flash-free"

    def test_orchestrator_alias(self):
        from ai.llm_client import LLMClient
        from app.config.models import get_model_config
        config = get_model_config("hy3")
        client = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", ""),
            model=config.get("model_id", "hy3-free"),
        )
        assert client.model == "hy3-free"
