"""PEN-AI Configuration Settings with Enterprise Mode."""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


# OpenCode.ai Free Models Base URL
OPENCODE_BASE_URL = "https://opencode.ai/zen/v1"


class LLMConfig(BaseSettings):
    """LLM provider configuration."""

    model: str = "mimo-v2.5-free"
    api_key: str = ""
    base_url: str = OPENCODE_BASE_URL
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 120
    free_tier: bool = True
    rate_limit_delay: float = 1.0


class ReconConfig(BaseSettings):
    """Reconnaissance engine configuration."""

    max_threads: int = 50
    timeout: int = 300
    scan_delay: float = 0.1
    host_discovery_timeout: int = 5
    aggressive_scanning: bool = True


class EngagementConfig(BaseSettings):
    """Engagement storage configuration."""

    base_dir: Path = Path("engagements")
    db_name: str = "engagement.db"
    evidence_dir: str = "raw"
    screenshots_dir: str = "screenshots"
    commands_dir: str = "commands"
    artifacts_dir: str = "artifacts"


class ScopeConfig(BaseSettings):
    """Scope and Rules of Engagement configuration."""

    allowed_targets: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    excluded_ports: list[int] = Field(default_factory=list)
    max_pivots: int = 5
    require_approval: bool = False  # Enterprise mode: no approval needed
    require_approval_for_exploitation: bool = False
    require_approval_for_pivoting: bool = False
    max_scan_intensity: str = "aggressive"


class EnterpriseConfig(BaseSettings):
    """Enterprise mode configuration."""

    enabled: bool = True
    full_auto: bool = True  # No permission prompts
    auto_exploit: bool = True
    auto_pivot: bool = True
    auto_loot: bool = True
    auto_report: bool = True
    max_concurrent_shells: int = 10
    capture_all_commands: bool = True
    capture_all_output: bool = True


class AppConfig(BaseSettings):
    """Main PEN-AI application configuration."""

    app_name: str = "PEN-AI"
    version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    llm: LLMConfig = Field(default_factory=LLMConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    engagement: EngagementConfig = Field(default_factory=EngagementConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    enterprise: EnterpriseConfig = Field(default_factory=EnterpriseConfig)

    model_config = {
        "env_prefix": "PENAI_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


# Global settings instance
settings = AppConfig()
