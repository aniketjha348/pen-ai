"""Tool Registry - Dynamic tool registration and calling for the AI agent."""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from enum import Enum


class ToolCategory(str, Enum):
    """Categories of tools available to PEN-AI."""

    TERMINAL = "terminal"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    RECON = "recon"
    AD = "ad"
    WEB = "web"
    BINARY = "binary"
    IOT = "iot"
    CTF = "ctf"
    NETWORK = "network"
    EXPLOITATION = "exploitation"
    PIVOTING = "pivoting"
    EVIDENCE = "evidence"
    REPORT = "report"


@dataclass
class ToolParameter:
    """Schema for a tool parameter."""

    name: str
    type: str  # str, int, bool, list
    description: str
    required: bool = True
    default: Any = None


@dataclass
class ToolDefinition:
    """Complete definition of a tool."""

    name: str
    description: str
    category: ToolCategory
    parameters: list[ToolParameter] = field(default_factory=list)
    requires_scope_check: bool = True
    requires_approval: bool = False
    executor: Optional[Callable] = None

    def to_schema(self) -> dict:
        """Convert to OpenAI function calling schema."""
        properties = {}
        required = []

        for param in self.parameters:
            properties[param.name] = {
                "type": param.type,
                "description": param.description,
            }
            if param.default is not None:
                properties[param.name]["default"] = param.default
            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


class ToolRegistry:
    """Registry of all tools available to the AI agent."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_all(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())

    def get_by_category(self, category: ToolCategory) -> list[ToolDefinition]:
        """Get tools by category."""
        return [t for t in self._tools.values() if t.category == category]

    def get_schemas(self, categories: Optional[list[ToolCategory]] = None) -> list[dict]:
        """Get OpenAI function schemas for tools, optionally filtered by category."""
        tools = self._tools.values()
        if categories:
            tools = [t for t in tools if t.category in categories]
        return [t.to_schema() for t in tools]

    async def execute(self, name: str, **kwargs) -> dict[str, Any]:
        """Execute a tool by name."""
        tool = self._tools.get(name)
        if not tool:
            return {"error": f"Tool '{name}' not found"}

        if not tool.executor:
            return {"error": f"Tool '{name}' has no executor"}

        try:
            result = await tool.executor(**kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def has_tool(self, name: str) -> bool:
        """Check if a tool exists."""
        return name in self._tools

    def list_names(self) -> list[str]:
        """List all tool names."""
        return list(self._tools.keys())


# Global tool registry
registry = ToolRegistry()


def register_tool(
    name: str,
    description: str,
    category: ToolCategory,
    parameters: Optional[list[ToolParameter]] = None,
    requires_scope_check: bool = True,
    requires_approval: bool = False,
):
    """Decorator to register a tool."""

    def decorator(func: Callable) -> Callable:
        tool = ToolDefinition(
            name=name,
            description=description,
            category=category,
            parameters=parameters or [],
            requires_scope_check=requires_scope_check,
            requires_approval=requires_approval,
            executor=func,
        )
        registry.register(tool)
        return func

    return decorator
