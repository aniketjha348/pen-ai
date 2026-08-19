"""LLM Client - OpenAI-compatible API client with tool calling support."""

import json
import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum

import httpx


class MessageRole(str, Enum):
    """Roles in a conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """A chat message."""

    role: MessageRole
    content: str
    tool_calls: Optional[list[dict]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to API format."""
        msg = {"role": self.role.value, "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        if self.name:
            msg["name"] = self.name
        return msg


@dataclass
class ToolCall:
    """A parsed tool call from the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Response from the LLM."""

    content: Optional[str] = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: Optional[str] = None
    usage: Optional[dict] = None
    raw: Optional[dict] = None


class LLMClient:
    """OpenAI-compatible LLM client with tool calling support.

    Supports both paid APIs (with API key) and free tiers (no key required).
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://opencode.ai/zen/v1",
        model: str = "mimo-v2.5-free",
        temperature: float = 0.3,
        max_tokens: int = 4096,
        timeout: int = 120,
        rate_limit_delay: float = 1.0,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

        # Build headers - only add auth if API key provided
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers=headers,
        )

        # Conversation history
        self._history: list[Message] = []
        self._system_prompt: Optional[str] = None

    def set_system_prompt(self, prompt: str) -> None:
        """Set the system prompt."""
        self._system_prompt = prompt
        # Update or add system message
        if self._history and self._history[0].role == MessageRole.SYSTEM:
            self._history[0] = Message(role=MessageRole.SYSTEM, content=prompt)
        else:
            self._history.insert(0, Message(role=MessageRole.SYSTEM, content=prompt))

    async def _rate_limit(self) -> None:
        """Apply rate limiting for free tier."""
        if self.rate_limit_delay > 0:
            current_time = asyncio.get_event_loop().time()
            elapsed = current_time - self._last_request_time
            if elapsed < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - elapsed)
            self._last_request_time = asyncio.get_event_loop().time()

    async def chat(
        self,
        messages: Optional[list[Message]] = None,
        tools: Optional[list[dict]] = None,
        tool_choice: str = "auto",
        system: Optional[str] = None,
    ) -> str:
        """Send a chat completion request. Returns the LLM's text response.

        Can be called two ways:
        1. chat(messages=[Message(...)], tools=...)  - full control
        2. chat(system="...", messages=[{"role":"user","content":"..."}])  - simple
        """
        await self._rate_limit()

        # Build messages list
        api_messages = []

        if system:
            api_messages.append({"role": "system", "content": system})

        if messages:
            for m in messages:
                if isinstance(m, Message):
                    api_messages.append(m.to_dict())
                elif isinstance(m, dict):
                    api_messages.append(m)

        if not api_messages:
            return "Error: No messages provided"

        payload = {
            "model": self.model,
            "messages": api_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        try:
            response = await self._client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            parsed = self._parse_response(data)
            return parsed.content or ""
        except httpx.HTTPStatusError as e:
            error_msg = f"API error: {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail.get('error', {}).get('message', e.response.text)}"
            except Exception:
                error_msg += f" - {e.response.text[:200]}"
            return error_msg
        except httpx.ConnectError as e:
            return f"Connection error: Could not connect to {self.base_url}. Error: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"

    async def chat_raw(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        tool_choice: str = "auto",
    ) -> LLMResponse:
        """Send a chat completion request. Returns full LLMResponse object."""
        await self._rate_limit()

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        try:
            response = await self._client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_response(data)
        except httpx.HTTPStatusError as e:
            error_msg = f"API error: {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail.get('error', {}).get('message', e.response.text)}"
            except Exception:
                error_msg += f" - {e.response.text[:200]}"
            return LLMResponse(
                content=error_msg,
                finish_reason="error",
            )
        except httpx.ConnectError as e:
            return LLMResponse(
                content=f"Connection error: Could not connect to {self.base_url}. Error: {str(e)}",
                finish_reason="error",
            )
        except Exception as e:
            return LLMResponse(
                content=f"Error: {str(e)}",
                finish_reason="error",
            )

    async def complete(
        self,
        prompt: str,
        tools: Optional[list[dict]] = None,
        system_prompt: Optional[str] = None,
    ) -> LLMResponse:
        """Complete a single prompt."""
        messages = []

        if system_prompt:
            messages.append(Message(role=MessageRole.SYSTEM, content=system_prompt))

        messages.append(Message(role=MessageRole.USER, content=prompt))

        return await self.chat(messages, tools=tools)

    async def reason(
        self,
        context: str,
        question: str,
        tools: Optional[list[dict]] = None,
    ) -> LLMResponse:
        """Reason about a question given context."""
        prompt = f"""Context:
{context}

Question: {question}

Think step by step about the best action to take. Consider:
1. What information do we have?
2. What are the possible actions?
3. Which action gives the most information gain?
4. What are the risks?

Provide your reasoning and, if appropriate, select a tool to execute."""

        return await self.complete(prompt, tools=tools)

    async def decide_action(
        self,
        state_summary: str,
        hypotheses: str,
        available_actions: str,
        tools: list[dict],
    ) -> LLMResponse:
        """Decide the next action to take."""
        prompt = f"""You are PEN-AI, an AI penetration testing operator.

Current State:
{state_summary}

Active Hypotheses:
{hypotheses}

Available Actions:
{available_actions}

Based on the current state and hypotheses, decide the BEST next action to take.
Consider:
- Information gain
- Risk level
- Alignment with objectives
- Previous failures to avoid

Select the most appropriate tool to execute next."""

        return await self.chat(
            [
                Message(role=MessageRole.SYSTEM, content=self._get_system_prompt()),
                Message(role=MessageRole.USER, content=prompt),
            ],
            tools=tools if tools else None,
        )

    async def analyze_result(
        self,
        action: str,
        result: str,
        state_summary: str,
    ) -> LLMResponse:
        """Analyze the result of an action."""
        prompt = f"""Analyze the result of this penetration testing action:

Action: {action}
Result: {result}

Current State:
{state_summary}

Provide:
1. What did we learn?
2. What new attack surfaces are revealed?
3. What should we do next?
4. Any credentials or vulnerabilities found?"""

        return await self.complete(prompt)

    def _parse_response(self, data: dict) -> LLMResponse:
        """Parse API response."""
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})

        content = message.get("content")
        tool_calls = []

        # Parse tool calls
        if "tool_calls" in message:
            for tc in message["tool_calls"]:
                func = tc.get("function", {})
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}

                tool_calls.append(
                    ToolCall(
                        id=tc.get("id", ""),
                        name=func.get("name", ""),
                        arguments=args,
                    )
                )

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage"),
            raw=data,
        )

    def _get_system_prompt(self) -> str:
        """Get the system prompt."""
        return self._system_prompt or """You are PEN-AI, an AI-powered penetration testing operator.

You are authorized to perform penetration testing on the target environment.
Your goal is to discover vulnerabilities, gain access, escalate privileges, and capture objectives.

Key principles:
1. Observe before acting
2. Generate hypotheses from evidence
3. Plan actions based on information gain
4. Execute tools carefully
5. Learn from failures
6. Stay within scope

You have access to various tools for reconnaissance, exploitation, and post-exploitation.
Always explain your reasoning before selecting a tool."""

    def add_to_history(self, message: Message) -> None:
        """Add a message to history."""
        self._history.append(message)

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._history = []
        if self._system_prompt:
            self._history.append(Message(role=MessageRole.SYSTEM, content=self._system_prompt))

    def get_history(self) -> list[Message]:
        """Get conversation history."""
        return self._history.copy()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
