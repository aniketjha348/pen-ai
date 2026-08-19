"""Real-time streaming output - like Claude Code."""

import sys
import asyncio
from typing import Optional, Callable


class StreamPrinter:
    """Print output character by character like Claude Code."""

    def __init__(self, delay: float = 0.01):
        self.delay = delay
        self._buffer = ""

    async def stream(self, text: str, end: str = "\n"):
        """Stream text character by character."""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            if self.delay > 0:
                await asyncio.sleep(self.delay)
        sys.stdout.write(end)
        sys.stdout.flush()

    async def stream_line(self, text: str, prefix: str = "", color: str = ""):
        """Stream a line with prefix and color."""
        colors = {
            "green": "\033[92m",
            "red": "\033[91m",
            "yellow": "\033[93m",
            "cyan": "\033[96m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "white": "\033[97m",
            "gray": "\033[90m",
            "bold": "\033[1m",
            "reset": "\033[0m",
        }
        color_code = colors.get(color, "")
        reset = colors["reset"] if color else ""
        full = f"{color_code}{prefix}{text}{reset}"
        await self.stream(full)

    async def stream_command(self, cmd: str):
        """Stream a command being executed."""
        await self.stream_line(f"$ {cmd}\n", color="cyan")

    async def stream_output(self, output: str, max_lines: int = 20):
        """Stream command output with line limiting."""
        lines = output.strip().split("\n")
        shown = 0
        for line in lines[:max_lines]:
            await self.stream_line(f"  {line}\n", color="white")
            shown += 1
        if len(lines) > max_lines:
            await self.stream_line(f"  ... {len(lines) - max_lines} more lines\n", color="gray")

    async def stream_success(self, msg: str):
        """Stream success message."""
        await self.stream_line(f"  ✓ {msg}\n", color="green")

    async def stream_error(self, msg: str):
        """Stream error message."""
        await self.stream_line(f"  ✗ {msg}\n", color="red")

    async def stream_info(self, msg: str):
        """Stream info message."""
        await self.stream_line(f"  ℹ {msg}\n", color="yellow")

    async def stream_thinking(self, msg: str):
        """Stream LLM thinking."""
        await self.stream_line(f"  🧠 {msg}\n", color="magenta")

    async def stream_banner(self, text: str):
        """Stream a banner."""
        await self.stream_line(f"\n{text}\n", color="bold")


class ProgressTracker:
    """Track and display progress."""

    def __init__(self):
        self.total = 0
        self.current = 0
        self.description = ""

    def update(self, current: int, description: str = ""):
        self.current = current
        self.description = description

    def get_bar(self, width: int = 30) -> str:
        if self.total == 0:
            return ""
        filled = int(width * self.current / self.total)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * self.current / self.total)
        return f"[{bar}] {pct}% {self.description}"
