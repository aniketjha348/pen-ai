"""PEN-AI CLI - Interactive Penetration Testing Agent."""

import asyncio
import sys
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="pen-ai",
    help="PEN-AI - Autonomous AI Penetration Testing Agent",
    add_completion=False,
)
console = Console()


@app.command()
def main(
    model: str = typer.Option("mimo", help="LLM model to use"),
    resume: Optional[str] = typer.Option(None, help="Resume session ID"),
    target: Optional[str] = typer.Argument(None, help="Target IP or CIDR"),
):
    """Start PEN-AI interactive terminal.

    Examples:
        pen-ai                          # Start interactive mode
        pen-ai 10.10.10.0/24            # Start and scan target
        pen-ai --resume 20260819_1430   # Resume previous session
    """
    from app.terminal.repl import PenAIRepl

    # Setup LLM if model specified
    llm = None
    if model:
        try:
            from ai.llm_client import LLMClient
            from app.config.models import get_model_config
            config = get_model_config(model)
            llm = LLMClient(
                api_key=config.get("api_key", ""),
                base_url=config.get("base_url", "https://opencode.ai/zen/v1"),
                model=config.get("model_id", "mimo-v2.5-free"),
            )
        except Exception:
            pass

    repl = PenAIRepl(llm=llm)

    # Auto-scan if target provided
    if target:
        repl.target = target

    # Auto-resume if session ID provided
    if resume:
        repl._cmd_resume(resume)

    asyncio.run(repl.run())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or CIDR"),
    model: str = typer.Option("mimo", help="LLM model"),
):
    """Quick scan - just scan and show results."""
    from app.terminal.repl import PenAIRepl

    repl = PenAIRepl()
    asyncio.run(repl._cmd_scan(target))
    repl._cmd_state()
    repl._cmd_suggest()


@app.command()
def sessions():
    """List saved sessions."""
    from core.session import SessionManager
    mgr = SessionManager()
    sessions_list = mgr.list_sessions()

    if not sessions_list:
        print("  No saved sessions.")
        return

    print("\n  SAVED SESSIONS:")
    for s in sessions_list:
        print(f"    {s['session_id']} | {s['target']} | {s['hosts']} hosts | {s['credentials']} creds | {s['saved_at'][:19]}")
    print("\n  Resume: pen-ai --resume SESSION_ID")


@app.command()
def tools():
    """List available tools."""
    from app.terminal.repl import PenAIRepl
    repl = PenAIRepl()
    asyncio.run(repl._cmd_install_menu())


if __name__ == "__main__":
    app()
