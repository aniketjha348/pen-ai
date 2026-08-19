"""Terminal UI - Rich-based terminal interface for PEN-AI."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, Any


class TerminalUI:
    """Rich-based terminal interface for PEN-AI."""

    def __init__(self):
        self.console = Console()
        self._live: Optional[Live] = None

    def print_banner(self) -> None:
        """Print the PEN-AI banner."""
        banner = """
[bold red]
 ██████╗ ███████╗███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝ ██╔════╝████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ███╗█████╗  ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██╔══╝  ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold red]
[dim]AI-Powered Adaptive Penetration Testing Operator[/dim]
"""
        self.console.print(banner)

    def print_state(self, state: Any) -> None:
        """Print current engagement state."""
        table = Table(title="Engagement State", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="green")

        table.add_row("Hosts Discovered", str(state.hosts_discovered))
        table.add_row("Services Found", str(state.services_discovered))
        table.add_row("Vulnerabilities", str(state.vulnerabilities_found))
        table.add_row("Credentials Found", str(state.credentials_found))
        table.add_row("Objectives", f"{state.objectives_completed}/{len(state.objectives)}")
        table.add_row("Current Access", state.current_access.value)
        table.add_row("Pivot Depth", f"{state.pivot_depth}/{state.max_pivot_depth}")

        self.console.print(table)

    def print_hypotheses(self, hypotheses: list) -> None:
        """Print current hypotheses."""
        if not hypotheses:
            self.console.print("[dim]No active hypotheses[/dim]")
            return

        table = Table(title="Active Hypotheses", show_header=True, header_style="bold yellow")
        table.add_column("#", style="dim", width=3)
        table.add_column("Hypothesis", max_width=50)
        table.add_column("Confidence", width=10)
        table.add_column("Category", width=12)

        for i, h in enumerate(hypotheses[:5], 1):
            confidence_color = {
                "high": "green",
                "medium": "yellow",
                "low": "red",
            }.get(h.confidence.value, "white")

            table.add_row(
                str(i),
                h.statement,
                f"[{confidence_color}]{h.confidence.value}[/{confidence_color}]",
                h.category,
            )

        self.console.print(table)

    def print_actions(self, actions: list) -> None:
        """Print candidate actions."""
        if not actions:
            self.console.print("[dim]No candidate actions[/dim]")
            return

        table = Table(title="Candidate Actions", show_header=True, header_style="bold green")
        table.add_column("Priority", width=8)
        table.add_column("Action", max_width=40)
        table.add_column("Score", width=6)
        table.add_column("Tool", width=15)

        for action in actions[:5]:
            priority_color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(action.priority.value, "white")

            table.add_row(
                f"[{priority_color}]{action.priority.value}[/{priority_color}]",
                action.description,
                f"{action.score:.2f}",
                action.tool_name or "-",
            )

        self.console.print(table)

    def print_event(self, event: Any) -> None:
        """Print an event."""
        event_type_colors = {
            "host_discovered": "green",
            "service_found": "cyan",
            "vulnerability_found": "yellow",
            "exploit_success": "bold green",
            "exploit_failed": "red",
            "tool_called": "dim",
            "tool_completed": "green",
            "tool_failed": "red",
        }

        color = event_type_colors.get(event.event_type.value, "white")

        self.console.print(
            f"[dim]{event.timestamp.strftime('%H:%M:%S')}[/dim] "
            f"[{color}]{event.event_type.value}[/{color}] "
            f"{event.action}"
        )

    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[bold red]ERROR:[/bold red] {message}")

    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[bold green]SUCCESS:[/bold green] {message}")

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[bold yellow]WARNING:[/bold yellow] {message}")

    def print_info(self, message: str) -> None:
        """Print an info message."""
        self.console.print(f"[bold blue]INFO:[/bold blue] {message}")

    def print_cycle_header(self, cycle: int, max_cycles: int) -> None:
        """Print cycle header."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold]Cycle {cycle}/{max_cycles}[/bold]",
                style="cyan",
            )
        )

    def print_summary(self, state: Any) -> None:
        """Print engagement summary."""
        summary = f"""
[bold]Engagement Summary[/bold]

Hosts Discovered: [green]{state.hosts_discovered}[/green]
Services Found: [green]{state.services_discovered}[/green]
Vulnerabilities: [yellow]{state.vulnerabilities_found}[/yellow]
Credentials Found: [green]{state.credentials_found}[/green]
Objectives Completed: [green]{state.objectives_completed}/{len(state.objectives)}[/green]
Current Access: [cyan]{state.current_access.value}[/cyan]
Pivot Depth: [cyan]{state.pivot_depth}/{state.max_pivot_depth}[/cyan]

[bold green]Engagement Complete![/bold green]
"""
        self.console.print(Panel(summary, title="Final Report", border_style="green"))

    def get_input(self, prompt: str = "pen-ai> ") -> str:
        """Get user input."""
        return self.console.input(f"[bold cyan]{prompt}[/bold cyan]")

    def start_live(self, layout: Layout) -> Live:
        """Start a live display."""
        self._live = Live(layout, console=self.console, refresh_per_second=4)
        self._live.start()
        return self._live

    def stop_live(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()
            self._live = None
