"""PEN-AI Professional CLI UI - Beautiful terminal interface using Rich."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.columns import Columns
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich import box
from datetime import datetime


console = Console()


class PenAIUI:
    """Professional terminal UI for PEN-AI."""

    # Color scheme
    COLORS = {
        "primary": "red",
        "secondary": "cyan",
        "success": "green",
        "warning": "yellow",
        "danger": "bold red",
        "info": "blue",
        "muted": "dim",
        "accent": "magenta",
    }

    @staticmethod
    def banner():
        """Show the main banner."""
        banner_text = """
[bold red]
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ╚██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝ ╚═════╝ ╚══════╝[/]
[bold white]  Autonomous Penetration Testing Agent v2.2[/]
[dim]  Type 'help' for commands. Ctrl+C to exit.[/]"""

        console.print(Panel(
            banner_text,
            border_style="red",
            padding=(0, 2),
        ))

    @staticmethod
    def header(title: str, subtitle: str = ""):
        """Show a section header."""
        if subtitle:
            console.print(f"\n[bold {PenAIUI.COLORS['primary']}]{title}[/] [dim]{subtitle}[/]")
        else:
            console.print(f"\n[bold {PenAIUI.COLORS['primary']}]{title}[/]")
        console.print(f"[dim]{'─' * 50}[/]")

    @staticmethod
    def success(msg: str):
        """Show success message."""
        console.print(f"  [green]✓[/] {msg}")

    @staticmethod
    def error(msg: str):
        """Show error message."""
        console.print(f"  [bold red]✗[/] {msg}")

    @staticmethod
    def warning(msg: str):
        """Show warning message."""
        console.print(f"  [yellow]⚠[/] {msg}")

    @staticmethod
    def info(msg: str):
        """Show info message."""
        console.print(f"  [blue]ℹ[/] {msg}")

    @staticmethod
    def command(cmd: str):
        """Show command being executed."""
        console.print(f"  [dim]$[/] [cyan]{cmd}[/]")

    @staticmethod
    def output_line(line: str):
        """Show output line."""
        console.print(f"    [dim]{line}[/]")

    @staticmethod
    def dashboard(target: str, session_id: str, hosts: list, services: dict,
                  credentials: list, access_map: dict, pivoted: list,
                  commands_run: list, start_time: datetime):
        """Show professional dashboard."""
        elapsed = datetime.now() - start_time
        minutes = int(elapsed.total_seconds() / 60)
        seconds = int(elapsed.total_seconds() % 60)
        total_svcs = sum(len(v) for v in services.values())

        # Stats table
        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column("Key", style="bold white")
        stats_table.add_column("Value", style="cyan")

        stats_table.add_row("Target", target or "Not set")
        stats_table.add_row("Session", session_id)
        stats_table.add_row("Duration", f"{minutes}m {seconds}s")
        stats_table.add_row("Commands", str(len(commands_run)))

        # Metrics
        metrics = Table(show_header=False, box=None, padding=(0, 2))
        metrics.add_column("Metric", style="bold")
        metrics.add_column("Count", justify="right")

        metrics.add_row("[green]Hosts[/]", f"[green]{len(hosts)}[/]")
        metrics.add_row("[cyan]Services[/]", f"[cyan]{total_svcs}[/]")
        metrics.add_row("[red]Credentials[/]", f"[red]{len(credentials)}[/]")
        metrics.add_row("[magenta]Access[/]", f"[magenta]{len(access_map)}[/]")
        metrics.add_row("[yellow]Networks[/]", f"[yellow]{len(pivoted)}[/]")

        # Combine
        layout = Layout()
        layout.split_row(
            Layout(stats_table, ratio=1),
            Layout(metrics, ratio=1),
        )

        console.print(Panel(
            layout,
            title="[bold red]📊 ENGAGEMENT DASHBOARD[/]",
            border_style="red",
            padding=(1, 2),
        ))

        # Hosts table
        if hosts:
            hosts_table = Table(
                title="[bold green]🖥️  HOSTS[/]",
                box=box.ROUNDED,
                show_lines=True,
                border_style="green",
            )
            hosts_table.add_column("IP", style="cyan", no_wrap=True)
            hosts_table.add_column("Access", style="bold")
            hosts_table.add_column("Services", style="dim")

            for h in hosts:
                svcs = services.get(h, [])
                access = access_map.get(h, "")
                access_style = "[green]" if access else "[dim]"
                svc_str = ", ".join(f"{s.get('port', '?')}/{s.get('service', '?')}" for s in svcs[:5])
                if len(svcs) > 5:
                    svc_str += f" +{len(svcs)-5} more"

                hosts_table.add_row(
                    h,
                    f"{access_style}{access or 'none'}[/]",
                    svc_str or "[dim]no services[/]",
                )

            console.print(hosts_table)

        # Credentials table
        if credentials:
            creds_table = Table(
                title="[bold red]🔑 CREDENTIALS[/]",
                box=box.ROUNDED,
                show_lines=True,
                border_style="red",
            )
            creds_table.add_column("Type", style="yellow")
            creds_table.add_column("Value", style="white")
            creds_table.add_column("Source", style="dim")

            for c in credentials[:10]:
                creds_table.add_row(
                    c.get("type", "?"),
                    str(c.get("value", ""))[:50],
                    c.get("target", ""),
                )

            console.print(creds_table)

        # Access table
        if access_map:
            access_table = Table(
                title="[bold magenta]🎯 ACCESS LEVELS[/]",
                box=box.ROUNDED,
                border_style="magenta",
            )
            access_table.add_column("Host", style="cyan")
            access_table.add_column("Level", style="bold red")

            for h, level in access_map.items():
                access_table.add_row(h, level)

            console.print(access_table)

    @staticmethod
    def scan_results(hosts: list, services: dict):
        """Show scan results in a professional table."""
        if not hosts:
            console.print("[yellow]No hosts found.[/]")
            return

        table = Table(
            title="[bold cyan]🔍 SCAN RESULTS[/]",
            box=box.ROUNDED,
            show_lines=True,
            border_style="cyan",
        )
        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Port", justify="right", style="green")
        table.add_column("Service", style="white")
        table.add_column("Version", style="dim")

        for host in hosts:
            svcs = services.get(host, [])
            if svcs:
                for i, svc in enumerate(svcs):
                    table.add_row(
                        host if i == 0 else "",
                        str(svc.get("port", "?")),
                        svc.get("service", "?"),
                        svc.get("version", "")[:30],
                    )
            else:
                table.add_row(host, "-", "[dim]no services[/]", "")

        console.print(table)

    @staticmethod
    def exploit_results(attempts: int, successes: int, details: list):
        """Show exploit results."""
        console.print(f"\n[bold red]⚔️  EXPLOITATION RESULTS[/]")
        console.print(f"[dim]{'─' * 50}[/]")

        # Summary
        summary = Table(show_header=False, box=None)
        summary.add_column("Key", style="bold")
        summary.add_column("Value", justify="right")
        summary.add_row("Attempts", str(attempts))
        summary.add_row("[green]Success[/]", f"[green]{successes}[/]")
        summary.add_row("[red]Failed[/]", f"[red]{attempts - successes}[/]")
        console.print(summary)

        # Details
        if details:
            details_table = Table(
                title="[dim]Details[/]",
                box=box.SIMPLE,
                border_style="dim",
            )
            details_table.add_column("Target", style="cyan")
            details_table.add_column("Technique", style="white")
            details_table.add_column("Status", justify="center")

            for d in details:
                status = "[green]✓[/]" if d.get("success") else "[red]✗[/]"
                details_table.add_row(
                    d.get("target", "?"),
                    d.get("technique", "?"),
                    status,
                )

            console.print(details_table)

    @staticmethod
    def network_map(hosts: list, services: dict, access_map: dict, pivoted: list):
        """Show network visualization."""
        console.print(f"\n[bold cyan]🗺️  NETWORK MAP[/]")
        console.print(f"[dim]{'─' * 50}[/]")

        if not hosts:
            console.print("[dim]No hosts discovered yet.[/]")
            return

        # Group by network
        networks = {}
        for host in hosts:
            parts = host.split(".")
            if len(parts) == 4:
                network = ".".join(parts[:3]) + ".0/24"
                if network not in networks:
                    networks[network] = []
                networks[network].append(host)

        for network, net_hosts in networks.items():
            console.print(f"\n  [bold cyan][{network}][/]")
            for i, host in enumerate(net_hosts):
                is_last = i == len(net_hosts) - 1
                prefix = "└── " if is_last else "├── "
                access = access_map.get(host, "")
                access_str = f" [bold red][{access}][/]" if access else ""

                console.print(f"  {prefix}[green]{host}[/]{access_str}")

                svcs = services.get(host, [])
                if svcs:
                    svc_prefix = "    " if is_last else "│   "
                    svc_strs = [f"{s.get('port', '?')}/{s.get('service', '?')}" for s in svcs[:5]]
                    console.print(f"  {svc_prefix}[dim]{' | '.join(svc_strs)}[/]")

        if pivoted:
            console.print(f"\n  [bold yellow][PIVOTED NETWORKS][/]")
            for net in pivoted:
                console.print(f"  ├── [yellow]{net}[/] [dim](discovered)[/]")

    @staticmethod
    def report_header(session_id: str, target: str, duration: int, commands: int):
        """Show report header."""
        console.print(Panel(
            f"""[bold white]Session:[/]   {session_id}
[bold white]Target:[/]    {target}
[bold white]Duration:[/]  {duration} minutes
[bold white]Commands:[/]  {commands}""",
            title="[bold red]📊 ENGAGEMENT REPORT[/]",
            border_style="red",
            padding=(1, 2),
        ))

    @staticmethod
    def help():
        """Show help with nice formatting."""
        console.print(Panel(
            """[bold cyan]RECON:[/]
  scan <target>          Scan target (hosts + services)
  enum                   Enumerate all discovered services
  map                    Show network visualization

[bold red]EXPLOIT:[/]
  exploit                Auto-exploit all found services
  attack <host>:<port>   Attack specific host:port
  crack                  Crack found hashes

[bold yellow]POST-EXPLOIT:[/]
  privesc                Attempt privilege escalation
  loot                   Harvest credentials and sensitive data
  pivot                  Find and pivot to new networks
  shell <type>           Generate reverse shell

[bold green]INFO:[/]
  dashboard              Show engagement dashboard
  suggest                Get attack suggestions
  brain                  Show AI Brain status + learned lessons
  think                  Suggest next safe moves
  think simulate         Dry-run with fallbacks + lessons
  think explain          Explain why the next moves make sense
  think run              Execute only the top suggested move
  think auto             Alias of think run (single step only)
  report                 Generate HTML + JSON report
  creds                  Show all discovered credentials

[bold magenta]SESSION:[/]
  sessions               List saved sessions
  resume <session_id>    Resume previous session
  replay                 List replayable sessions
  set target <ip>        Set target (auto-scans)

[bold blue]AUTO CHAINS:[/]
  auto                   Full auto: scan → exploit → privesc → loot
  auto-recon             Auto recon chain
  auto-exploit           Auto exploit chain
  auto-post              Auto post-exploit chain

[bold white]TOOLS:[/]
  install <tool>         Install a tool
  run <command>          Run any command
  help                   Show this help
  exit / quit / q        Exit (saves session)""",
            title="[bold red]🎯 PEN-AI COMMANDS[/]",
            border_style="red",
            padding=(1, 2),
        ))

    @staticmethod
    def progress_bar(description: str):
        """Get a progress bar context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/]"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        )
