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
def freewill(
    target: str = typer.Argument(..., help="Target IP or CIDR"),
    model: str = typer.Option("mimo", help="LLM model to use"),
    scope: Optional[str] = typer.Option(None, help="Scope (CIDR), defaults to target"),
    max_cycles: int = typer.Option(100, help="Max engagement cycles"),
):
    """Start fully autonomous LLM-driven engagement.

    The LLM decides EVERYTHING:
    - What to scan
    - What to enumerate
    - What to exploit
    - How to pivot
    - What to report

    Examples:
        pen-ai freewill 10.10.10.0/24
        pen-ai freewill 192.168.1.0/24 --model deepseek
        pen-ai freewill 10.10.10.5 --scope 10.10.10.0/24
    """
    from ai.freewill_agent import FreewillAgent
    from ai.llm_client import LLMClient
    from app.config.models import get_model_config

    # Setup LLM
    llm = None
    try:
        config = get_model_config(model)
        llm = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", "https://opencode.ai/zen/v1"),
            model=config.get("model_id", "mimo-v2.5-free"),
        )
    except Exception as e:
        console.print(f"[yellow]Warning: Could not setup LLM: {e}[/yellow]")
        console.print("[yellow]Running in fallback mode (limited intelligence)[/yellow]")

    # Create and run agent
    agent = FreewillAgent(llm_client=llm)
    asyncio.run(agent.engage(target=target, scope=scope, max_cycles=max_cycles))


@app.command()
def enterprise(
    target: str = typer.Argument(..., help="Target IP or CIDR"),
    chain: str = typer.Option("auto", help="Attack chain: auto, ad, exchange, sccm, network, database"),
    username: Optional[str] = typer.Option(None, help="Username for authentication"),
    password: Optional[str] = typer.Option(None, help="Password for authentication"),
    domain: Optional[str] = typer.Option(None, help="AD domain name"),
):
    """Enterprise pentesting mode.

    Runs enterprise-specific attack chains:
    - Active Directory (full AD kill chain)
    - Exchange Server attacks
    - SCCM/ConfigMgr attacks
    - Network infrastructure attacks
    - Database attacks

    Examples:
        pen-ai enterprise 10.10.10.0/24 --chain ad
        pen-ai enterprise 10.10.10.5 --chain exchange
        pen-ai enterprise 10.10.10.0/24 --chain ad --username admin --password P@ssw0rd --domain corp.local
    """
    from ai.freewill_agent import FreewillAgent
    from ai.llm_client import LLMClient
    from app.config.models import get_model_config

    # Setup LLM
    llm = None
    try:
        config = get_model_config("mimo")
        llm = LLMClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", "https://opencode.ai/zen/v1"),
            model=config.get("model_id", "mimo-v2.5-free"),
        )
    except Exception:
        pass

    # Create agent
    agent = FreewillAgent(llm_client=llm)

    # Build creds
    creds = {}
    if username:
        creds["username"] = username
    if password:
        creds["password"] = password
    if domain:
        creds["domain"] = domain

    async def run_enterprise():
        """Run enterprise engagement."""
        agent.target = target
        agent.scope = target

        print(f"\n{'='*60}")
        print(f"  🏢 PEN-AI ENTERPRISE MODE")
        print(f"  Target: {target}")
        print(f"  Chain: {chain}")
        if username:
            print(f"  User: {username}@{domain or 'N/A'}")
        print(f"{'='*60}\n")

        if chain == "auto":
            # Run all applicable chains
            chains_to_run = ["ad", "exchange", "sccm", "network", "database"]
            for chain_name in chains_to_run:
                result = await agent.enterprise_attack_chain(chain_name, target, creds)
                if result.get("findings"):
                    print(f"\n  [{chain_name.upper()}] Findings:")
                    for f in result["findings"]:
                        print(f"    • {f}")
                    agent.findings.extend(result["findings"])
        else:
            # Run specific chain
            result = await agent.enterprise_attack_chain(chain, target, creds)
            if result.get("findings"):
                print(f"\n  [{chain.upper()}] Findings:")
                for f in result["findings"]:
                    print(f"    • {f}")
                agent.findings.extend(result["findings"])

        # Also run general pentest
        print(f"\n  Running general penetration test...")
        await agent.engage(target=target, scope=target, max_cycles=50)

    asyncio.run(run_enterprise())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or CIDR"),
    model: str = typer.Option("mimo", help="LLM model"),
):
    """Quick scan - just scan and show results."""
    from app.terminal.repl import PenAIRepl

    repl = PenAIRepl()
    asyncio.run(repl._cmd_scan(target))
    repl._cmd_dashboard()
    repl._cmd_suggest()


@app.command()
def fingerprint(
    target: str = typer.Argument(..., help="Target IP"),
    port: int = typer.Argument(..., help="Port number"),
    service: str = typer.Argument("http", help="Service name"),
):
    """Fingerprint a service and research CVEs.

    Examples:
        pen-ai fingerprint 10.10.10.5 80 http
        pen-ai fingerprint 10.10.10.5 22 ssh
        pen-ai fingerprint 10.10.10.5 445 smb
    """
    from ai.autonomous_executor import AutonomousExecutor
    from enterprise.zeroday_fingerprint import ZeroDayFingerprint

    async def run_fingerprint():
        executor = AutonomousExecutor(timeout=30)
        fp = ZeroDayFingerprint(executor)

        print(f"\n🔍 Fingerprinting {target}:{port} ({service})...")

        # Deep fingerprint
        result = await fp.deep_fingerprint(target, port, service)

        print(f"\n📋 Results:")
        if result.get("banner"):
            print(f"  Banner: {result['banner'][:200]}")
        if result.get("version_info"):
            print(f"  Version: {result['version_info']}")
        if result.get("http_headers"):
            print(f"  Headers: {result['http_headers'][:200]}")
        if result.get("potential_vulns"):
            print(f"\n  Potential Vulnerabilities:")
            for v in result["potential_vulns"]:
                print(f"    ⚠️  {v}")

        # Research CVEs
        version = result.get("version_info", "")
        if version:
            print(f"\n🔬 Researching CVEs for {service} {version}...")
            vulns = await fp.research_cves(service, version)
            if vulns:
                print(f"\n  Found {len(vulns)} potential vulnerabilities:")
                for v in vulns[:10]:
                    print(f"    [{v.severity.upper()}] {v.cve_id}: {v.title[:60]}")
                    if v.exploit_available:
                        print(f"      💥 Exploit available: {v.exploit_path}")
            else:
                print(f"  No known CVEs found for this version.")

    asyncio.run(run_fingerprint())


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


@app.command()
def chains():
    """List available enterprise attack chains."""
    print("\n  🏢 ENTERPRISE ATTACK CHAINS:")
    print("\n  Active Directory:")
    print("    ad        - Full AD attack chain (enum → kerberoast → privesc → domain compromise)")
    print("\n  Exchange:")
    print("    exchange  - Exchange Server attacks (ProxyShell, ProxyLogon, ProxyNotShell)")
    print("\n  SCCM:")
    print("    sccm      - SCCM/ConfigMgr attacks")
    print("\n  Network Infrastructure:")
    print("    network   - Router/switch/firewall attacks (SNMP, default creds)")
    print("\n  Database:")
    print("    database  - MySQL, MSSQL, PostgreSQL, Oracle attacks")
    print("\n  Cloud:")
    print("    aws       - AWS cloud attacks (S3, EC2 metadata)")
    print("    azure     - Azure cloud attacks")
    print("\n  Usage:")
    print("    pen-ai enterprise <target> --chain ad")
    print("    pen-ai enterprise <target> --chain auto  # Run all chains")
    print("\n  🔬 Zero-Day Fingerprinting:")
    print("    pen-ai fingerprint <target> <port> <service>")


if __name__ == "__main__":
    app()
