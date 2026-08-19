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


@app.command()
def analyze(
    binary: str = typer.Argument(..., help="Path to binary file"),
):
    """Analyze binary for vulnerabilities (OSCP/CPENT).

    Checks protections, finds dangerous functions, suggests exploit techniques.

    Examples:
        pen-ai analyze /tmp/vuln
        pen-ai analyze ./bof_binary
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.binary_analysis import BinaryAnalyzer

    async def run_analyze():
        executor = AutonomousExecutor(timeout=60)
        analyzer = BinaryAnalyzer(executor)

        print(f"\n🔍 Analyzing {binary}...")
        info = await analyzer.analyze_binary(binary)
        analyzer.print_analysis(info)

        suggestions = analyzer.get_exploitation_suggestions(info)
        if suggestions:
            print(f"\n  EXPLOITATION SUGGESTIONS:")
            for s in suggestions:
                print(f"    [{s['difficulty'].upper()}] {s['technique']}: {s['reason']}")

    asyncio.run(run_analyze())


@app.command()
def shellcode(
    payload: str = typer.Option("reverse_tcp", help="Payload type: reverse_tcp, bind_tcp, exec"),
    lhost: str = typer.Option("127.0.0.1", help="Listener host"),
    lport: int = typer.Option(4444, help="Listener port"),
    arch: str = typer.Option("x64", help="Architecture: x86, x64"),
    encoder: str = typer.Option("", help="Encoder: x86/shikata_ga_nai"),
    bad_chars: str = typer.Option("\\x00\\x0a\\x0d", help="Bad characters to avoid"),
):
    """Generate shellcode (OSCP/CPENT).

    Uses msfvenom to generate encoded shellcode.

    Examples:
        pen-ai shellcode --payload reverse_tcp --lhost 10.10.14.5 --lport 4444
        pen-ai shellcode --payload bind_tcp --lport 4444 --arch x86
        pen-ai shellcode --encoder x86/shikata_ga_nai
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.shellcode_gen import ShellcodeGenerator

    async def run_shellcode():
        executor = AutonomousExecutor(timeout=60)
        gen = ShellcodeGenerator(executor)

        print(f"\n🔧 Generating shellcode...")
        print(f"  Payload:  {payload}")
        print(f"  LHOST:    {lhost}")
        print(f"  LPORT:    {lport}")
        print(f"  Arch:     {arch}")
        if encoder:
            print(f"  Encoder:  {encoder}")
        print(f"  Bad chars: {bad_chars}")

        sc = await gen.generate(
            payload_type=payload,
            lhost=lhost,
            lport=lport,
            arch=arch,
            encoder=encoder,
            bad_chars=bad_chars,
        )

        gen.print_shellcode(sc)

        # Save to file
        if sc.payload:
            filename = gen.save_shellcode(sc)
            print(f"\n  Saved to: {filename}")

    asyncio.run(run_shellcode())


@app.command()
def exploit(
    binary: str = typer.Argument(..., help="Path to vulnerable binary"),
    technique: str = typer.Option("auto", help="Technique: auto, bof, ret2libc, rop, fmtstr"),
    offset: int = typer.Option(0, help="Buffer overflow offset (0 = auto-find)"),
    arch: str = typer.Option("x64", help="Architecture: x86, x64"),
):
    """Generate exploit script (OSCP/CPENT).

    Analyzes binary and generates pwntools exploit script.

    Examples:
        pen-ai exploit ./vuln_binary
        pen-ai exploit ./bof --technique bof --offset 72
        pen-ai exploit ./vuln --technique ret2libc
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.binary_analysis import BinaryAnalyzer
    from exploitation.exploit_dev import ExploitFramework

    async def run_exploit():
        executor = AutonomousExecutor(timeout=60)
        analyzer = BinaryAnalyzer(executor)
        framework = ExploitFramework(executor)

        print(f"\n🔧 Generating exploit for {binary}...")

        # Analyze binary first
        info = await analyzer.analyze_binary(binary)

        # Auto-detect technique
        if technique == "auto":
            suggestions = analyzer.get_exploitation_suggestions(info)
            if suggestions:
                detected = suggestions[0]['technique'].lower()
                print(f"  Detected technique: {detected}")
                if 'bof' in detected or 'buffer' in detected:
                    detected_tech = "bof"
                elif 'ret2libc' in detected:
                    detected_tech = "ret2libc"
                elif 'rop' in detected:
                    detected_tech = "rop"
                elif 'format' in detected:
                    detected_tech = "fmtstr"
                else:
                    detected_tech = "bof"
            else:
                detected_tech = "bof"
        else:
            detected_tech = technique

        # Auto-find offset if not provided
        if offset == 0 and detected_tech in ['bof', 'rop']:
            print("  Auto-detecting buffer overflow offset...")
            bof_info = await analyzer.find_buffer_overflow(binary)
            if bof_info.get('overflow_offset'):
                detected_offset = bof_info['overflow_offset']
                print(f"  Detected offset: {detected_offset}")
            else:
                detected_offset = 72  # Common default
                print(f"  Using default offset: {detected_offset}")
        else:
            detected_offset = offset

        # Generate exploit
        if detected_tech == "bof":
            exploit_result = await framework.generate_bof_exploit(binary, detected_offset, arch=arch)
        elif detected_tech == "ret2libc":
            exploit_result = await framework.generate_ret2libc(binary, detected_offset, arch=arch)
        elif detected_tech == "rop":
            exploit_result = await framework.generate_rop_chain(binary, detected_offset, arch=arch)
        elif detected_tech == "fmtstr":
            exploit_result = await framework.generate_format_string(binary)
        else:
            exploit_result = await framework.generate_bof_exploit(binary, detected_offset, arch=arch)

        framework.print_exploit(exploit_result)

        # Save exploit
        filename = framework.save_exploit(exploit_result)
        print(f"\n  Exploit saved to: {filename}")
        print(f"  Run with: python3 {filename}")

    asyncio.run(run_exploit())


@app.command()
def gdb(
    binary: str = typer.Argument(..., help="Path to binary file"),
    offset: int = typer.Option(0, help="Buffer overflow offset"),
):
    """Debug binary with GDB (OSCP/CPENT).

    Generates GDB scripts for exploit development.

    Examples:
        pen-ai gdb ./vuln_binary
        pen-ai gdb ./bof --offset 72
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.gdb_helper import GDBHelper

    async def run_gdb():
        executor = AutonomousExecutor(timeout=30)
        helper = GDBHelper(executor)

        print(f"\n🔧 Generating GDB script for {binary}...")

        # Generate GDB script
        if offset > 0:
            script = helper.generate_overflow_debug_script(binary, offset)
            print(f"  Buffer overflow offset: {offset}")
        else:
            script = helper.generate_buffer_overflow_script(binary)

        # Save script
        script_file = f"/tmp/gdb_{binary.replace('/', '_')}.py"
        with open(script_file, "w") as f:
            f.write(script)

        print(f"  GDB script saved to: {script_file}")
        print(f"  Run with: gdb -q -x {script_file} {binary}")

        # Also create pattern file if offset provided
        if offset > 0:
            pattern = helper.create_pattern(offset + 100)
            pattern_file = f"/tmp/pattern_{offset + 100}"
            with open(pattern_file, "w") as f:
                f.write(pattern)
            print(f"  Pattern file: {pattern_file}")

    asyncio.run(run_gdb())


@app.command()
def reverse(
    binary: str = typer.Argument(..., help="Path to binary file"),
):
    """Reverse engineer binary with radare2 (OSCP/CPENT).

    Analyzes functions, imports, strings, and vulnerabilities.

    Examples:
        pen-ai reverse ./vuln_binary
        pen-ai reverse /usr/bin/ls
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.reverse_eng import ReverseEngineer

    async def run_reverse():
        executor = AutonomousExecutor(timeout=60)
        re_eng = ReverseEngineer(executor)

        print(f"\n🔍 Reverse engineering {binary}...")
        result = await re_eng.analyze_r2(binary)
        re_eng.print_analysis(result)

        # Also check for buffer overflow
        bof_info = await re_eng.find_buffer_overflow_pattern(binary)
        if bof_info.get('vulnerable'):
            print(f"\n  ⚠️  BUFFER OVERFLOW DETECTED!")
            if bof_info.get('buffer_size'):
                print(f"  Buffer size: {bof_info['buffer_size']} bytes")
            if bof_info.get('overflow_offset'):
                print(f"  Overflow offset: {bof_info['overflow_offset']} bytes")
            if bof_info.get('dangerous_calls'):
                print(f"  Dangerous calls: {', '.join(bof_info['dangerous_calls'])}")

    asyncio.run(run_reverse())


@app.command()
def oscp(
    target: str = typer.Argument(None, help="Target IP (for network targets)")
):
    """OSCP/CPENT mode - full pentest workflow.

    Combines scanning, enumeration, exploitation, and reporting.

    Examples:
        pen-ai oscp 10.10.10.1
        pen-ai oscp ./vuln_binary
    """
    from ai.autonomous_executor import AutonomousExecutor
    from exploitation.binary_analysis import BinaryAnalyzer
    from exploitation.exploit_dev import ExploitFramework
    from exploitation.shellcode_gen import ShellcodeGenerator
    from exploitation.gdb_helper import GDBHelper

    async def run_oscp():
        executor = AutonomousExecutor(timeout=60)
        analyzer = BinaryAnalyzer(executor)
        framework = ExploitFramework(executor)
        shellcode_gen = ShellcodeGenerator(executor)
        gdb_helper = GDBHelper(executor)

        print(f"\n{'='*60}")
        print(f"  🎯 PEN-AI OSCP/CPENT MODE")
        print(f"{'='*60}\n")

        if not target:
            print("  No target specified. Use: pen-ai oscp <target>")
            return

        # Check if target is a file or network
        import os
        if os.path.isfile(target):
            # Binary analysis workflow
            print(f"  Binary Analysis Mode: {target}")
            print(f"  {'─'*50}")

            # Step 1: Analyze
            print("\n  [1/4] Analyzing binary...")
            info = await analyzer.analyze_binary(target)
            analyzer.print_analysis(info)

            # Step 2: Find vulnerabilities
            print("\n  [2/4] Finding vulnerabilities...")
            suggestions = analyzer.get_exploitation_suggestions(info)
            if suggestions:
                print(f"  Found {len(suggestions)} exploitation techniques:")
                for s in suggestions:
                    print(f"    [{s['difficulty'].upper()}] {s['technique']}")

            # Step 3: Generate exploit
            print("\n  [3/4] Generating exploit...")
            if info.vulnerabilities:
                # Auto-generate based on vulnerabilities
                vuln_types = [v.get('type', '') for v in info.vulnerabilities]
                if any('buffer_overflow' in v for v in vuln_types):
                    bof_info = await analyzer.find_buffer_overflow(target)
                    offset = bof_info.get('overflow_offset', 72)
                    exploit = await framework.generate_bof_exploit(target, offset)
                elif any('format_string' in v for v in vuln_types):
                    exploit = await framework.generate_format_string(target)
                elif any('command_injection' in v for v in vuln_types):
                    print("  Command injection detected - try manual exploitation")
                    exploit = None
                else:
                    exploit = await framework.generate_bof_exploit(target, 72)

                if exploit:
                    framework.print_exploit(exploit)
                    filename = framework.save_exploit(exploit)
                    print(f"  Exploit saved: {filename}")

            # Step 4: Generate GDB script
            print("\n  [4/4] Generating GDB debug script...")
            gdb_script = gdb_helper.generate_buffer_overflow_script(target)
            gdb_file = f"/tmp/gdb_{os.path.basename(target)}.py"
            with open(gdb_file, "w") as f:
                f.write(gdb_script)
            print(f"  GDB script: {gdb_file}")

        else:
            # Network target workflow
            print(f"  Network Target Mode: {target}")
            print(f"  {'─'*50}")
            print("\n  Use 'pen-ai freewill {target}' for full autonomous mode")
            print(f"  Or 'pen-ai <target>' for interactive mode")

        print(f"\n{'='*60}")
        print(f"  📋 OSCP/CPENT WORKFLOW COMPLETE")
        print(f"{'='*60}")

    asyncio.run(run_oscp())


@app.command()
def bugbounty(
    target: str = typer.Argument(..., help="Target URL (https://example.com)"),
    domain: Optional[str] = typer.Option(None, help="Domain for subdomain enum"),
):
    """Bug bounty mode - full internet-facing web app scan.

    Tests for: CORS, open redirect, host header injection, API exposure,
    IDOR, subdomain takeover, cache poisoning.

    Examples:
        pen-ai bugbounty https://example.com
        pen-ai bugbounty https://example.com --domain example.com
    """
    from exploitation.bugbounty import BugBountyFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_bugbounty():
        executor = AutonomousExecutor(timeout=30)
        bb = BugBountyFramework(executor)
        findings = await bb.full_scan(target, domain)
        bb.print_findings(findings)

        # Save report
        import json, tempfile, os
        report_dir = os.path.join(tempfile.gettempdir(), "penai_bugbounty")
        os.makedirs(report_dir, exist_ok=True)
        report_file = os.path.join(report_dir, "findings.json")
        with open(report_file, "w") as f:
            json.dump([{"name": f.name, "severity": f.severity, "target": f.target, "evidence": f.evidence} for f in findings], f, indent=2)
        print(f"\n  Report saved: {report_file}")

    asyncio.run(run_bugbounty())


@app.command()
def advanced_binary(
    binary: str = typer.Argument(..., help="Path to binary"),
    technique: str = typer.Option("auto", help="Technique: auto, heap, fmtstr, aslr, rop, got"),
):
    """Advanced binary exploitation (OSCP/CPENT/OSCE).

    Heap exploitation, format string, ASLR bypass, ROP chains.

    Examples:
        pen-ai advanced-binary ./vuln --technique heap
        pen-ai advanced-binary ./vuln --technique fmtstr
        pen-ai advanced-binary ./vuln --technique rop
    """
    from exploitation.advanced_binary import AdvancedExploitFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_advanced():
        executor = AutonomousExecutor(timeout=60)
        fw = AdvancedExploitFramework(executor)

        print(f"\n🔧 Advanced Binary Exploitation: {binary}")
        print(f"  Technique: {technique}\n")

        if technique == "heap":
            exploit = await fw.generate_heap_exploit(binary, "auto")
        elif technique == "fmtstr":
            exploit = await fw.generate_format_string_write(binary, "0x404040", 0x41414141)
        elif technique == "aslr":
            exploit = await fw.generate_aslr_bypass(binary)
        elif technique == "rop":
            exploit = await fw.generate_dep_bypass(binary, "rop")
        elif technique == "got":
            exploit = await fw.generate_got_overwrite(binary)
        else:
            exploit = await fw.generate_heap_exploit(binary, "auto")

        fw.print_exploit(exploit)
        fn = fw.save_exploit(exploit)
        print(f"\n  Exploit saved: {fn}")

    asyncio.run(run_advanced())


@app.command()
def advanced_web(
    target: str = typer.Argument(..., help="Target URL"),
    technique: str = typer.Option("auto", help="Technique: deser, ssrf, xxe, race, jwt, ssti"),
):
    """Advanced web exploitation (OSWE/CPENT).

    Deserialization, SSRF, XXE, race conditions, JWT, SSTI.

    Examples:
        pen-ai advanced-web http://target.com --technique deser
        pen-ai advanced-web http://target.com --technique ssrf
        pen-ai advanced-web http://target.com --technique jwt
    """
    from exploitation.advanced_web import AdvancedWebExploitation
    from ai.autonomous_executor import AutonomousExecutor

    async def run_web():
        executor = AutonomousExecutor(timeout=60)
        web = AdvancedWebExploitation(executor)

        print(f"\n🌐 Advanced Web Exploitation: {target}")
        print(f"  Technique: {technique}\n")

        if technique == "deser":
            exploit = await web.generate_deserialization_exploit(target, "java")
        elif technique == "ssrf":
            exploit = await web.generate_ssrf_exploit(target)
        elif technique == "xxe":
            exploit = await web.generate_xxe_exploit(target)
        elif technique == "race":
            exploit = await web.generate_race_condition_exploit(target)
        elif technique == "jwt":
            exploit = await web.generate_jwt_attack(target)
        elif technique == "ssti":
            exploit = await web.generate_ssti_exploit(target)
        else:
            exploit = await web.generate_ssrf_exploit(target)

        web.print_exploit(exploit)
        fn = web.save_exploit(exploit)
        print(f"\n  Exploit saved: {fn}")

    asyncio.run(run_web())


@app.command()
def ad_attack(
    target: str = typer.Argument(..., help="Domain Controller IP"),
    chain: str = typer.Option("auto", help="Chain: adcs, golden, silver, shadow, dcshadow, delegation, llmnr"),
    username: str = typer.Option("", help="Username"),
    password: str = typer.Option("", help="Password"),
    domain: str = typer.Option("", help="Domain name"),
):
    """Advanced AD attacks (GPEN/CRTP/CRTE).

    AD CS abuse, Golden/Silver tickets, Shadow Credentials, DCShadow.

    Examples:
        pen-ai ad-attack 10.10.10.1 --chain adcs --username admin --password P@ss --domain corp.local
        pen-ai ad-attack 10.10.10.1 --chain golden --domain corp.local
        pen-ai ad-attack 10.10.10.1 --chain llmnr
    """
    from exploitation.advanced_ad import AdvancedADAttacks
    from ai.autonomous_executor import AutonomousExecutor

    async def run_ad():
        executor = AutonomousExecutor(timeout=60)
        ad = AdvancedADAttacks(executor)

        creds = {"username": username, "password": password, "domain": domain}

        print(f"\n🏢 Advanced AD Attack: {target}")
        print(f"  Chain: {chain}\n")

        if chain == "adcs":
            attack = await ad.generate_adcs_exploit(target, domain, username, password)
        elif chain == "golden":
            attack = await ad.generate_golden_ticket(domain, "S-1-5-21-0000000000-0000000000-0000000000", "aad3b435b51404eeaad3b435b51404ee:da769...", target)
        elif chain == "shadow":
            attack = await ad.generate_shadow_credentials(target, domain, username, password)
        elif chain == "dcshadow":
            attack = await ad.generate_dcshadow(target, domain, username, password)
        elif chain == "delegation":
            attack = await ad.generate_delegation_abuse(target, domain, username, password, "rbcd")
        elif chain == "llmnr":
            attack = await ad.generate_llmnr_poisoning(target)
        else:
            attack = await ad.generate_adcs_exploit(target, domain, username, password)

        ad.print_attack(attack)
        fn = ad.save_exploit(attack)
        print(f"\n  Attack script saved: {fn}")

    asyncio.run(run_ad())


@app.command()
def evade(
    lhost: str = typer.Option("10.10.14.5", help="Listener host"),
    lport: int = typer.Option(4444, help="Listener port"),
    technique: str = typer.Option("encoding", help="Technique: encoding, encryption, injection, dropper, c2, antiforensics, dns"),
):
    """Evasion and C2 framework (OSEP).

    AV bypass, process injection, C2 framework, anti-forensics.

    Examples:
        pen-ai evade --technique encoding
        pen-ai evade --technique c2 --lhost 10.10.14.5
        pen-ai evade --technique antiforensics
    """
    from exploitation.evasion import EvasionFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_evade():
        executor = AutonomousExecutor(timeout=60)
        ev = EvasionFramework(executor)

        print(f"\n🛡️  Evasion Framework")
        print(f"  Technique: {technique}\n")

        if technique == "c2":
            payload = await ev.generate_c2_framework(lhost, lport)
        elif technique == "antiforensics":
            payload = await ev.generate_anti_forensics()
        elif technique == "dns":
            payload = await ev.generate_dns_tunnel(lhost)
        else:
            payload = await ev.generate_av_bypass_payload(lhost=lhost, lport=lport, technique=technique)

        print(f"  Name: {payload.name}")
        print(f"  Description: {payload.description}")
        print(f"  AV Bypass: {payload.av_bypass}")
        print(f"  EDR Bypass: {payload.edr_bypass}")

        fn = ev.save_exploit(payload)
        print(f"\n  Script saved: {fn}")

    asyncio.run(run_evade())


@app.command()
def forensics(
    evidence_path: str = typer.Argument(..., help="Path to evidence (memory dump, pcap, disk image, log file)"),
    evidence_type: str = typer.Option("auto", help="Type: memory, pcap, disk, log"),
):
    """Forensics analysis (CHFI/CPENT).

    Memory forensics, network forensics, disk analysis, log analysis.

    Examples:
        pen-ai forensics /tmp/memory.dump --type memory
        pen-ai forensics capture.pcap --type pcap
        pen-ai forensics /var/log/auth.log --type log
    """
    from exploitation.forensics import ForensicsFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_forensics():
        executor = AutonomousExecutor(timeout=60)
        fs = ForensicsFramework(executor)

        print(f"\n🔬 Forensics Analysis: {evidence_path}")
        print(f"  Type: {evidence_type}\n")

        if evidence_type == "memory":
            results = await fs.analyze_memory(evidence_path)
        elif evidence_type == "pcap":
            results = await fs.analyze_pcap(evidence_path)
        elif evidence_type == "disk":
            results = await fs.analyze_disk(evidence_path)
        elif evidence_type == "log":
            results = await fs.analyze_logs(evidence_path)
        else:
            # Auto-detect
            if evidence_path.endswith('.pcap') or evidence_path.endswith('.pcapng'):
                results = await fs.analyze_pcap(evidence_path)
            elif evidence_path.endswith('.log') or '/var/log/' in evidence_path:
                results = await fs.analyze_logs(evidence_path)
            elif evidence_path.endswith('.raw') or evidence_path.endswith('.mem'):
                results = await fs.analyze_memory(evidence_path)
            else:
                results = await fs.analyze_disk(evidence_path)

        fs.print_results(results)

    asyncio.run(run_forensics())


@app.command()
def social_engineering(
    scenario: str = typer.Option("phishing", help="Scenario: phishing, usb, pretext"),
    service: str = typer.Option("o365", help="Phishing target: o365, google, generic"),
    lhost: str = typer.Option("10.10.14.5", help="Attacker host"),
):
    """Social engineering tools (CEH/CPENT).

    Phishing pages, USB drop payloads, pretexting scripts.

    Examples:
        pen-ai social-engineering --scenario phishing --service o365
        pen-ai social-engineering --scenario usb --lhost 10.10.14.5
        pen-ai social-engineering --scenario pretext
    """
    from exploitation.social_engineering import SocialEngineeringFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_se():
        executor = AutonomousExecutor(timeout=30)
        se = SocialEngineeringFramework(executor)

        print(f"\n🎭 Social Engineering")
        print(f"  Scenario: {scenario}\n")

        if scenario == "phishing":
            attack = await se.generate_phishing_page(service)
        elif scenario == "usb":
            attack = await se.generate_usb_payload(lhost)
        else:
            attack = await se.generate_pretexting("it_support")

        print(f"  Name: {attack.name}")
        print(f"  Description: {attack.description}")

        fn = se.save_attack(attack)
        print(f"\n  Script saved: {fn}")
        if scenario == "phishing":
            print(f"  Run: python3 {fn}")
            print(f"  Then visit: http://localhost:8080")

    asyncio.run(run_se())


@app.command()
def pivot(
    lhost: str = typer.Option("10.10.14.5", help="Attacker host"),
    lport: int = typer.Option(8080, help="Listener port"),
    technique: str = typer.Option("chisel", help="Technique: chisel, ligolo, ssh, double"),
    target: str = typer.Option("", help="Pivot target host"),
):
    """Advanced pivoting (OSCP/OSEP).

    Chisel, Ligolo, SSH tunnels, double pivoting.

    Examples:
        pen-ai pivot --technique chisel
        pen-ai pivot --technique ssh --target 10.10.10.1
        pen-ai pivot --technique double
    """
    from exploitation.advanced_pivoting import AdvancedPivotingFramework
    from ai.autonomous_executor import AutonomousExecutor

    async def run_pivot():
        executor = AutonomousExecutor(timeout=30)
        pv = AdvancedPivotingFramework(executor)

        print(f"\n🔀 Advanced Pivoting")
        print(f"  Technique: {technique}\n")

        if technique == "chisel":
            config = await pv.setup_chisel_pivot(lhost, lport)
        elif technique == "ligolo":
            config = await pv.setup_ligolo(lhost)
        elif technique == "ssh":
            config = await pv.setup_ssh_tunnel(lhost, lport, target, "root")
        elif technique == "double":
            config = await pv.setup_double_pivot(lhost, "10.10.10.1", "user", "10.10.11.1", "user")
        else:
            config = await pv.setup_chisel_pivot(lhost, lport)

        pv.print_config(config)
        fn = pv.save_config(config)
        print(f"\n  Config saved: {fn}")

    asyncio.run(run_pivot())


@app.command()
def report(
    target: str = typer.Option("", help="Target for report"),
    format: str = typer.Option("html", help="Format: html, json, oscp, cpent, gpen"),
    output: str = typer.Option("/tmp/penai_report", help="Output directory"),
):
    """Generate exam-specific reports.

    Professional pentest reports in multiple formats.

    Examples:
        pen-ai report --format html
        pen-ai report --format oscp --output /tmp/oscp_report
        pen-ai report --format cpent
    """
    import os, json
    from datetime import datetime

    os.makedirs(output, exist_ok=True)

    print(f"\n📄 Generating {format.upper()} report...")

    if format == "html":
        from reporting.html_report import HTMLReportGenerator
        report = HTMLReportGenerator(title="PEN-AI Penetration Test Report")
        report.target = target
        report.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = os.path.join(output, "report.html")
        report.save_html(fn)
        print(f"  HTML report: {fn}")

    elif format == "oscp":
        # OSCP-specific report template
        fn = os.path.join(output, "oscp_report.md")
        with open(fn, "w") as f:
            f.write("# PEN-AI OSCP Penetration Test Report\n\n")
            f.write("## 1. Executive Summary\n\n")
            f.write("[Write executive summary here]\n\n")
            f.write("## 2. High-Level Overview\n\n")
            f.write("### 2.1 Target Infrastructure\n\n")
            f.write("[Describe target infrastructure]\n\n")
            f.write("### 2.2 Methodology\n\n")
            f.write("[Describe methodology used]\n\n")
            f.write("## 3. Exploitation\n\n")
            f.write("### 3.1 Gaining Access\n\n")
            f.write("[Document exploitation steps with evidence]\n\n")
            f.write("### 3.2 Proof of Concept\n\n")
            f.write("[Include screenshots and command output]\n\n")
            f.write("## 4. Privilege Escalation\n\n")
            f.write("[Document privesc techniques]\n\n")
            f.write("## 5. Post-Exploitation\n\n")
            f.write("### 5.1 Active Directory\n\n")
            f.write("[Document AD attacks if applicable]\n\n")
            f.write("### 5.2 Data Exfiltration\n\n")
            f.write("[Document data exfiltration]\n\n")
            f.write("## 6. Recommendations\n\n")
            f.write("[Provide remediation recommendations]\n\n")
        print(f"  OSCP report template: {fn}")

    elif format == "cpent":
        fn = os.path.join(output, "cpent_report.md")
        with open(fn, "w") as f:
            f.write("# PEN-AI CPENT Penetration Test Report\n\n")
            f.write("## 1. Engagement Overview\n\n")
            f.write("[Write engagement overview]\n\n")
            f.write("## 2. Methodology\n\n")
            f.write("[Describe CPENT methodology]\n\n")
            f.write("## 3. Findings\n\n")
            f.write("### 3.1 Critical Findings\n\n")
            f.write("[Document critical findings]\n\n")
            f.write("### 3.2 High Findings\n\n")
            f.write("[Document high findings]\n\n")
            f.write("## 4. Exploitation Evidence\n\n")
            f.write("[Include exploitation evidence]\n\n")
            f.write("## 5. Remediation\n\n")
            f.write("[Provide remediation]\n\n")
        print(f"  CPENT report template: {fn}")

    elif format == "gpen":
        fn = os.path.join(output, "gpen_report.md")
        with open(fn, "w") as f:
            f.write("# PEN-AI GPEN Penetration Test Report\n\n")
            f.write("## 1. Executive Summary\n\n")
            f.write("[Executive summary]\n\n")
            f.write("## 2. Scope and Methodology\n\n")
            f.write("[Scope description]\n\n")
            f.write("## 3. Findings Summary\n\n")
            f.write("| Severity | Count |\n|----------|-------|\n")
            f.write("| Critical | 0 |\n| High | 0 |\n| Medium | 0 |\n| Low | 0 |\n\n")
            f.write("## 4. Detailed Findings\n\n")
            f.write("[Detailed findings with evidence]\n\n")
            f.write("## 5. Recommendations\n\n")
            f.write("[Remediation recommendations]\n\n")
        print(f"  GPEN report template: {fn}")

    else:
        fn = os.path.join(output, "report.json")
        with open(fn, "w") as f:
            json.dump({"target": target, "generated": datetime.now().isoformat()}, f, indent=2)
        print(f"  JSON report: {fn}")

    print(f"  Done! Edit the report with your findings.")


if __name__ == "__main__":
    app()
