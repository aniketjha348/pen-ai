"""Firewall / Filter Analysis - PenTest "Go Deeper" firewall identification & bypass modules.

Implements the advanced techniques needed when a target subnet is protected by a
filtering device (router ACL, firewall software, iptables, or a firewall appliance):

1. ``filter_detect``           - Identify WHICH filtering mechanism is in place by
                                  analyzing ICMP / port responses. A TCP probe coming
                                  back as ICMP Type 3 Code 13 (Communication
                                  Administratively Prohibited) is the classic signature
                                  of a Cisco router doing stateless ACL filtering.
2. ``filter_rule_map``         - Map the rules of the filter. "closed" responses prove
                                  the box is live and routed; "filtered" responses mean
                                  the filter is silently dropping. Compare to build a
                                  rule table and flag firewall misconfigurations (e.g.
                                  ICMP unreachable left exposed).
3. ``filter_sourceport_bypass``- Stateless filters with weak rules can be bypassed by
                                  spoofing the source port (e.g. source port 20 to mimic
                                  active-FTP data channel). Re-scan with a chosen source
                                  port and diff against baseline.

All parsing / classification logic is pure and unit-testable without nmap. The
command wrappers degrade gracefully when nmap is not installed (returning the
offline analysis if raw nmap output is supplied via ``raw``).
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


# ---------------------------------------------------------------------------
# ICMP interpretation tables
# ---------------------------------------------------------------------------
# ICMP Type 3 = Destination Unreachable. The code tells us a LOT about what is
# between us and the target.
ICMP_TYPE3_CODES = {
    1: ("Host Unreachable", "routing-level block (router has no route / drops)"),
    3: ("Port Unreachable", "host is ALIVE and routed; port is closed/silent -> confirms reachability"),
    10: ("Host Administratively Prohibited", "firewall/iptables denying the host deliberately"),
    13: ("Communication Administratively Prohibited", "Cisco router / stateless ACL filtering - the PenTest firewall signature"),
}

# The strongest indicator of a stateless filter (Cisco ACL).
ADMIN_PROHIBITED_CODES = {10, 13}


@dataclass
class PortProbe:
    """Result of probing a single port for filter analysis."""

    port: int
    state: str  # "open" | "closed" | "filtered" | "unfiltered"
    icmp_type3_code: Optional[int] = None


@dataclass
class FilterReport:
    """Structured conclusion about a filtering mechanism."""

    filter_present: bool
    mechanism: str  # "none" | "router_acl" | "firewall_software" | "iptables" | "firewall_device" | "unknown"
    confidence: float  # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    finding: Optional[str] = None
    next_steps: list[str] = field(default_factory=list)


def classify_port_states(lines: str) -> list[PortProbe]:
    """Parse raw nmap-style port lines into PortProbe records."""
    probes: list[PortProbe] = []
    pattern = re.compile(
        r"^\s*(\d{1,5})/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered)\b",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in pattern.finditer(lines):
        probes.append(
            PortProbe(
                port=int(m.group(1)),
                state=m.group(3).lower(),
            )
        )
    return probes


def detect_icmp_prohibited(lines: str) -> list[tuple[int, int]]:
    """Detect ICMP administratively-prohibited replies ("type N code M" or "type=N code=M").

    Returns a list of (type, code) tuples observed.
    """
    observed: list[tuple[int, int]] = []
    for m in re.finditer(
        r"type\s*[=:]?\s*?(\d+)[^\d]*(?:code)\s*[=:]?\s*?(\d+)",
        lines,
        re.IGNORECASE,
    ):
        observed.append((int(m.group(1)), int(m.group(2))))
    return observed

def classify_filter(probes: list[PortProbe], icmp_codes: Optional[list[tuple[int, int]]] = None) -> FilterReport:
    """Turn observed port/ICMP responses into a conclusion about the filter.

    This is the "interpret the data" step from the PenTest methodology.

    Decision tree:
    - ICMP type 3 code 13 (admin prohibited) -> Cisco router / stateless ACL.
    - ICMP type 3 code 10 (host admin prohibited) -> iptables/stateful deny.
    - ICMP type 3 code 3 (port unreachable) + filtered ports -> host is alive
      behind a filter that silently drops (firewall software / device / iptables).
    - Only open/closed, no filtered -> no filter blocking us (flat reachability).
    - Only filtered, no closed -> cannot confirm host; likely stateless drop.
    """
    icmp_codes = icmp_codes or []
    codes = {code for _, code in icmp_codes}
    states = {p.state for p in probes}

    has_filtered = "filtered" in states or "open|filtered" in states
    has_closed = "closed" in states
    has_open = "open" in states

    report = FilterReport(filter_present=False, mechanism="none", confidence=0.0)

    def finalize(mechanism, confidence, evidence, finding, steps):
        report.mechanism = mechanism
        report.confidence = confidence
        report.evidence = evidence
        report.filter_present = mechanism != "none"
        report.finding = finding or None
        report.next_steps = steps or []
        return report

    # 1) Strongest signal: ICMP admin-prohibited (13 => Cisco/stateless ACL).
    if 13 in codes:
        return finalize(
            "router_acl",
            0.95,
            ["ICMP Type 3 Code 13 (Communication Administratively Prohibited) observed - classic Cisco/stateless ACL signature"],
            "Weak stateless filter present. ICMP unreachable messages are exposed; firewall admin should block ICMP unreachable to avoid leaking rule information.",
            [
                "Map the filter rules (filter_rule_map).",
                "Probe source-port spoofing to find weak permissive rules (filter_sourceport_bypass), e.g. source port 20 for FTP.",
                "Try fragmentation (-f) and -Pn to map the attack surface behind the ACL.",
            ],
        )

    # 2) Host admin-prohibited -> iptables/stateful host deny.
    if 10 in codes:
        return finalize(
            "iptables",
            0.85,
            ["ICMP Type 3 Code 10 (Host Administratively Prohibited) observed"],
            "Host-level deny (iptables/firewall-software) blocking probes.",
            ["Try full -Pn TCP SYN scanning; STATEful rules may still permit ESTABLISHED traffic.",
             "Consider pivoting through an already-owned host in an adjacent segment."],
        )

    # 3) Port-unreachable confirms host live; filtered ports imply silent-drop filter.
    if has_filtered and has_closed:
        return finalize(
            "firewall_software",
            0.8,
            ["Host responds with closed (routed, alive) while other ports are filtered (silently dropped): shows a filter in front."],
            "Filter detected between us and the host. Closed responses confirm reachability; filtered responses confirm silent-drop filtering.",
            [
                "Map which ports pass the filter (closed/open) vs which are dropped (filtered) via filter_rule_map.",
                "Test source-port and fragmentation bypasses for weak stateless rules.",
            ],
        )

    # 4) Silently dropped across the board -> stateless device/iptables DROP.
    if has_filtered and not has_closed:
        return finalize(
            "firewall_device",
            0.6,
            ["All probed ports filtered with no closed response: filter drops without replying."],
            "Silent-drop stateless filtering (no ICMP leak). Cannot yet confirm host is alive behind it.",
            [
                "Use very slow controlled scans (-T1, --max-retries 1, --scan-delay) with -Pn -sS.",
                "Attempt source-port spoof to match an allowed service rule.",
                "Look for a pivot path through a neighboring reachable host.",
            ],
        )

    # 5) No filtering observed.
    if not has_filtered and (has_open or has_closed):
        return finalize(
            "none",
            0.7,
            ["Ports respond open/closed with no filtered state and no ICMP prohibited codes."],
            None,
            ["Subnet is directly routable - enumerate normally."],
        )

    # 6) Unknown / no data.
    return finalize(
        "unknown",
        0.1,
        ["Insufficient response data to classify the filtering mechanism."],
        "Inconclusive. Slow the scan, add -Pn, and probe ICMP codes directly.",
        ["Re-run detection with -Pn -sS --max-retries 1 -T2 and -PE -PP ICMP probes."],
    )


def build_controlled_scan(target: str, ports: str, source_port: Optional[int] = None) -> str:
    """Build a slow, controlled nmap command tuned for filtered enterprise networks.

    - ``-Pn``: skip ICMP ping (ICMP filtering is common).
    - ``-sS``: TCP SYN half-open (less logging).
    - ``-T1``: paranoid pacing; over-aggressive defaults degrade responses.
    - ``--max-retries 1 --scan-delay 200ms --max-scan-delay 2s``: rate control.
    """
    cmd = "nmap -Pn -sS -T1 --max-retries 1 --scan-delay 200ms --max-scan-delay 2s"
    if source_port:
        cmd += f" -g {source_port}"
    cmd += f" -p {ports} {target}"
    return cmd


async def _run(cmd: str, timeout: int = 300) -> tuple[str, str]:
    """Run a command; returns (stdout, stderr)."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        return "", f"Command timed out: {cmd}"
    except Exception as e:  # noqa: BLE001
        return "", f"Command failed: {e}"


class FirewallAnalyzer:
    """High-level firewall/filter analysis engine (register_tool backends)."""

    async def detect_filter(self, target: str, ports: str = "1-100", raw: Optional[str] = None) -> dict:
        """Identify whether a filtering mechanism protects the target."""
        if raw:
            probes = classify_port_states(raw)
            icmp = detect_icmp_prohibited(raw)
            report = classify_filter(probes, icmp)
        else:
            cmd = build_controlled_scan(target, ports)
            out, err = await _run(cmd)
            probes = classify_port_states(out)
            icmp = detect_icmp_prohibited(out)
            report = classify_filter(probes, icmp)
            report.evidence.insert(0, f"Command: {cmd}")
            if err.strip():
                report.evidence.append(f"stderr: {err.strip()[:300]}")

        return {
            "target": target,
            "filter_present": report.filter_present,
            "mechanism": report.mechanism,
            "confidence": round(report.confidence, 2),
            "finding": report.finding,
            "evidence": report.evidence,
            "next_steps": report.next_steps,
            "port_states": [p.__dict__ for p in probes],
            "icmp_codes": icmp,
        }


    async def map_filter_rules(self, target: str, ports: str = "1-1000", raw: Optional[str] = None) -> dict:
        """Map which ports pass the filter (open/closed) vs are dropped (filtered)."""
        if raw:
            probes = classify_port_states(raw)
            icmp = detect_icmp_prohibited(raw)
        else:
            cmd = build_controlled_scan(target, ports)
            out, err = await _run(cmd)
            probes = classify_port_states(out)
            icmp = detect_icmp_prohibited(out)
            _ = err  # reserved for future diagnostics

        allowed = [p.port for p in probes if p.state == "open"]
        routed = [p.port for p in probes if p.state == "closed"]  # filter passes, but nothing listening
        blocked = [p.port for p in probes if p.state in ("filtered", "open|filtered")]

        report = classify_filter(probes, icmp)

        return {
            "target": target,
            "ports_allowed_open": allowed,
            "ports_routed_closed": routed,
            "ports_filtered_blocked": blocked,
            "filter": {"present": report.filter_present, "mechanism": report.mechanism, "confidence": report.confidence},
            "finding": report.finding,
            "next_steps": report.next_steps,
            "icmp_codes": icmp,
            "interpretation": (
                f"{len(allowed)} open, {len(routed)} closed (routed/live), {len(blocked)} filtered (dropped by filter). "
                f"{len(routed) + len(allowed)} ports pass the filter versus {len(blocked)} dropped."
            ),
        }

    async def source_port_bypass(self, target: str, ports: str = "1-1000", source_port: int = 20,
                                 baseline_raw: Optional[str] = None, bypass_raw: Optional[str] = None) -> dict:
        """Bypass a weak stateless-filter rule by spoofing the source port.

        Stateless ACLs often permit a service based on source port (e.g. FTP data
        channel uses source port 20). Sending probes from that source port can
        bypass the filter. Diff baseline vs bypass to reveal newly-visible ports.
        """
        if baseline_raw is None:
            base_cmd = build_controlled_scan(target, ports)
            base_out, _ = await _run(base_cmd)
        else:
            base_out = baseline_raw

        if bypass_raw is None:
            bypass_cmd = build_controlled_scan(target, ports, source_port=source_port)
            bypass_out, _ = await _run(bypass_cmd)
        else:
            bypass_out = bypass_raw

        base_probes = classify_port_states(base_out)
        bypass_probes = classify_port_states(bypass_out)

        base_visible = {p.port for p in base_probes if p.state in ("open", "closed")}
        bypass_visible = {p.port for p in bypass_probes if p.state in ("open", "closed")}
        newly_visible = sorted(bypass_visible - base_visible)
        base_open = {p.port for p in base_probes if p.state == "open"}
        newly_open = sorted(
            p.port for p in bypass_probes if p.state == "open" and p.port not in base_open
        )

        return {
            "target": target,
            "source_port": source_port,
            "baseline_visible": sorted(base_visible),
            "bypass_visible": sorted(bypass_visible),
            "newly_visible_via_sourceport": newly_visible,
            "newly_open_via_sourceport": newly_open,
            "bypass_successful": bool(newly_visible),
            "note": (
                "Source-port spoof exposed ports visible only from the crafted source port - "
                "confirmed weak/incorrect stateless filter rule." if newly_visible
                else "No additional ports exposed from this source port. Try 20 (FTP), 53 (DNS), 67/68 (DHCP), or -S random."
            ),
        }


# ---------------------------------------------------------------------------
# register_tool backends (added to the global tool registry)
# ---------------------------------------------------------------------------
@register_tool(
    name="filter_detect",
    description="Identify the filtering mechanism protecting a target subnet (router ACL, firewall software, iptables, firewall device) via ICMP & port response analysis. Detects Cisco stateless ACL via ICMP Type 3 Code 13.",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP or subnet"),
        ToolParameter(name="ports", type="str", description="Port range to probe", required=False, default="1-100"),
        ToolParameter(name="raw", type="str", description="Optional raw nmap output for offline analysis", required=False, default=None),
    ],
)
async def filter_detect(target: str, ports: str = "1-100", raw: Optional[str] = None) -> dict:
    """Identify the filtering mechanism in front of a target."""
    return await FirewallAnalyzer().detect_filter(target, ports, raw)


@register_tool(
    name="filter_rule_map",
    description="Map the rules of a stateless firewall/filter: which ports pass (open/closed, proving host live) vs which are silently dropped (filtered). Flags ICMP unreachable misconfigurations.",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="ports", type="str", description="Port range to map", required=False, default="1-1000"),
        ToolParameter(name="raw", type="str", description="Optional raw nmap output for offline analysis", required=False, default=None),
    ],
)
async def filter_rule_map(target: str, ports: str = "1-1000", raw: Optional[str] = None) -> dict:
    """Map filter rules for a target."""
    return await FirewallAnalyzer().map_filter_rules(target, ports, raw)


@register_tool(
    name="filter_sourceport_bypass",
    description="Bypass a weak stateless-filter rule by spoofing the source port (e.g. -g 20 to mimic active-FTP data channel). Diffs baseline vs bypass to expose newly-visible ports. PenTest weak-rule technique.",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="ports", type="str", description="Port range to test", required=False, default="1-1000"),
        ToolParameter(name="source_port", type="int", description="Source port to spoof (20=FTP data, 53=DNS, 67/68=DHCP)", required=False, default=20),
        ToolParameter(name="baseline_raw", type="str", description="Optional raw nmap output of baseline scan (offline)", required=False, default=None),
        ToolParameter(name="bypass_raw", type="str", description="Optional raw nmap output of source-port scan (offline)", required=False, default=None),
    ],
)
async def filter_sourceport_bypass(target: str, ports: str = "1-1000", source_port: int = 20,
                                   baseline_raw: Optional[str] = None, bypass_raw: Optional[str] = None) -> dict:
    """Test a source-port based stateless filter bypass."""
    return await FirewallAnalyzer().source_port_bypass(target, ports, source_port, baseline_raw, bypass_raw)

