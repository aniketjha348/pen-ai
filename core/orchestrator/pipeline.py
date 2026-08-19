"""DeepEngage Pipeline - deterministic zero-to-advanced engagement orchestrator.

Chains the full enterprise internal-network lifecycle WITHOUT requiring an LLM:

    RECON -> FILTER_ANALYZE -> ENUMERATE -> EXPLOIT -> POST_EXPLOIT -> PIVOT -> REPORT

- Each phase is a step function that updates the shared EngagementState.
- Dependencies (scan / filter / exploit runners) are injectable, so the whole
  pipeline is fully testable offline and degrades gracefully on hosts without
  the Kali toolchain.
- Produces an executive + technical report (Markdown + JSON) on disk.

The LLM is optional: when provided, its decisions are appended to the narrative;
when absent, deterministic heuristics drive every phase.
"""

import asyncio
import inspect
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from core.state.engagement_state import (
    AccessLevel,
    Credential,
    EngagementState,
    Host,
    Objective,
    Service,
    Vulnerability,
)
from ai.tool_registry import ToolCategory, register_tool, ToolParameter
from reporting.generator import Finding, ReportGenerator


class Phase(str, Enum):
    """Engagement phases in execution order."""

    RECON = "recon"
    FILTER_ANALYZE = "filter_analyze"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PIVOT = "pivot"
    REPORT = "report"


# Default phase order - but phases are skipped dynamically based on state.
DEFAULT_PHASES = [
    Phase.RECON,
    Phase.FILTER_ANALYZE,
    Phase.ENUMERATE,
    Phase.EXPLOIT,
    Phase.POST_EXPLOIT,
    Phase.PIVOT,
    Phase.REPORT,
]


# Conditions for skipping a phase - determined by state, not hardcoded rules.
def _should_skip_phase(phase: Phase, state: 'EngagementState') -> tuple[bool, str]:
    """Dynamically determine if a phase should be skipped based on current state.

    Returns (should_skip, reason). No fixed rules - just state-based logic.
    """
    if phase == Phase.RECON:
        # Skip if hosts are already discovered
        if state.hosts_discovered > 0:
            return True, f"Hosts already discovered ({state.hosts_discovered})"
    elif phase == Phase.FILTER_ANALYZE:
        # Skip if no hosts to analyze filters for
        if state.hosts_discovered == 0:
            return True, "No hosts to analyze filters for"
    elif phase == Phase.ENUMERATE:
        # Skip if no services to enumerate
        if state.services_discovered == 0:
            return True, "No services to enumerate"
    elif phase == Phase.EXPLOIT:
        # Skip if no services or already have system-level access
        if state.services_discovered == 0:
            return True, "No services to exploit"
        if state.current_access.value in ("system", "domain_admin"):
            return True, f"Already at {state.current_access.value} access"
    elif phase == Phase.POST_EXPLOIT:
        # Skip if no access gained
        if state.current_access.value == "none":
            return True, "No access gained yet"
    elif phase == Phase.PIVOT:
        # Skip if no access or max pivot depth reached
        if state.current_access.value == "none":
            return True, "No access to pivot from"
        if state.pivot_depth >= state.max_pivot_depth:
            return True, f"Max pivot depth ({state.max_pivot_depth}) reached"
    return False, ""


@dataclass
class PhaseResult:
    """Outcome of a single pipeline phase."""

    phase: Phase
    ok: bool
    summary: str
    findings: list[Finding] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


# Injectable runner signatures
ScanFn = Callable[[str], Awaitable[dict]]
FilterFn = Callable[[str], Awaitable[dict]]
ExploitFn = Callable[[str, int, str], Awaitable[list[dict]]]


async def _maybe_await(value: Any) -> Any:
    """Await a coroutine if the runner returned one; otherwise pass through.

    Lets callers inject either sync or async runners (both are supported).
    """
    if inspect.isawaitable(value):
        return await value
    return value
class DeepEngagePipeline:
    """Zero-to-advanced enterprise internal-network engagement pipeline."""

    def __init__(
        self,
        state: Optional[EngagementState] = None,
        target: str = "",
        name: str = "Enterprise Engagement",
        scan_fn: Optional[ScanFn] = None,
        filter_fn: Optional[FilterFn] = None,
        exploit_fn: Optional[ExploitFn] = None,
        output_dir: str = "reports",
        llm: Optional[Any] = None,
    ):
        self.state = state or EngagementState(name=name)
        self.target = target
        self.scan_fn = scan_fn or self._default_scan
        self.filter_fn = filter_fn or self._default_filter
        self.exploit_fn = exploit_fn or self._default_exploit
        self.output_dir = Path(output_dir)
        self.llm = llm
        self.report = ReportGenerator(self.state)
        self._phase_results: list[PhaseResult] = []

    # -- Public API ---------------------------------------------------------

    async def run(self, target: Optional[str] = None, phases: Optional[list[Phase]] = None) -> dict:
        """Execute the full engagement lifecycle and return the report payload."""
        if target:
            self.target = target
        if not self.target:
            raise ValueError("DeepEngagePipeline requires a target")

        self.state.current_network = self.target
        phase_order = phases or DEFAULT_PHASES

        for phase in phase_order:
            result = await self._dispatch(phase)
            self._phase_results.append(result)
            for finding in result.findings:
                self.report.add_finding(finding)
            self.report.add_narrative_step(f"[{phase.value.upper()}] {result.summary}")

        # Final report phase always generates artifacts.
        report_payload = self.phase_report()
        return report_payload

    async def _dispatch(self, phase: Phase) -> PhaseResult:
        if phase == Phase.RECON:
            return await self.phase_recon()
        if phase == Phase.FILTER_ANALYZE:
            return await self.phase_filter_analyze()
        if phase == Phase.ENUMERATE:
            return await self.phase_enumerate()
        if phase == Phase.EXPLOIT:
            return await self.phase_exploit()
        if phase == Phase.POST_EXPLOIT:
            return await self.phase_post_exploit()
        if phase == Phase.PIVOT:
            return await self.phase_pivot()
        return PhaseResult(phase=phase, ok=True, summary="Report generated")

    # -- Default runners (degrade gracefully without the Kali toolchain) -----

    async def _default_scan(self, target: str) -> dict:
        """Real host+service discovery via recon.network; returns raw JSON."""
        from recon.network import NetworkRecon

        recon = NetworkRecon()
        try:
            host_res = await recon.host_discovery(target)
            hosts = [h.ip for h in host_res.hosts]
            services = []
            if hosts:
                for host_ip in hosts[:8]:
                    try:
                        svc = await recon.service_enumeration(host_ip)
                        services.extend([s.__dict__ for s in svc.services])
                    except Exception:  # noqa: BLE001
                        continue
            return {"hosts": hosts, "services": services}
        except Exception as e:  # noqa: BLE001
            return {"hosts": [], "services": [], "error": str(e)}

    async def _default_filter(self, target: str) -> dict:
        """Real filter analysis via recon.firewall_analysis."""
        from recon.firewall_analysis import FirewallAnalyzer

        try:
            return await FirewallAnalyzer().detect_filter(target)
        except Exception as e:  # noqa: BLE001
            return {"filter_present": False, "mechanism": "unknown", "error": str(e)}

    async def _default_exploit(self, target: str, port: int, service: str) -> list[dict]:
        """Real exploitation attempts via the ExploitationEngine."""
        from exploitation.engine import ExploitationEngine

        try:
            engine = ExploitationEngine()
            attempts = await engine.auto_exploit_service(target, port, service)
            return [
                {
                    "technique": a.technique,
                    "success": a.status.value == "success",
                    "access_gained": a.access_gained.value if a.access_gained else None,
                    "error": a.error,
                }
                for a in attempts
            ]
        except Exception as e:  # noqa: BLE001
            return [{"technique": "engine_error", "success": False, "error": str(e)}]

    # -- Phase implementations -------------------------------------------------

    async def phase_recon(self) -> PhaseResult:
        """Host discovery + basic port scan on the target scope."""
        scan = await _maybe_await(self.scan_fn(self.target))
        hosts = scan.get("hosts", [])
        services = scan.get("services", [])

        findings: list[Finding] = []
        for ip in hosts:
            if self.state.get_host_by_ip(ip) is None:
                self.state.add_host(Host(ip=ip, is_alive=True))
                self.state.mark_host_visited(ip)

        for svc in services:
            host_ip = svc.get("host_id") or (hosts[0] if hosts else self.target)
            host = self.state.get_host_by_ip(host_ip) or (
                None if not hosts else self.state.get_host_by_ip(hosts[0])
            )
            self.state.add_service(
                Service(
                    host_id=host.id if host else self.state.id,
                    port=svc.get("port", 0),
                    service_name=svc.get("service") or svc.get("service_name"),
                    version=svc.get("version"),
                    state="open",
                )
            )

        if not hosts and scan.get("error"):
            self.state.record_failure("recon", scan["error"])

        return PhaseResult(
            phase=Phase.RECON,
            ok=bool(hosts) or bool(services),
            summary=f"Recon: {len(hosts)} hosts, {len(services)} services on {self.target}",
            findings=findings,
            detail={"hosts": hosts, "services": len(services)},
        )

    async def phase_filter_analyze(self) -> PhaseResult:
        """Identify a filtering mechanism between us and the target."""
        # Only meaningful when scanning a host directly.
        target = self.target
        fw = await _maybe_await(self.filter_fn(target))
        findings: list[Finding] = []

        if fw.get("filter_present"):
            mechanism = fw.get("mechanism", "unknown")
            severity = "high" if mechanism in ("router_acl", "firewall_device") else "medium"
            findings.append(
                Finding(
                    id="FW-001",
                    title=f"Network filter detected: {mechanism}",
                    severity=severity,
                    description=(
                        fw.get("finding")
                        or f"ICMP/port responses indicate a filtering device in front of {target}."
                    ),
                    evidence=fw.get("evidence", []),
                    remediation=(
                        "Block ICMP unreachable messages at the firewall/ACL to stop rule leakage; "
                        "tighten stateless ACL rules (source-port allowlists are bypassable)."
                    ),
                    target=target,
                )
            )

        return PhaseResult(
            phase=Phase.FILTER_ANALYZE,
            ok=True,
            summary=(
                f"Filter analysis: {fw.get('mechanism', 'unknown')} "
                f"(present={fw.get('filter_present', False)})"
            ),
            findings=findings,
            detail=fw,
        )

    async def phase_enumerate(self) -> PhaseResult:
        """Tag open services with informational findings.

        No hardcoded service risk ratings - just records what exists
        and lets the LLM/attacker decide what's important.
        """
        findings: list[Finding] = []

        for svc in self.state.services:
            name = (svc.service_name or "").lower()
            findings.append(
                Finding(
                    id=f"SRV-{svc.port}",
                    title=f"Service {name}:{svc.port} discovered",
                    severity="info",
                    description=(
                        f"Service '{svc.service_name}' on port {svc.port} "
                        f"(version: {svc.version or 'unknown'}). "
                        f"Assess attack surface based on service type."
                    ),
                    evidence=[f"{svc.service_name} version {svc.version or 'n/a'}"],
                    target=self.target,
                )
            )

        return PhaseResult(
            phase=Phase.ENUMERATE,
            ok=True,
            summary=f"Enumerated {len(self.state.services)} services",
            findings=findings,
        )

    async def phase_exploit(self) -> PhaseResult:
        """Attempt exploitation of every open service."""
        attempts_total = 0
        successes = 0
        for svc in self.state.services:
            service_name = svc.service_name or "unknown"
            attempts = await _maybe_await(self.exploit_fn(self.target, svc.port, service_name))
            attempts_total += len(attempts)
            for attempt in attempts:
                if attempt.get("success"):
                    successes += 1
                    self.state.add_vulnerability(
                        Vulnerability(
                            host_id=svc.host_id,
                            service_id=svc.id,
                            title=f"Exploited via {attempt.get('technique', service_name)}",
                            description=f"Access gained on {self.target}:{svc.port}",
                            severity="critical",
                            exploited=True,
                            evidence=attempt.get("error") or f"{attempt.get('technique')} succeeded",
                        )
                    )
                    access = attempt.get("access_gained") or "user"
                    try:
                        self.state.current_access = AccessLevel(access)
                    except ValueError:
                        self.state.current_access = AccessLevel.USER

        return PhaseResult(
            phase=Phase.EXPLOIT,
            ok=True,
            summary=f"Exploitation: {successes}/{attempts_total} attempts succeeded",
            detail={"attempts": attempts_total, "successes": successes},
        )

    async def phase_post_exploit(self) -> PhaseResult:
        """Harvest credentials and promote access based on successes."""
        findings: list[Finding] = []
        # If we hold access, register a finding documenting the beachhead.
        if self.state.current_access != AccessLevel.NONE:
            findings.append(
                Finding(
                    id="ACC-001",
                    title="Access established on target",
                    severity="critical",
                    description=(
                        f"A foothold was established on {self.target} with "
                        f"access level {self.state.current_access.value}."
                    ),
                    evidence=[self.target],
                    remediation="Apply security hardening & segmentation per vendor guidance.",
                    target=self.target,
                )
            )
        return PhaseResult(
            phase=Phase.POST_EXPLOIT,
            ok=True,
            summary=f"Post-exploitation: access level {self.state.current_access.value}",
            findings=findings,
        )

    async def phase_pivot(self) -> PhaseResult:
        """Record a pivot point when we hold access on the target."""
        if self.state.current_access in (AccessLevel.USER, AccessLevel.PRIVILEGED,
                                         AccessLevel.ADMIN, AccessLevel.SYSTEM, AccessLevel.DOMAIN_ADMIN):
            from core.state.engagement_state import PivotPoint

            self.state.add_pivot(
                PivotPoint(
                    source_host=self.target,
                    destination_network="<adjacent-segment>",
                    method="socks_proxy",
                    status="pending",
                )
            )
        return PhaseResult(
            phase=Phase.PIVOT,
            ok=True,
            summary=f"Pivot planning: {self.state.pivot_depth} pivot(s) recorded",
        )

    def phase_report(self) -> dict:
        """Render the report artifacts (Markdown + JSON) and return payload."""
        if not self._phase_results:
            self.report.add_narrative_step("[REPORT] Empty engagement")

        payload = {
            "engagement": {"name": self.state.name, "target": self.target},
            "summary": {
                "hosts": self.state.hosts_discovered,
                "services": self.state.services_discovered,
                "vulnerabilities": self.state.vulnerabilities_found,
                "credentials": self.state.credentials_found,
                "access": self.state.current_access.value,
                "pivots": self.state.pivot_depth,
                "phases": [p.phase.value for p in self._phase_results],
            },
            "phases": [
                {
                    "phase": p.phase.value,
                    "ok": p.ok,
                    "summary": p.summary,
                    "detail": p.detail,
                }
                for p in self._phase_results
            ],
            "findings": [f.__dict__ for f in self.report._findings],
            "narrative": self.report._attack_narrative,
        }

        # Persist artifacts.
        try:
            out = self.output_dir / self.state.name.replace(" ", "_")
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.md").write_text(self._render_markdown(), encoding="utf-8")
            (out / "report.json").write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )
            payload["artifacts"] = {
                "markdown": str(out / "report.md"),
                "json": str(out / "report.json"),
            }
        except OSError as e:  # noqa: BLE001
            payload["artifacts"] = {"error": str(e)}

        return payload

    def _render_markdown(self) -> str:
        """Render the full report as Markdown."""
        md = [f"# Penetration Test Report", "", f"**{self.state.name}**", ""]
        md.append("## Executive Summary")
        md.append(f"- Hosts discovered: {self.state.hosts_discovered}")
        md.append(f"- Services enumerated: {self.state.services_discovered}")
        md.append(f"- Vulnerabilities found: {self.state.vulnerabilities_found}")
        md.append(f"- Maximum access achieved: {self.state.current_access.value}")
        md.append("")
        md.append("## Attack Timeline")
        for i, step in enumerate(self.report._attack_narrative, 1):
            md.append(f"{i}. {step}")
        md.append("")
        md.append("## Findings")
        for finding in self.report._findings:
            md.append(f"### {finding.id} - {finding.title} ({finding.severity.upper()})")
            md.append(finding.description)
            for ev in finding.evidence:
                md.append(f"- Evidence: {ev}")
            if finding.remediation:
                md.append(f"**Remediation:** {finding.remediation}")
            md.append("")
        md.append("---")
        md.append("*Generated by PEN-AI DeepEngage pipeline*")
        return "\n".join(md)


# ---------------------------------------------------------------------------
# register_tool backend: one-shot DeepEngage pipeline for the agent/LLM
# ---------------------------------------------------------------------------
@register_tool(
    name="deep_engage",
    description="Run the full zero-to-advanced enterprise engagement pipeline against a target: recon -> filter analysis -> enumerate -> exploit -> post-exploit -> pivot -> report. Produces Markdown + JSON report artifacts.",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP or CIDR"),
        ToolParameter(name="name", type="str", description="Engagement name", required=False, default="Enterprise Engagement"),
    ],
)
async def deep_engage(target: str, name: str = "Enterprise Engagement") -> dict:
    """Execute the full DeepEngage pipeline for a target."""
    pipeline = DeepEngagePipeline(target=target, name=name)
    return await pipeline.run()

