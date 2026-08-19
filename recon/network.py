"""Network Reconnaissance Engine - Host discovery, port scanning, service enumeration."""

import asyncio
import subprocess
import re
from typing import Any, Optional
from dataclasses import dataclass

from ai.tool_registry import ToolCategory, register_tool, ToolParameter
from core.state.engagement_state import Host, Service, NetworkSegment


@dataclass
class ScanResult:
    """Result of a network scan."""

    target: str
    hosts: list[Host]
    services: list[Service]
    networks: list[NetworkSegment]
    raw_output: str
    errors: list[str]


class NetworkRecon:
    """Network reconnaissance engine with async parallel support."""

    def __init__(self):
        self._scan_history: list[ScanResult] = []

    async def host_discovery(self, target: str, timeout: int = 5) -> ScanResult:
        """Discover live hosts in a network."""
        cmd = f"nmap -sn -T4 --host-timeout {timeout}s {target}"
        raw_output, errors = await self._run_command(cmd)

        hosts = self._parse_host_discovery(raw_output)

        result = ScanResult(
            target=target,
            hosts=hosts,
            services=[],
            networks=[],
            raw_output=raw_output,
            errors=errors,
        )
        self._scan_history.append(result)
        return result

    async def port_scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "quick",
    ) -> ScanResult:
        """Scan ports on a target."""
        intensity_map = {
            "quick": "-T4 -F",
            "full": "-T4 -p-",
            "stealth": "-sS -T2",
            "aggressive": "-T5 -A",
        }
        flags = intensity_map.get(scan_type, "-T4")

        cmd = f"nmap {flags} -p {ports} {target}"
        raw_output, errors = await self._run_command(cmd)

        hosts, services = self._parse_port_scan(raw_output, target)

        result = ScanResult(
            target=target,
            hosts=hosts,
            services=services,
            networks=[],
            raw_output=raw_output,
            errors=errors,
        )
        self._scan_history.append(result)
        return result

    async def service_enumeration(
        self,
        target: str,
        ports: str = "1-1000",
    ) -> ScanResult:
        """Enumerate services on open ports."""
        cmd = f"nmap -sV -sC -p {ports} {target}"
        raw_output, errors = await self._run_command(cmd)

        hosts, services = self._parse_service_scan(raw_output, target)

        result = ScanResult(
            target=target,
            hosts=hosts,
            services=services,
            networks=[],
            raw_output=raw_output,
            errors=errors,
        )
        self._scan_history.append(result)
        return result

    async def os_detection(self, target: str) -> ScanResult:
        """Detect operating system."""
        cmd = f"nmap -O -sV {target}"
        raw_output, errors = await self._run_command(cmd)

        hosts, services = self._parse_os_detection(raw_output, target)

        result = ScanResult(
            target=target,
            hosts=hosts,
            services=services,
            networks=[],
            raw_output=raw_output,
            errors=errors,
        )
        self._scan_history.append(result)
        return result

    async def network_mapping(self, target: str) -> ScanResult:
        """Map network topology."""
        cmd = f"nmap -sn -PE -PP -PM {target}"
        raw_output, errors = await self._run_command(cmd)

        hosts = self._parse_host_discovery(raw_output)
        networks = [NetworkSegment(name="primary", cidr=target)]

        result = ScanResult(
            target=target,
            hosts=hosts,
            services=[],
            networks=networks,
            raw_output=raw_output,
            errors=errors,
        )
        self._scan_history.append(result)
        return result

    async def parallel_host_discovery(
        self,
        targets: list[str],
        max_concurrent: int = 10,
    ) -> list[ScanResult]:
        """Discover hosts in parallel across multiple targets."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_scan(target: str) -> ScanResult:
            async with semaphore:
                return await self.host_discovery(target)

        tasks = [limited_scan(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def parallel_port_scan(
        self,
        targets: list[str],
        ports: str = "1-1000",
        scan_type: str = "quick",
        max_concurrent: int = 10,
    ) -> list[ScanResult]:
        """Scan ports in parallel across multiple targets."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_scan(target: str) -> ScanResult:
            async with semaphore:
                return await self.port_scan(target, ports, scan_type)

        tasks = [limited_scan(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def parallel_service_enum(
        self,
        targets: list[str],
        ports: str = "1-1000",
        max_concurrent: int = 10,
    ) -> list[ScanResult]:
        """Enumerate services in parallel."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_scan(target: str) -> ScanResult:
            async with semaphore:
                return await self.service_enumeration(target, ports)

        tasks = [limited_scan(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def full_recon(self, target: str) -> dict:
        """Execute full reconnaissance with parallel scanning."""
        results = {}

        # Phase 1: Host discovery
        host_result = await self.host_discovery(target)
        results["hosts"] = [h.ip for h in host_result.hosts]

        if not host_result.hosts:
            return results

        # Phase 2: Parallel port scans on all hosts
        host_ips = [h.ip for h in host_result.hosts]
        port_results = await self.parallel_port_scan(host_ips)

        # Collect all open ports
        all_services = []
        for pr in port_results:
            if hasattr(pr, 'services'):
                all_services.extend(pr.services)
        results["services"] = len(all_services)

        # Phase 3: Parallel service enumeration on discovered ports
        if host_ips:
            service_results = await self.parallel_service_enum(host_ips[:5])  # Limit to 5 hosts
            results["service_enum"] = len(service_results)

        return results

    async def _run_command(self, cmd: str) -> tuple[str, list[str]]:
        """Run a shell command and capture output."""
        errors = []
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300,  # 5 minute timeout
            )
            raw_output = stdout.decode("utf-8", errors="replace")
            if stderr:
                err_text = stderr.decode("utf-8", errors="replace")
                if err_text.strip():
                    errors.append(err_text)
            return raw_output, errors
        except asyncio.TimeoutError:
            errors.append(f"Command timed out: {cmd}")
            return "", errors
        except Exception as e:
            errors.append(f"Command failed: {str(e)}")
            return "", errors

    def _parse_host_discovery(self, output: str) -> list[Host]:
        """Parse nmap host discovery output."""
        hosts = []
        # Pattern: "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
        pattern = r"Nmap scan report for (?:\S+ )?\((\d+\.\d+\.\d+\.\d+)\)"
        for match in re.finditer(pattern, output):
            ip = match.group(1)
            hosts.append(Host(ip=ip, is_alive=True))
        return hosts

    def _parse_port_scan(self, output: str, target: str) -> tuple[list[Host], list[Service]]:
        """Parse nmap port scan output."""
        hosts = []
        services = []

        # Extract host info
        host_match = re.search(r"Nmap scan report for (?:\S+ )?\((\d+\.\d+\.\d+\.\d+)\)", output)
        if host_match:
            ip = host_match.group(1)
            host = Host(ip=ip, is_alive=True)
            hosts.append(host)

            # Extract open ports
            port_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)"
            for match in re.finditer(port_pattern, output):
                port = int(match.group(1))
                protocol = match.group(2)
                service_name = match.group(3)
                services.append(Service(
                    host_id=host.id,
                    port=port,
                    protocol=protocol,
                    state="open",
                    service_name=service_name,
                ))

        return hosts, services

    def _parse_service_scan(self, output: str, target: str) -> tuple[list[Host], list[Service]]:
        """Parse nmap service scan output."""
        hosts = []
        services = []

        host_match = re.search(r"Nmap scan report for (?:\S+ )?\((\d+\.\d+\.\d+\.\d+)\)", output)
        if host_match:
            ip = host_match.group(1)
            host = Host(ip=ip, is_alive=True)
            hosts.append(host)

            # Extract services with versions
            service_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)\s+(.*?)(?:\n|$)"
            for match in re.finditer(service_pattern, output):
                port = int(match.group(1))
                protocol = match.group(2)
                service_name = match.group(3)
                version_info = match.group(4).strip()

                product = ""
                version = ""
                if version_info:
                    parts = version_info.split(None, 1)
                    product = parts[0] if parts else ""
                    version = parts[1] if len(parts) > 1 else ""

                services.append(Service(
                    host_id=host.id,
                    port=port,
                    protocol=protocol,
                    state="open",
                    service_name=service_name,
                    product=product or None,
                    version=version or None,
                ))

        return hosts, services

    def _parse_os_detection(self, output: str, target: str) -> tuple[list[Host], list[Service]]:
        """Parse nmap OS detection output."""
        hosts = []

        host_match = re.search(r"Nmap scan report for (?:\S+ )?\((\d+\.\d+\.\d+\.\d+)\)", output)
        if host_match:
            ip = host_match.group(1)
            os_match = re.search(r"OS details?:\s*(.+?)(?:\n|$)", output)
            os_info = os_match.group(1) if os_match else None

            host = Host(ip=ip, is_alive=True, os=os_info)
            hosts.append(host)

        return hosts, []


# Register tools
@register_tool(
    name="nmap_host_scan",
    description="Discover live hosts in a network using nmap ping scan",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target network (CIDR)"),
        ToolParameter(name="timeout", type="int", description="Timeout in seconds", required=False, default=5),
    ],
)
async def nmap_host_scan(target: str, timeout: int = 5) -> dict:
    """Execute host discovery scan."""
    recon = NetworkRecon()
    result = await recon.host_discovery(target, timeout)
    return {
        "hosts": [{"ip": h.ip, "hostname": h.hostname} for h in result.hosts],
        "raw": result.raw_output,
        "errors": result.errors,
    }


@register_tool(
    name="nmap_service_scan",
    description="Scan ports and enumerate services on a target",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP address"),
        ToolParameter(name="ports", type="str", description="Port range (e.g., 1-1000)", required=False, default="1-1000"),
        ToolParameter(name="scan_type", type="str", description="Scan type: quick, full, stealth, aggressive", required=False, default="quick"),
    ],
)
async def nmap_service_scan(target: str, ports: str = "1-1000", scan_type: str = "quick") -> dict:
    """Execute service scan."""
    recon = NetworkRecon()
    result = await recon.port_scan(target, ports, scan_type)
    return {
        "hosts": [{"ip": h.ip, "os": h.os} for h in result.hosts],
        "services": [
            {"port": s.port, "service": s.service_name, "version": s.version}
            for s in result.services
        ],
        "raw": result.raw_output,
        "errors": result.errors,
    }


@register_tool(
    name="network_map",
    description="Map network topology",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="target", type="str", description="Target network (CIDR)"),
    ],
)
async def network_map(target: str) -> dict:
    """Execute network mapping."""
    recon = NetworkRecon()
    result = await recon.network_mapping(target)
    return {
        "hosts": [{"ip": h.ip} for h in result.hosts],
        "networks": [{"cidr": n.cidr, "name": n.name} for n in result.networks],
        "raw": result.raw_output,
    }


@register_tool(
    name="parallel_scan",
    description="Scan multiple targets in parallel for faster reconnaissance",
    category=ToolCategory.RECON,
    parameters=[
        ToolParameter(name="targets", type="str", description="Comma-separated list of targets"),
        ToolParameter(name="scan_type", type="str", description="Scan type: quick, full, stealth", required=False, default="quick"),
        ToolParameter(name="max_concurrent", type="int", description="Max concurrent scans", required=False, default=10),
    ],
)
async def parallel_scan(targets: str, scan_type: str = "quick", max_concurrent: int = 10) -> dict:
    """Execute parallel scans."""
    target_list = [t.strip() for t in targets.split(",")]
    recon = NetworkRecon()
    results = await recon.parallel_port_scan(target_list, scan_type=scan_type, max_concurrent=max_concurrent)

    return {
        "scans_completed": len(results),
        "results": [
            {
                "target": r.target,
                "hosts": len(r.hosts),
                "services": len(r.services),
            }
            for r in results if hasattr(r, 'hosts')
        ],
    }
