"""Pivot Manager - Real pivot and double-pivot workflows via SSH and Chisel."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from ai.sessions import SSH_SESSION_MANAGER


class PivotMethod(str, Enum):
    """Methods for establishing pivots."""
    SSH_TUNNEL = "ssh_tunnel"
    SOCKS_PROXY = "socks_proxy"
    PORT_FORWARD = "port_forward"
    CHISEL = "chisel"
    PROXYCHAINS = "proxychains"


class PivotStatus(str, Enum):
    """Status of a pivot."""
    ACTIVE = "active"
    FAILED = "failed"
    CLOSED = "closed"
    PENDING = "pending"


@dataclass
class Pivot:
    """A network pivot."""
    id: UUID = field(default_factory=uuid4)
    source_host: str = ""
    destination_network: str = ""
    method: PivotMethod = PivotMethod.SSH_TUNNEL
    local_port: Optional[int] = None
    remote_port: Optional[int] = None
    status: PivotStatus = PivotStatus.PENDING
    depth: int = 0
    established_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    process: Optional[asyncio.subprocess.Process] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class PivotManager:
    """Manages real pivots via SSH tunneling and Chisel."""

    def __init__(self, max_depth: int = 3):
        self._pivots: list[Pivot] = []
        self._max_depth = max_depth
        self._used_ports: set[int] = set()
        self._next_local_port = 1080

    def _get_available_port(self) -> int:
        """Get next available local port."""
        while self._next_local_port in self._used_ports:
            self._next_local_port += 1
        port = self._next_local_port
        self._used_ports.add(port)
        return port

    def can_pivot(self) -> bool:
        """Check if another pivot can be established."""
        active_pivots = [p for p in self._pivots if p.status == PivotStatus.ACTIVE]
        if not active_pivots:
            return True
        max_current_depth = max(p.depth for p in active_pivots)
        return max_current_depth < self._max_depth

    def get_current_depth(self) -> int:
        """Get current pivot depth."""
        active_pivots = [p for p in self._pivots if p.status == PivotStatus.ACTIVE]
        if not active_pivots:
            return 0
        return max(p.depth for p in active_pivots)

    async def establish_pivot(
        self,
        source_host: str,
        destination_network: str,
        method: PivotMethod = PivotMethod.SSH_TUNNEL,
        local_port: Optional[int] = None,
        credentials: Optional[dict] = None,
    ) -> Pivot:
        """Establish a new pivot."""
        depth = self.get_current_depth() + 1
        if local_port is None:
            local_port = self._get_available_port()

        pivot = Pivot(
            source_host=source_host,
            destination_network=destination_network,
            method=method,
            local_port=local_port,
            depth=depth,
            status=PivotStatus.PENDING,
        )

        try:
            result = await self._create_pivot(pivot, credentials)
            if result.get("success"):
                pivot.status = PivotStatus.ACTIVE
                pivot.established_at = datetime.now()
                pivot.remote_port = result.get("remote_port")
                pivot.process = result.get("process")
                pivot.metadata["method"] = method.value
            else:
                pivot.status = PivotStatus.FAILED
                pivot.metadata["error"] = result.get("error", "Unknown error")
        except Exception as e:
            pivot.status = PivotStatus.FAILED
            pivot.metadata["error"] = str(e)

        self._pivots.append(pivot)
        return pivot

    async def _create_pivot(self, pivot: Pivot, credentials: Optional[dict] = None) -> dict:
        """Create the actual pivot connection."""
        if pivot.method == PivotMethod.SSH_TUNNEL:
            return await self._create_ssh_tunnel(pivot, credentials)
        elif pivot.method == PivotMethod.SOCKS_PROXY:
            return await self._create_socks_proxy(pivot, credentials)
        elif pivot.method == PivotMethod.PORT_FORWARD:
            return await self._create_port_forward(pivot, credentials)
        elif pivot.method == PivotMethod.CHISEL:
            return await self._create_chisel_pivot(pivot, credentials)
        else:
            return {"success": False, "error": f"Method {pivot.method} not implemented"}

    async def _create_ssh_tunnel(self, pivot: Pivot, credentials: Optional[dict] = None) -> dict:
        """Create SSH SOCKS proxy tunnel."""
        username = credentials.get("username", "root") if credentials else "root"
        password = credentials.get("password", "") if credentials else ""

        # Dynamic SOCKS proxy via SSH
        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 -D {pivot.local_port} -N "
            f"{username}@{pivot.source_host}"
        )

        try:
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            # Give it a moment to connect
            await asyncio.sleep(2)

            # Check if process is still running (not crashed)
            if process.returncode is None:
                return {
                    "success": True,
                    "process": process,
                    "local_port": pivot.local_port,
                    "method": "SOCKS proxy",
                    "usage": f"proxychains -q nmap -sT target",
                }
            else:
                stderr = await process.stderr.read()
                return {"success": False, "error": stderr.decode("utf-8", errors="replace")}

        except FileNotFoundError:
            return {"success": False, "error": "sshpass not found. Install: apt-get install sshpass"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _create_socks_proxy(self, pivot: Pivot, credentials: Optional[dict] = None) -> dict:
        """Create SOCKS proxy via SSH."""
        return await self._create_ssh_tunnel(pivot, credentials)

    async def _create_port_forward(self, pivot: Pivot, credentials: Optional[dict] = None) -> dict:
        """Create SSH port forward."""
        username = credentials.get("username", "root") if credentials else "root"
        password = credentials.get("password", "") if credentials else ""

        remote_port = pivot.remote_port or 8080

        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 -L {pivot.local_port}:127.0.0.1:{remote_port} -N "
            f"{username}@{pivot.source_host}"
        )

        try:
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            await asyncio.sleep(2)

            if process.returncode is None:
                return {
                    "success": True,
                    "process": process,
                    "local_port": pivot.local_port,
                    "remote_port": remote_port,
                    "method": "port forward",
                }
            else:
                stderr = await process.stderr.read()
                return {"success": False, "error": stderr.decode("utf-8", errors="replace")}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _create_chisel_pivot(self, pivot: Pivot, credentials: Optional[dict] = None) -> dict:
        """Create pivot using Chisel."""
        username = credentials.get("username", "root") if credentials else "root"
        password = credentials.get("password", "") if credentials else ""

        # Upload chisel to source host
        try:
            upload_cmd = (
                f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no "
                f"/tmp/chisel {username}@{pivot.source_host}:/tmp/chisel"
            )
            proc = await asyncio.create_subprocess_shell(
                upload_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)

            # Execute chisel on source host to create SOCKS proxy
            cmd = (
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
                f"{username}@{pivot.source_host} "
                f"'chmod +x /tmp/chisel && /tmp/chisel client http://127.0.0.1:8080 socks'"
            )

            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            await asyncio.sleep(3)

            if process.returncode is None:
                return {
                    "success": True,
                    "process": process,
                    "method": "chisel",
                    "usage": "proxychains -q nmap -sT target",
                }
            else:
                return {"success": False, "error": "Chisel connection failed"}

        except Exception as e:
            return {"success": False, "error": f"Chisel setup failed: {e}"}

    async def close_pivot(self, pivot_id: UUID) -> bool:
        """Close a pivot."""
        for pivot in self._pivots:
            if pivot.id == pivot_id and pivot.status == PivotStatus.ACTIVE:
                # Kill the process if running
                if pivot.process:
                    try:
                        pivot.process.terminate()
                        await asyncio.wait_for(pivot.process.wait(), timeout=5)
                    except Exception:
                        try:
                            pivot.process.kill()
                        except Exception:
                            pass

                pivot.status = PivotStatus.CLOSED
                pivot.closed_at = datetime.now()

                if pivot.local_port:
                    self._used_ports.discard(pivot.local_port)

                return True
        return False

    async def close_all(self) -> int:
        """Close all active pivots."""
        count = 0
        for pivot in self._pivots:
            if pivot.status == PivotStatus.ACTIVE:
                await self.close_pivot(pivot.id)
                count += 1
        count += await SSH_SESSION_MANAGER.close_all()
        return count

    async def close_all_sessions(self) -> int:
        """Close all persistent SSH sessions opened during pivoting."""
        return await SSH_SESSION_MANAGER.close_all()

    async def establish_double_pivot(
        self,
        first_source: str,
        second_source: str,
        destination_network: str,
        credentials_first: Optional[dict] = None,
        credentials_second: Optional[dict] = None,
    ) -> list[Pivot]:
        """Establish double pivot: attacker -> first_source -> second_source -> destination."""
        pivots = []

        # First pivot
        pivot1 = await self.establish_pivot(
            source_host=first_source,
            destination_network=destination_network,
            method=PivotMethod.SSH_TUNNEL,
            credentials=credentials_first,
        )
        pivots.append(pivot1)

        if pivot1.status != PivotStatus.ACTIVE:
            return pivots

        # Second pivot through first
        pivot2 = await self.establish_pivot(
            source_host=second_source,
            destination_network=destination_network,
            method=PivotMethod.SSH_TUNNEL,
            credentials=credentials_second,
        )
        pivots.append(pivot2)

        return pivots

    def get_active_pivots(self) -> list[Pivot]:
        """Get all active pivots."""
        return [p for p in self._pivots if p.status == PivotStatus.ACTIVE]

    def get_pivot_chain(self) -> list[Pivot]:
        """Get the current pivot chain."""
        active = self.get_active_pivots()
        return sorted(active, key=lambda p: p.depth)

    def get_all_pivots(self) -> list[Pivot]:
        """Get all pivots."""
        return self._pivots.copy()

    def get_statistics(self) -> dict:
        """Get pivot statistics."""
        return {
            "total": len(self._pivots),
            "active": len([p for p in self._pivots if p.status == PivotStatus.ACTIVE]),
            "failed": len([p for p in self._pivots if p.status == PivotStatus.FAILED]),
            "closed": len([p for p in self._pivots if p.status == PivotStatus.CLOSED]),
            "current_depth": self.get_current_depth(),
            "max_depth": self._max_depth,
        }

    def to_ascii_diagram(self) -> str:
        """Generate ASCII diagram of pivot chain."""
        chain = self.get_pivot_chain()
        if not chain:
            return "No active pivots"

        lines = ["Pivot Chain:"]
        lines.append("  [Attacker]")

        for i, pivot in enumerate(chain):
            status_icon = "✓" if pivot.status == PivotStatus.ACTIVE else "✗"
            port_info = f":{pivot.local_port}" if pivot.local_port else ""
            lines.append(f"    │")
            lines.append(f"    ▼ Pivot #{i+1} ({pivot.method.value}) [{status_icon}]{port_info}")
            lines.append(f"  [{pivot.destination_network}]")

        return "\n".join(lines)
