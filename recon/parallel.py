"""Parallel Reconnaissance Engine - Async parallel scanning for faster discovery."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
from uuid import UUID, uuid4


class ScanStatus(str, Enum):
    """Status of a scan task."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPriority(str, Enum):
    """Priority of a scan task."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ScanTask:
    """A single scan task."""

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    target: str = ""
    scan_type: str = ""
    status: ScanStatus = ScanStatus.PENDING
    priority: ScanPriority = ScanPriority.MEDIUM
    result: Optional[dict] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanGroup:
    """A group of related scan tasks."""

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    tasks: list[ScanTask] = field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def total_tasks(self) -> int:
        return len(self.tasks)

    @property
    def completed_tasks(self) -> int:
        return sum(1 for t in self.tasks if t.status == ScanStatus.COMPLETED)

    @property
    def failed_tasks(self) -> int:
        return sum(1 for t in self.tasks if t.status == ScanStatus.FAILED)

    @property
    def progress(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100


class ParallelScanner:
    """Async parallel scanning engine."""

    def __init__(self, max_concurrent: int = 10, timeout: int = 300):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: list[ScanTask] = []
        self._groups: list[ScanGroup] = []
        self._active_tasks: dict[UUID, asyncio.Task] = {}

    async def scan_single(
        self,
        func: Callable,
        target: str,
        scan_type: str = "custom",
        **kwargs,
    ) -> ScanTask:
        """Execute a single scan task."""
        task = ScanTask(
            name=f"{scan_type}_{target}",
            target=target,
            scan_type=scan_type,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        try:
            async with self._semaphore:
                result = await asyncio.wait_for(
                    func(target, **kwargs),
                    timeout=self.timeout,
                )
                task.result = result
                task.status = ScanStatus.COMPLETED
        except asyncio.TimeoutError:
            task.status = ScanStatus.FAILED
            task.error = f"Scan timed out after {self.timeout}s"
        except Exception as e:
            task.status = ScanStatus.FAILED
            task.error = str(e)
        finally:
            task.completed_at = datetime.utcnow()
            if task.started_at:
                task.duration_seconds = (task.completed_at - task.started_at).total_seconds()

        self._tasks.append(task)
        return task

    async def scan_parallel(
        self,
        func: Callable,
        targets: list[str],
        scan_type: str = "custom",
        group_name: Optional[str] = None,
        **kwargs,
    ) -> ScanGroup:
        """Execute parallel scans against multiple targets."""
        group = ScanGroup(
            name=group_name or f"{scan_type}_parallel",
            started_at=datetime.utcnow(),
            status=ScanStatus.RUNNING,
        )

        # Create tasks for all targets
        tasks = []
        for target in targets:
            task = ScanTask(
                name=f"{scan_type}_{target}",
                target=target,
                scan_type=scan_type,
                status=ScanStatus.PENDING,
            )
            group.tasks.append(task)
            tasks.append(self._execute_task(func, task, **kwargs))

        # Execute all tasks in parallel
        await asyncio.gather(*tasks, return_exceptions=True)

        # Update group status
        group.completed_at = datetime.utcnow()
        if group.failed_tasks > 0 and group.completed_tasks > 0:
            group.status = ScanStatus.COMPLETED  # Partial success
        elif group.failed_tasks == group.total_tasks:
            group.status = ScanStatus.FAILED
        else:
            group.status = ScanStatus.COMPLETED

        self._groups.append(group)
        return group

    async def scan_multi_type(
        self,
        scans: list[dict],
        group_name: str = "multi_scan",
    ) -> ScanGroup:
        """Execute multiple scan types against targets.

        scans: [{"func": callable, "target": str, "scan_type": str, "kwargs": dict}, ...]
        """
        group = ScanGroup(
            name=group_name,
            started_at=datetime.utcnow(),
            status=ScanStatus.RUNNING,
        )

        tasks = []
        for scan_config in scans:
            func = scan_config["func"]
            target = scan_config["target"]
            scan_type = scan_config.get("scan_type", "custom")
            scan_kwargs = scan_config.get("kwargs", {})

            task = ScanTask(
                name=f"{scan_type}_{target}",
                target=target,
                scan_type=scan_type,
                status=ScanStatus.PENDING,
            )
            group.tasks.append(task)
            tasks.append(self._execute_task(func, task, **scan_kwargs))

        await asyncio.gather(*tasks, return_exceptions=True)

        group.completed_at = datetime.utcnow()
        if group.failed_tasks > 0 and group.completed_tasks > 0:
            group.status = ScanStatus.COMPLETED
        elif group.failed_tasks == group.total_tasks:
            group.status = ScanStatus.FAILED
        else:
            group.status = ScanStatus.COMPLETED

        self._groups.append(group)
        return group

    async def _execute_task(
        self,
        func: Callable,
        task: ScanTask,
        **kwargs,
    ) -> None:
        """Execute a single task with semaphore control."""
        task.status = ScanStatus.RUNNING
        task.started_at = datetime.utcnow()

        try:
            async with self._semaphore:
                result = await asyncio.wait_for(
                    func(task.target, **kwargs),
                    timeout=self.timeout,
                )
                task.result = result
                task.status = ScanStatus.COMPLETED
        except asyncio.TimeoutError:
            task.status = ScanStatus.FAILED
            task.error = f"Scan timed out after {self.timeout}s"
        except Exception as e:
            task.status = ScanStatus.FAILED
            task.error = str(e)
        finally:
            task.completed_at = datetime.utcnow()
            if task.started_at:
                task.duration_seconds = (task.completed_at - task.started_at).total_seconds()

    def get_progress(self, group_id: Optional[UUID] = None) -> dict:
        """Get scan progress."""
        if group_id:
            for group in self._groups:
                if group.id == group_id:
                    return {
                        "group": group.name,
                        "total": group.total_tasks,
                        "completed": group.completed_tasks,
                        "failed": group.failed_tasks,
                        "progress": group.progress,
                        "status": group.status.value,
                    }
            return {"error": "Group not found"}

        # Overall progress
        total = len(self._tasks)
        completed = sum(1 for t in self._tasks if t.status == ScanStatus.COMPLETED)
        failed = sum(1 for t in self._tasks if t.status == ScanStatus.FAILED)

        return {
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "running": total - completed - failed,
            "progress": (completed / total * 100) if total > 0 else 0,
        }

    def get_results(
        self,
        group_id: Optional[UUID] = None,
        scan_type: Optional[str] = None,
    ) -> list[ScanTask]:
        """Get scan results with optional filters."""
        if group_id:
            for group in self._groups:
                if group.id == group_id:
                    tasks = group.tasks
                    if scan_type:
                        tasks = [t for t in tasks if t.scan_type == scan_type]
                    return tasks
            return []

        tasks = self._tasks
        if scan_type:
            tasks = [t for t in tasks if t.scan_type == scan_type]
        return tasks

    def get_successful_results(
        self,
        group_id: Optional[UUID] = None,
    ) -> list[ScanTask]:
        """Get only successful scan results."""
        return [
            t for t in self.get_results(group_id)
            if t.status == ScanStatus.COMPLETED
        ]

    def cancel_all(self) -> int:
        """Cancel all running tasks."""
        cancelled = 0
        for task_id, async_task in self._active_tasks.items():
            if not async_task.done():
                async_task.cancel()
                cancelled += 1
        return cancelled

    def clear_history(self) -> None:
        """Clear scan history."""
        self._tasks.clear()
        self._groups.clear()
        self._active_tasks.clear()


class ReconOrchestrator:
    """High-level reconnaissance orchestrator with parallel scanning."""

    def __init__(self, max_concurrent: int = 10):
        self.scanner = ParallelScanner(max_concurrent=max_concurrent)
        self._scan_history: list[dict] = []

    async def full_recon(
        self,
        target: str,
        ports: str = "1-1000",
        scan_types: Optional[list[str]] = None,
    ) -> dict:
        """Execute full reconnaissance against a target."""
        if scan_types is None:
            scan_types = ["host_discovery", "port_scan", "service_scan"]

        results = {}

        # Phase 1: Host discovery (quick)
        if "host_discovery" in scan_types:
            from recon.network import NetworkRecon
            recon = NetworkRecon()
            task = await self.scanner.scan_single(
                recon.host_discovery,
                target,
                scan_type="host_discovery",
            )
            results["host_discovery"] = task.result

        # Phase 2: Parallel port scans
        if "port_scan" in scan_types:
            # Split target if it's a network
            targets = self._expand_targets(target, results.get("host_discovery"))
            from recon.network import NetworkRecon
            recon = NetworkRecon()

            group = await self.scanner.scan_parallel(
                recon.port_scan,
                targets,
                scan_type="port_scan",
                group_name="port_scans",
                ports=ports,
            )
            results["port_scan"] = {
                "group_id": str(group.id),
                "progress": group.progress,
                "completed": group.completed_tasks,
                "total": group.total_tasks,
            }

        # Phase 3: Service enumeration on discovered ports
        if "service_scan" in scan_types:
            # Get discovered services and enumerate them
            from recon.network import NetworkRecon
            recon = NetworkRecon()

            service_targets = self._get_service_targets(results)
            if service_targets:
                group = await self.scanner.scan_parallel(
                    recon.service_enumeration,
                    service_targets,
                    scan_type="service_scan",
                    group_name="service_scans",
                )
                results["service_scan"] = {
                    "group_id": str(group.id),
                    "progress": group.progress,
                    "completed": group.completed_tasks,
                    "total": group.total_tasks,
                }

        # Phase 4: Parallel OS detection
        if "os_detection" in scan_types:
            from recon.network import NetworkRecon
            recon = NetworkRecon()

            os_targets = self._get_os_targets(results)
            if os_targets:
                group = await self.scanner.scan_parallel(
                    recon.os_detection,
                    os_targets,
                    scan_type="os_detection",
                    group_name="os_detection",
                )
                results["os_detection"] = {
                    "group_id": str(group.id),
                    "progress": group.progress,
                }

        self._scan_history.append({
            "target": target,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        })

        return results

    async def parallel_network_scan(
        self,
        targets: list[str],
        scan_type: str = "quick",
    ) -> ScanGroup:
        """Execute parallel network scans."""
        from recon.network import NetworkRecon
        recon = NetworkRecon()

        return await self.scanner.scan_parallel(
            recon.port_scan,
            targets,
            scan_type=f"network_{scan_type}",
            group_name=f"parallel_{scan_type}",
        )

    async def parallel_service_enum(
        self,
        targets: list[str],
    ) -> ScanGroup:
        """Execute parallel service enumeration."""
        from recon.network import NetworkRecon
        recon = NetworkRecon()

        return await self.scanner.scan_parallel(
            recon.service_enumeration,
            targets,
            scan_type="service_enum",
            group_name="parallel_service_enum",
        )

    def _expand_targets(self, target: str, host_discovery: Optional[dict]) -> list[str]:
        """Expand target to individual hosts if available."""
        if host_discovery and "hosts" in host_discovery:
            return [h["ip"] for h in host_discovery["hosts"]]
        return [target]

    def _get_service_targets(self, results: dict) -> list[str]:
        """Get targets for service scanning from results."""
        targets = []
        if "host_discovery" in results and results["host_discovery"]:
            hosts = results["host_discovery"].get("hosts", [])
            targets = [h["ip"] for h in hosts]
        return targets if targets else []

    def _get_os_targets(self, results: dict) -> list[str]:
        """Get targets for OS detection from results."""
        targets = []
        if "host_discovery" in results and results["host_discovery"]:
            hosts = results["host_discovery"].get("hosts", [])
            targets = [h["ip"] for h in hosts]
        return targets if targets else []

    def get_progress(self) -> dict:
        """Get overall reconnaissance progress."""
        return self.scanner.get_progress()

    def get_all_results(self) -> list[dict]:
        """Get all scan results."""
        return self._scan_history.copy()
