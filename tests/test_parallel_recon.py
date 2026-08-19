"""Tests for parallel reconnaissance."""

import pytest
import asyncio

from recon.parallel import (
    ParallelScanner,
    ReconOrchestrator,
    ScanTask,
    ScanGroup,
    ScanStatus,
    ScanPriority,
)


class TestScanTask:
    """Tests for ScanTask."""

    def test_create_task(self):
        task = ScanTask(name="test", target="192.168.1.1", scan_type="port_scan")
        assert task.name == "test"
        assert task.target == "192.168.1.1"
        assert task.status == ScanStatus.PENDING

    def test_task_defaults(self):
        task = ScanTask()
        assert task.id is not None
        assert task.status == ScanStatus.PENDING
        assert task.priority == ScanPriority.MEDIUM


class TestScanGroup:
    """Tests for ScanGroup."""

    def test_create_group(self):
        group = ScanGroup(name="test_group")
        assert group.name == "test_group"
        assert group.tasks == []

    def test_group_progress(self):
        group = ScanGroup(name="test")
        group.tasks = [
            ScanTask(status=ScanStatus.COMPLETED),
            ScanTask(status=ScanStatus.COMPLETED),
            ScanTask(status=ScanStatus.RUNNING),
        ]
        assert group.total_tasks == 3
        assert group.completed_tasks == 2
        assert group.progress == pytest.approx(66.67, rel=0.01)

    def test_group_empty_progress(self):
        group = ScanGroup(name="empty")
        assert group.progress == 0.0


class TestParallelScanner:
    """Tests for ParallelScanner."""

    def test_create_scanner(self):
        scanner = ParallelScanner(max_concurrent=5)
        assert scanner.max_concurrent == 5

    def test_get_progress_empty(self):
        scanner = ParallelScanner()
        progress = scanner.get_progress()
        assert progress["total_tasks"] == 0
        assert progress["completed"] == 0

    def test_clear_history(self):
        scanner = ParallelScanner()
        scanner.clear_history()
        assert len(scanner._tasks) == 0
        assert len(scanner._groups) == 0


class TestParallelScannerAsync:
    """Async tests for ParallelScanner."""

    @pytest.mark.asyncio
    async def test_scan_single(self):
        async def mock_scan(target: str) -> dict:
            return {"target": target, "status": "ok"}

        scanner = ParallelScanner(timeout=10)
        task = await scanner.scan_single(mock_scan, "192.168.1.1", scan_type="test")

        assert task.status == ScanStatus.COMPLETED
        assert task.result is not None
        assert task.result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_scan_single_timeout(self):
        async def slow_scan(target: str) -> dict:
            await asyncio.sleep(5)
            return {"target": target}

        scanner = ParallelScanner(timeout=1)
        task = await scanner.scan_single(slow_scan, "192.168.1.1")

        assert task.status == ScanStatus.FAILED
        assert "timed out" in task.error.lower()

    @pytest.mark.asyncio
    async def test_scan_parallel(self):
        async def mock_scan(target: str) -> dict:
            return {"target": target, "status": "ok"}

        scanner = ParallelScanner(max_concurrent=5)
        group = await scanner.scan_parallel(
            mock_scan,
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            scan_type="test",
        )

        assert group.status == ScanStatus.COMPLETED
        assert group.total_tasks == 3
        assert group.completed_tasks == 3
        assert group.progress == 100.0

    @pytest.mark.asyncio
    async def test_scan_parallel_partial_failure(self):
        call_count = 0

        async def sometimes_fail(target: str) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ValueError("Test error")
            return {"target": target}

        scanner = ParallelScanner(max_concurrent=5)
        group = await scanner.scan_parallel(
            sometimes_fail,
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        )

        assert group.completed_tasks == 2
        assert group.failed_tasks == 1

    @pytest.mark.asyncio
    async def test_concurrency_limit(self):
        max_concurrent = 2
        concurrent_count = 0
        max_concurrent_reached = 0

        async def tracked_scan(target: str) -> dict:
            nonlocal concurrent_count, max_concurrent_reached
            concurrent_count += 1
            max_concurrent_reached = max(max_concurrent_reached, concurrent_count)
            await asyncio.sleep(0.1)
            concurrent_count -= 1
            return {"target": target}

        scanner = ParallelScanner(max_concurrent=max_concurrent)
        await scanner.scan_parallel(
            tracked_scan,
            ["1", "2", "3", "4", "5"],
        )

        assert max_concurrent_reached <= max_concurrent


class TestReconOrchestrator:
    """Tests for ReconOrchestrator."""

    def test_create_orchestrator(self):
        orch = ReconOrchestrator(max_concurrent=5)
        assert orch.scanner.max_concurrent == 5

    def test_get_progress(self):
        orch = ReconOrchestrator()
        progress = orch.get_progress()
        assert "total_tasks" in progress


class TestReconOrchestratorAsync:
    """Async tests for ReconOrchestrator."""

    @pytest.mark.asyncio
    async def test_parallel_network_scan(self):
        async def mock_scan(target: str, **kwargs) -> dict:
            return {"target": target, "ports": [80, 443]}

        orch = ReconOrchestrator()
        # Mock the recon module
        from unittest.mock import MagicMock, AsyncMock
        mock_recon = MagicMock()
        mock_recon.port_scan = AsyncMock(return_value=MagicMock(
            target="test",
            hosts=[],
            services=[],
            raw_output="",
            errors=[],
        ))

        # Patch the import
        import recon.network
        original = recon.network.NetworkRecon
        recon.network.NetworkRecon = lambda: mock_recon

        try:
            group = await orch.parallel_network_scan(
                ["192.168.1.1", "192.168.1.2"],
            )
            assert group.total_tasks == 2
        finally:
            recon.network.NetworkRecon = original
