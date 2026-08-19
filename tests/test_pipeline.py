"""Tests for the DeepEngage pipeline (core.orchestrator.pipeline)."""

import asyncio
import json
from pathlib import Path

from core.orchestrator.pipeline import DeepEngagePipeline, Phase
from core.state.engagement_state import AccessLevel, EngagementState

# --- Injectable fakes (offline; no nmap / no external tools) -----------------

def fake_scan(target: str) -> dict:
    return {
        "hosts": ["10.10.10.5"],
        "services": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 80, "service": "http", "version": "Apache 2.4"},
        ],
    }


def fake_filter(target: str) -> dict:
    return {
        "filter_present": True,
        "mechanism": "router_acl",
        "finding": "Weak stateless filter present (Cisco ACL signature).",
        "evidence": ["ICMP type=3 code=13 observed"],
    }


def fake_exploit(target: str, port: int, service: str) -> list[dict]:
    if service == "ssh":
        return [
            {
                "technique": "ssh_brute_force",
                "success": True,
                "access_gained": "user",
                "error": None,
            }
        ]
    return [
        {
            "technique": "http_probe",
            "success": False,
            "access_gained": None,
            "error": "no vuln",
        }
    ]


async def run_pipeline(output_dir):
    pipe = DeepEngagePipeline(
        target="10.10.10.5",
        name="Pipeline Test",
        scan_fn=fake_scan,
        filter_fn=fake_filter,
        exploit_fn=fake_exploit,
        output_dir=str(output_dir),
    )
    return await pipe.run()


class TestDeepEngagePipeline:
    def test_full_pipeline_runs(self, tmp_path):
        payload = asyncio.run(run_pipeline(tmp_path))

        # Summary reflects the chained lifecycle.
        assert payload["summary"]["hosts"] == 1
        assert payload["summary"]["services"] == 2
        assert payload["summary"]["access"] == "user"
        assert payload["summary"]["vulnerabilities"] >= 2  # 1 risky service + 1 exploited

        # All 7 phases executed in order.
        phases = [p["phase"] for p in payload["phases"]]
        assert phases == ["recon", "filter_analyze", "enumerate", "exploit", "post_exploit", "pivot", "report"]

        # Filter finding + access finding present.
        finding_ids = {f["id"] for f in payload["findings"]}
        assert "FW-001" in finding_ids
        assert "ACC-001" in finding_ids

    def test_report_artifacts_written(self, tmp_path):
        payload = asyncio.run(run_pipeline(tmp_path))

        md_path = payload["artifacts"]["markdown"]
        json_path = payload["artifacts"]["json"]

        md = Path(md_path).read_text(encoding="utf-8")
        js = json.loads(Path(json_path).read_text(encoding="utf-8"))

        assert "Penetration Test Report" in md
        assert "Attack Timeline" in md
        assert "FW-001" in md
        assert js["summary"]["access"] == "user"

    def test_single_phase_run(self, tmp_path):
        state = EngagementState(name="Single Phase")
        pipe = DeepEngagePipeline(
            state=state,
            target="10.10.10.5",
            scan_fn=fake_scan,
            filter_fn=fake_filter,
            exploit_fn=fake_exploit,
            output_dir=str(tmp_path),
        )
        payload = asyncio.run(pipe.run(phases=[Phase.RECON]))
        assert state.hosts_discovered == 1
        assert state.services_discovered == 2
        assert payload["summary"]["phases"] == ["recon"]

    def test_requires_target(self, tmp_path):
        pipe = DeepEngagePipeline(output_dir=str(tmp_path))
        try:
            asyncio.run(pipe.run())
        except ValueError as e:
            assert "target" in str(e).lower()
        else:
            raise AssertionError("expected ValueError without target")

    def test_exploit_access_promotes_state(self, tmp_path):
        state = EngagementState(name="Access Test")
        pipe = DeepEngagePipeline(
            state=state,
            target="10.10.10.5",
            scan_fn=fake_scan,
            filter_fn=fake_filter,
            exploit_fn=fake_exploit,
            output_dir=str(tmp_path),
        )
        asyncio.run(pipe.run(phases=[Phase.RECON, Phase.EXPLOIT]))
        assert state.current_access == AccessLevel.USER
