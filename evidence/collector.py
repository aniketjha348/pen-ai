"""Evidence Collector - Captures raw output, screenshots, and artifacts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from uuid import UUID, uuid4

from core.events.models import Event


class EvidenceType(str, Enum):
    """Types of evidence."""

    RAW_OUTPUT = "raw_output"
    SCREENSHOT = "screenshot"
    COMMAND = "command"
    ARTIFACT = "artifact"
    LOG = "log"
    PCAP = "pcap"


@dataclass
class EvidenceItem:
    """A single evidence item."""

    id: UUID = field(default_factory=uuid4)
    evidence_type: EvidenceType = EvidenceType.RAW_OUTPUT
    event_id: Optional[UUID] = None
    target: Optional[str] = None
    tool: Optional[str] = None
    content: str = ""
    file_path: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class EvidenceCollector:
    """Collects and manages evidence during engagement."""

    def __init__(self, engagement_dir: str = "engagements"):
        self._engagement_dir = Path(engagement_dir)
        self._evidence: list[EvidenceItem] = []
        self._initialized = False

    def initialize(self, engagement_id: str) -> None:
        """Initialize evidence directories for an engagement."""
        engagement_path = self._engagement_dir / engagement_id

        directories = [
            "raw",
            "screenshots",
            "commands",
            "artifacts",
            "timeline",
            "metadata",
        ]

        for dir_name in directories:
            (engagement_path / dir_name).mkdir(parents=True, exist_ok=True)

        self._initialized = True

    def capture_raw_output(
        self,
        content: str,
        target: Optional[str] = None,
        tool: Optional[str] = None,
        event_id: Optional[UUID] = None,
    ) -> EvidenceItem:
        """Capture raw command output."""
        evidence = EvidenceItem(
            evidence_type=EvidenceType.RAW_OUTPUT,
            event_id=event_id,
            target=target,
            tool=tool,
            content=content,
        )
        self._evidence.append(evidence)
        return evidence

    def capture_command(
        self,
        command: str,
        output: str,
        exit_code: int,
        target: Optional[str] = None,
        event_id: Optional[UUID] = None,
    ) -> EvidenceItem:
        """Capture a command and its output."""
        content = f"$ {command}\nExit Code: {exit_code}\n\n{output}"
        evidence = EvidenceItem(
            evidence_type=EvidenceType.COMMAND,
            event_id=event_id,
            target=target,
            content=content,
            metadata={"command": command, "exit_code": exit_code},
        )
        self._evidence.append(evidence)
        return evidence

    def capture_screenshot(
        self,
        image_data: bytes,
        target: Optional[str] = None,
        event_id: Optional[UUID] = None,
    ) -> EvidenceItem:
        """Capture a screenshot."""
        evidence = EvidenceItem(
            evidence_type=EvidenceType.SCREENSHOT,
            event_id=event_id,
            target=target,
            metadata={"size": len(image_data)},
        )
        self._evidence.append(evidence)
        return evidence

    def capture_artifact(
        self,
        file_path: str,
        target: Optional[str] = None,
        event_id: Optional[UUID] = None,
    ) -> EvidenceItem:
        """Capture an artifact file."""
        evidence = EvidenceItem(
            evidence_type=EvidenceType.ARTIFACT,
            event_id=event_id,
            target=target,
            file_path=file_path,
        )
        self._evidence.append(evidence)
        return evidence

    def get_evidence(
        self,
        evidence_type: Optional[EvidenceType] = None,
        target: Optional[str] = None,
        event_id: Optional[UUID] = None,
    ) -> list[EvidenceItem]:
        """Get evidence items with optional filters."""
        results = self._evidence

        if evidence_type:
            results = [e for e in results if e.evidence_type == evidence_type]
        if target:
            results = [e for e in results if e.target == target]
        if event_id:
            results = [e for e in results if e.event_id == event_id]

        return results

    def get_timeline(self) -> list[EvidenceItem]:
        """Get evidence items in chronological order."""
        return sorted(self._evidence, key=lambda e: e.timestamp)

    def get_statistics(self) -> dict:
        """Get evidence statistics."""
        stats = {
            "total": len(self._evidence),
            "by_type": {},
            "by_target": {},
        }

        for evidence in self._evidence:
            # Count by type
            type_key = evidence.evidence_type.value
            stats["by_type"][type_key] = stats["by_type"].get(type_key, 0) + 1

            # Count by target
            if evidence.target:
                stats["by_target"][evidence.target] = stats["by_target"].get(evidence.target, 0) + 1

        return stats

    def export_index(self) -> dict:
        """Export evidence index."""
        return {
            "items": [
                {
                    "id": str(e.id),
                    "type": e.evidence_type.value,
                    "target": e.target,
                    "tool": e.tool,
                    "timestamp": e.timestamp.isoformat(),
                    "file_path": e.file_path,
                }
                for e in self._evidence
            ],
            "statistics": self.get_statistics(),
        }
