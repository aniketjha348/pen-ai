"""Objective Tracker - Tracks objectives and flags throughout the engagement."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4


class ObjectiveStatus(str, Enum):
    """Status of an objective."""

    DISCOVERED = "discovered"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Objective:
    """An objective to complete."""

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: Optional[str] = None
    target: Optional[str] = None
    requirement: Optional[str] = None
    access_required: str = "user"  # none, user, admin, system
    status: ObjectiveStatus = ObjectiveStatus.DISCOVERED
    flag: Optional[str] = None
    flag_validated: bool = False
    evidence_events: list[UUID] = field(default_factory=list)
    completed_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ObjectiveTracker:
    """Tracks objectives and flags throughout the engagement."""

    def __init__(self):
        self._objectives: list[Objective] = []

    def add_objective(
        self,
        name: str,
        description: Optional[str] = None,
        target: Optional[str] = None,
        requirement: Optional[str] = None,
        access_required: str = "user",
    ) -> Objective:
        """Add a new objective."""
        objective = Objective(
            name=name,
            description=description,
            target=target,
            requirement=requirement,
            access_required=access_required,
        )
        self._objectives.append(objective)
        return objective

    def start_objective(self, objective_id: UUID) -> bool:
        """Mark an objective as in progress."""
        for obj in self._objectives:
            if obj.id == objective_id and obj.status == ObjectiveStatus.DISCOVERED:
                obj.status = ObjectiveStatus.IN_PROGRESS
                return True
        return False

    def complete_objective(
        self,
        objective_id: UUID,
        flag: Optional[str] = None,
        validate: bool = True,
    ) -> bool:
        """Mark an objective as completed."""
        for obj in self._objectives:
            if obj.id == objective_id:
                obj.status = ObjectiveStatus.COMPLETED
                obj.completed_at = datetime.utcnow()
                if flag:
                    obj.flag = flag
                    if validate:
                        obj.flag_validated = self._validate_flag(flag)
                return True
        return False

    def fail_objective(self, objective_id: UUID) -> bool:
        """Mark an objective as failed."""
        for obj in self._objectives:
            if obj.id == objective_id:
                obj.status = ObjectiveStatus.FAILED
                return True
        return False

    def add_evidence(self, objective_id: UUID, event_id: UUID) -> bool:
        """Add evidence event to an objective."""
        for obj in self._objectives:
            if obj.id == objective_id:
                obj.evidence_events.append(event_id)
                return True
        return False

    def _validate_flag(self, flag: str) -> bool:
        """Validate a flag format."""
        import re
        # Common flag formats
        patterns = [
            r"flag\{.*\}",
            r"FLAG\{.*\}",
            r"[A-Za-z0-9]{32}",
            r"[A-F0-9]{32}",
        ]
        return any(re.match(p, flag) for p in patterns)

    def get_objectives(
        self,
        status: Optional[ObjectiveStatus] = None,
    ) -> list[Objective]:
        """Get objectives with optional status filter."""
        if status:
            return [o for o in self._objectives if o.status == status]
        return self._objectives.copy()

    def get_completed(self) -> list[Objective]:
        """Get completed objectives."""
        return self.get_objectives(ObjectiveStatus.COMPLETED)

    def get_pending(self) -> list[Objective]:
        """Get pending objectives."""
        return [
            o for o in self._objectives
            if o.status in [ObjectiveStatus.DISCOVERED, ObjectiveStatus.IN_PROGRESS]
        ]

    def get_statistics(self) -> dict:
        """Get objective statistics."""
        return {
            "total": len(self._objectives),
            "completed": len(self.get_completed()),
            "in_progress": len(self.get_objectives(ObjectiveStatus.IN_PROGRESS)),
            "failed": len(self.get_objectives(ObjectiveStatus.FAILED)),
            "pending": len(self.get_objectives(ObjectiveStatus.DISCOVERED)),
        }

    def to_report_format(self) -> list[dict]:
        """Convert objectives to report format."""
        return [
            {
                "id": str(o.id),
                "name": o.name,
                "description": o.description,
                "target": o.target,
                "status": o.status.value,
                "flag": o.flag,
                "flag_validated": o.flag_validated,
                "completed_at": o.completed_at.isoformat() if o.completed_at else None,
            }
            for o in self._objectives
        ]
