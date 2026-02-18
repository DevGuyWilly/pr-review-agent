"""
Agent Coordinator
──────────────────
Multi-agent handoff and delegation system.
Manages communication between the review agent and refactoring agent,
tracks state across handoffs, and enforces delegation criteria.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .refactoring_agent import DelegationRequest, RefactoringAgent, RefactorAction

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    REVIEWER = "reviewer"
    REFACTORER = "refactorer"
    COORDINATOR = "coordinator"


class HandoffStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class AgentMessage:
    """Structured message for inter-agent communication."""
    sender: AgentRole
    receiver: AgentRole
    message_type: str       # delegation_request, delegation_result, status_update
    payload: dict
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "sender": self.sender.value,
            "receiver": self.receiver.value,
            "message_type": self.message_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }


@dataclass
class HandoffRecord:
    """Tracks a single delegation handoff."""
    handoff_id: str
    file_path: str
    reason: str
    status: HandoffStatus = HandoffStatus.PENDING
    violations: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    commit_shas: list[str] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "handoff_id": self.handoff_id,
            "file_path": self.file_path,
            "reason": self.reason,
            "status": self.status.value,
            "violation_count": len(self.violations),
            "action_count": len(self.actions),
            "commit_shas": self.commit_shas,
            "duration_seconds": (
                self.completed_at - self.started_at if self.completed_at else 0
            ),
            "error": self.error,
        }


class AgentCoordinator:
    """
    Orchestrates multi-agent workflow between the review agent
    and refactoring agent. Manages handoffs, state, and communication.
    """

    def __init__(
        self,
        refactoring_agent: RefactoringAgent,
        delegation_config: Optional[dict] = None,
    ):
        self.refactoring_agent = refactoring_agent
        self.delegation_config = delegation_config or {}
        self.message_log: list[AgentMessage] = []
        self.handoffs: list[HandoffRecord] = []
        self._handoff_counter = 0

    # ── Delegation Criteria ───────────────────────────────────────────────

    def should_delegate(
        self,
        file_path: str,
        violations: list[dict],
        complexity_score: int = 0,
    ) -> tuple[bool, str]:
        """
        Evaluate whether a file should be delegated to the refactoring agent.
        Returns (should_delegate, reason).
        """
        if not self.delegation_config.get("enabled", False):
            return False, "Delegation disabled."

        max_violations = self.delegation_config.get("max_violations_per_file", 3)
        min_complexity = self.delegation_config.get("min_complexity_for_refactor", 10)
        auto_severities = set(
            self.delegation_config.get("auto_refactor_severities", [])
        )

        # Check: too many violations in one file
        file_violations = [v for v in violations if v.get("file_path") == file_path]
        if len(file_violations) > max_violations:
            return True, (
                f"File has {len(file_violations)} violations "
                f"(threshold: {max_violations})."
            )

        # Check: critical/error severity violations
        for v in file_violations:
            if v.get("severity") in auto_severities:
                return True, (
                    f"Violation with '{v['severity']}' severity detected: "
                    f"{v.get('description', '')[:80]}"
                )

        # Check: high complexity score
        if complexity_score > min_complexity:
            return True, (
                f"Complexity score {complexity_score} exceeds "
                f"threshold {min_complexity}."
            )

        return False, "Does not meet delegation criteria."

    # ── Handoff Management ────────────────────────────────────────────────

    def initiate_handoff(
        self,
        file_path: str,
        source_code: str,
        violations: list[dict],
        complexity_score: int = 0,
        reason: str = "",
    ) -> HandoffRecord:
        """
        Initiate a handoff from the review agent to the refactoring agent.
        """
        self._handoff_counter += 1
        handoff_id = f"handoff-{self._handoff_counter:04d}"

        record = HandoffRecord(
            handoff_id=handoff_id,
            file_path=file_path,
            reason=reason,
            violations=violations,
            started_at=time.time(),
        )
        self.handoffs.append(record)

        # Send delegation message
        self._send_message(AgentMessage(
            sender=AgentRole.COORDINATOR,
            receiver=AgentRole.REFACTORER,
            message_type="delegation_request",
            payload={
                "handoff_id": handoff_id,
                "file_path": file_path,
                "violation_count": len(violations),
                "complexity_score": complexity_score,
                "reason": reason,
            },
        ))

        # Execute delegation
        try:
            record.status = HandoffStatus.IN_PROGRESS

            request = DelegationRequest(
                file_path=file_path,
                source_code=source_code,
                violations=violations,
                complexity_score=complexity_score,
                priority=self._determine_priority(violations),
            )

            actions = self.refactoring_agent.process_delegation(request)
            record.actions = [a.to_dict() for a in actions]
            record.status = HandoffStatus.COMPLETED
            record.completed_at = time.time()

            # Send result message
            self._send_message(AgentMessage(
                sender=AgentRole.REFACTORER,
                receiver=AgentRole.COORDINATOR,
                message_type="delegation_result",
                payload={
                    "handoff_id": handoff_id,
                    "actions_applied": sum(1 for a in actions if a.status == "applied"),
                    "actions_failed": sum(1 for a in actions if a.status == "failed"),
                },
            ))

            logger.info(
                "Handoff %s completed: %d actions applied.",
                handoff_id,
                sum(1 for a in actions if a.status == "applied"),
            )
            return record

        except Exception as exc:
            record.status = HandoffStatus.FAILED
            record.error = str(exc)
            record.completed_at = time.time()
            logger.error("Handoff %s failed: %s", handoff_id, exc)
            return record

    def commit_handoff_changes(
        self,
        handoff_id: str,
        repo_full_name: str,
        branch: str,
    ) -> list[str]:
        """Commit the changes from a completed handoff."""
        record = self._get_handoff(handoff_id)
        if not record:
            logger.error("Handoff %s not found.", handoff_id)
            return []

        if record.status != HandoffStatus.COMPLETED:
            logger.warning(
                "Cannot commit handoff %s with status %s.",
                handoff_id, record.status.value,
            )
            return []

        applied = [
            a for a in self.refactoring_agent.actions_taken
            if a.status == "applied" and a.file_path == record.file_path
        ]

        shas = self.refactoring_agent.commit_changes(
            repo_full_name, branch, applied
        )
        record.commit_shas = shas
        return shas

    # ── State & Reporting ─────────────────────────────────────────────────

    def get_delegation_summary(self) -> list[dict]:
        """
        Return summary of all delegation actions for the PR summary comment.
        """
        return [
            {
                "file": h.file_path,
                "action": h.reason,
                "status": h.status.value,
                "actions_count": len(h.actions),
            }
            for h in self.handoffs
        ]

    def get_full_report(self) -> dict:
        """Generate a full report of all coordinator activity."""
        return {
            "total_handoffs": len(self.handoffs),
            "completed": sum(
                1 for h in self.handoffs if h.status == HandoffStatus.COMPLETED
            ),
            "failed": sum(
                1 for h in self.handoffs if h.status == HandoffStatus.FAILED
            ),
            "handoffs": [h.to_dict() for h in self.handoffs],
            "message_log": [m.to_dict() for m in self.message_log],
        }

    # ── Internal ──────────────────────────────────────────────────────────

    def _send_message(self, message: AgentMessage) -> None:
        """Log an agent-to-agent message."""
        self.message_log.append(message)
        logger.debug(
            "Agent message: %s → %s (%s)",
            message.sender.value,
            message.receiver.value,
            message.message_type,
        )

    def _get_handoff(self, handoff_id: str) -> Optional[HandoffRecord]:
        for h in self.handoffs:
            if h.handoff_id == handoff_id:
                return h
        return None

    def _determine_priority(self, violations: list[dict]) -> str:
        """Determine delegation priority based on violation severities."""
        severities = {v.get("severity", "info") for v in violations}
        if "critical" in severities:
            return "critical"
        elif "error" in severities:
            return "high"
        elif "warning" in severities:
            return "normal"
        return "low"
