"""
Diff Parser
────────────
Parses unified diffs from GitHub PRs to extract:
  - Changed files and their modification types
  - Code hunks with line number mappings
  - Individual changed lines with position tracking
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ModificationType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class LineChangeType(str, Enum):
    ADDITION = "addition"
    DELETION = "deletion"
    CONTEXT = "context"


@dataclass
class ChangedLine:
    """A single changed line within a hunk."""
    content: str
    old_line_number: Optional[int]
    new_line_number: Optional[int]
    change_type: LineChangeType
    diff_position: int  # Position within the diff (for GitHub comment API)


@dataclass
class DiffHunk:
    """A contiguous block of changes within a file."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: list[ChangedLine] = field(default_factory=list)

    @property
    def added_lines(self) -> list[ChangedLine]:
        return [l for l in self.lines if l.change_type == LineChangeType.ADDITION]

    @property
    def deleted_lines(self) -> list[ChangedLine]:
        return [l for l in self.lines if l.change_type == LineChangeType.DELETION]


@dataclass
class FileDiff:
    """Parsed diff for a single file."""
    filename: str
    modification_type: ModificationType
    additions: int
    deletions: int
    hunks: list[DiffHunk] = field(default_factory=list)
    previous_filename: Optional[str] = None
    sha: Optional[str] = None

    @property
    def total_changes(self) -> int:
        return self.additions + self.deletions

    @property
    def added_line_numbers(self) -> list[int]:
        """All new-side line numbers that were added."""
        result = []
        for hunk in self.hunks:
            for line in hunk.added_lines:
                if line.new_line_number is not None:
                    result.append(line.new_line_number)
        return result

    @property
    def line_to_position_map(self) -> dict[int, int]:
        """
        Map from new-side absolute line numbers to diff positions.
        Includes both added and context lines (any line visible in the diff).
        This is what GitHub's review API requires for inline comments.
        """
        mapping = {}
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.new_line_number is not None:
                    mapping[line.new_line_number] = line.diff_position
        return mapping


# ── Hunk header regex ─────────────────────────────────────────────────────
HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)


def parse_pr_files(pr_files: list[dict]) -> list[FileDiff]:
    """
    Parse a list of PR file dicts (from GitHubClient.get_pr_diff())
    into structured FileDiff objects.
    """
    diffs = []
    for file_data in pr_files:
        mod_type = _classify_modification(file_data.get("status", "modified"))
        file_diff = FileDiff(
            filename=file_data["filename"],
            modification_type=mod_type,
            additions=file_data.get("additions", 0),
            deletions=file_data.get("deletions", 0),
            previous_filename=file_data.get("previous_filename"),
            sha=file_data.get("sha"),
        )

        patch = file_data.get("patch", "")
        if patch:
            file_diff.hunks = _parse_patch(patch)

        diffs.append(file_diff)
        logger.debug(
            "Parsed %s: %s (+%d/-%d), %d hunks",
            mod_type.value,
            file_diff.filename,
            file_diff.additions,
            file_diff.deletions,
            len(file_diff.hunks),
        )

    logger.info("Parsed %d file diffs.", len(diffs))
    return diffs


def _parse_patch(patch: str) -> list[DiffHunk]:
    """Parse a unified diff patch string into DiffHunk objects."""
    hunks: list[DiffHunk] = []
    current_hunk: Optional[DiffHunk] = None
    diff_position = 0  # 1-indexed position within the entire patch

    for raw_line in patch.split("\n"):
        diff_position += 1

        # Check for hunk header
        match = HUNK_HEADER_RE.match(raw_line)
        if match:
            current_hunk = DiffHunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or "1"),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or "1"),
                header=raw_line,
            )
            hunks.append(current_hunk)
            old_line = current_hunk.old_start
            new_line = current_hunk.new_start
            continue

        if current_hunk is None:
            continue

        if raw_line.startswith("+"):
            current_hunk.lines.append(ChangedLine(
                content=raw_line[1:],
                old_line_number=None,
                new_line_number=new_line,
                change_type=LineChangeType.ADDITION,
                diff_position=diff_position,
            ))
            new_line += 1
        elif raw_line.startswith("-"):
            current_hunk.lines.append(ChangedLine(
                content=raw_line[1:],
                old_line_number=old_line,
                new_line_number=None,
                change_type=LineChangeType.DELETION,
                diff_position=diff_position,
            ))
            old_line += 1
        elif raw_line.startswith(" ") or raw_line == "":
            content = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current_hunk.lines.append(ChangedLine(
                content=content,
                old_line_number=old_line,
                new_line_number=new_line,
                change_type=LineChangeType.CONTEXT,
                diff_position=diff_position,
            ))
            old_line += 1
            new_line += 1

    return hunks


def _classify_modification(status: str) -> ModificationType:
    """Map GitHub file status to our ModificationType enum."""
    mapping = {
        "added": ModificationType.ADDED,
        "modified": ModificationType.MODIFIED,
        "removed": ModificationType.DELETED,
        "renamed": ModificationType.RENAMED,
    }
    return mapping.get(status, ModificationType.MODIFIED)


def get_changed_code_context(
    file_diff: FileDiff, context_lines: int = 3
) -> list[dict]:
    """
    Extract changed code segments with surrounding context
    for feeding into analysis engines.
    """
    segments = []
    for hunk in file_diff.hunks:
        added = []
        for line in hunk.lines:
            if line.change_type == LineChangeType.ADDITION:
                added.append({
                    "content": line.content,
                    "line_number": line.new_line_number,
                    "diff_position": line.diff_position,
                })

        if added:
            segments.append({
                "file": file_diff.filename,
                "hunk_header": hunk.header,
                "old_start": hunk.old_start,
                "new_start": hunk.new_start,
                "added_lines": added,
                "full_hunk": "\n".join(l.content for l in hunk.lines),
            })

    return segments
