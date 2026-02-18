"""
Refactoring Agent
──────────────────
A specialised agent that receives delegation from the code review
agent and applies automated refactoring fixes to source code.
Commits changes back to the PR branch with explanatory comments.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RefactorAction:
    """A single refactoring action to apply."""
    action_type: str        # extract_method, rename_variable, simplify_conditional, general
    file_path: str
    description: str
    original_code: str = ""
    refactored_code: str = ""
    status: str = "pending"  # pending, applied, failed
    commit_sha: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        """Serialise the action to a plain dictionary for JSON output."""
        return {
            "action_type": self.action_type,
            "file_path": self.file_path,
            "description": self.description,
            "status": self.status,
            "commit_sha": self.commit_sha,
            "error": self.error,
        }


@dataclass
class DelegationRequest:
    """A request from the review agent to the refactoring agent."""
    file_path: str
    source_code: str
    violations: list[dict]
    complexity_score: int = 0
    priority: str = "normal"  # low, normal, high, critical

    def to_dict(self) -> dict:
        """Serialise the request to a plain dictionary for logging."""
        return {
            "file_path": self.file_path,
            "violation_count": len(self.violations),
            "complexity_score": self.complexity_score,
            "priority": self.priority,
        }


class RefactoringAgent:
    """
    Applies automated refactoring based on delegation from the review agent.
    Supports: extract methods, rename variables, simplify conditionals.
    """

    def __init__(self, github_client=None, llm_reviewer=None):
        """Initialise with optional GitHub client (for commits) and LLM reviewer."""
        self.github_client = github_client
        self.llm_reviewer = llm_reviewer
        self.actions_taken: list[RefactorAction] = []

    def process_delegation(self, request: DelegationRequest) -> list[RefactorAction]:
        """
        Process a delegation request and apply refactoring actions.
        Returns a list of actions taken.
        """
        logger.info(
            "Refactoring agent received delegation for %s "
            "(%d violations, complexity=%d).",
            request.file_path,
            len(request.violations),
            request.complexity_score,
        )

        actions = []

        # Categorise violations and determine refactoring strategy
        for violation in request.violations:
            action = self._determine_action(violation, request.source_code)
            if action:
                actions.append(action)

        # Apply refactoring (using LLM if available, AST transforms otherwise)
        applied_actions = self._apply_refactoring(
            request.file_path, request.source_code, actions
        )

        self.actions_taken.extend(applied_actions)
        return applied_actions

    def _determine_action(
        self, violation: dict, source_code: str
    ) -> Optional[RefactorAction]:
        """Map a violation to a refactoring action type."""
        rule_name = violation.get("rule_name", "")
        severity = violation.get("severity", "info")

        # Only refactor for serious issues
        if severity not in ("critical", "error", "warning"):
            return None

        action_mapping = {
            "function_complexity": "extract_method",
            "naming_conventions": "rename_variable",
            "no_dangerous_functions": "general",
            "unused_imports": "remove_code",
            "no_hardcoded_secrets": "general",
        }

        action_type = action_mapping.get(rule_name, "general")

        return RefactorAction(
            action_type=action_type,
            file_path=violation.get("file_path", ""),
            description=violation.get("description", ""),
        )

    def _apply_refactoring(
        self,
        file_path: str,
        source_code: str,
        actions: list[RefactorAction],
    ) -> list[RefactorAction]:
        """Apply refactoring actions to the source code."""
        if not actions:
            return []

        current_code = source_code
        applied = []

        for action in actions:
            try:
                if action.action_type == "remove_code":
                    new_code = self._remove_unused_imports(current_code, action)
                elif action.action_type == "rename_variable":
                    new_code = self._fix_naming(current_code, action)
                elif action.action_type == "extract_method":
                    new_code = self._try_llm_refactor(
                        file_path, current_code, action
                    )
                else:
                    new_code = self._try_llm_refactor(
                        file_path, current_code, action
                    )

                if new_code and new_code != current_code:
                    action.original_code = current_code
                    action.refactored_code = new_code
                    action.status = "applied"
                    current_code = new_code
                    applied.append(action)
                    logger.info(
                        "Applied %s refactoring: %s",
                        action.action_type, action.description,
                    )
                else:
                    action.status = "skipped"
                    action.error = "No changes produced."

            except Exception as exc:
                action.status = "failed"
                action.error = str(exc)
                logger.error(
                    "Refactoring failed for %s: %s", action.action_type, exc
                )

        return applied

    # ── Refactoring Strategies ────────────────────────────────────────────

    def _remove_unused_imports(
        self, source_code: str, action: RefactorAction
    ) -> Optional[str]:
        """Remove unused import lines identified in the violation."""
        lines = source_code.split("\n")
        # Extract the import name from the description
        match = re.search(r"Import '(\w+)' appears to be unused", action.description)
        if not match:
            return None

        import_name = match.group(1)
        new_lines = []
        for line in lines:
            # Check if this line imports the unused name
            if re.match(
                rf"^\s*(from\s+\S+\s+)?import\s+.*\b{re.escape(import_name)}\b",
                line,
            ):
                # If it's a multi-import line, only remove the specific name
                if "," in line:
                    parts = line.split("import")
                    if len(parts) == 2:
                        imports = [
                            i.strip()
                            for i in parts[1].split(",")
                            if i.strip() and i.strip().split(" as ")[0].strip().split(".")[-1] != import_name
                        ]
                        if imports:
                            new_lines.append(f"{parts[0]}import {', '.join(imports)}")
                            continue
                # Skip the entire import line
                continue
            new_lines.append(line)

        return "\n".join(new_lines)

    def _fix_naming(
        self, source_code: str, action: RefactorAction
    ) -> Optional[str]:
        """Fix naming convention violations."""
        match = re.search(
            r"(?:Function|Variable) '(\w+)' does not follow snake_case",
            action.description,
        )
        if not match:
            return None

        old_name = match.group(1)
        new_name = self._to_snake_case(old_name)
        if old_name == new_name:
            return None

        # Replace all occurrences of the name in the source
        new_code = re.sub(rf"\b{re.escape(old_name)}\b", new_name, source_code)
        return new_code

    def _try_llm_refactor(
        self,
        file_path: str,
        source_code: str,
        action: RefactorAction,
    ) -> Optional[str]:
        """Attempt LLM-powered refactoring for complex changes."""
        if not self.llm_reviewer:
            logger.info(
                "LLM not available for refactoring; skipping %s.",
                action.action_type,
            )
            return None

        issues = [{"description": action.description, "type": action.action_type}]
        result = self.llm_reviewer.generate_refactoring(
            file_path, source_code, issues
        )

        if result and "refactored_code" in result:
            # Validate refactored code parses correctly
            try:
                ast.parse(result["refactored_code"])
                return result["refactored_code"]
            except SyntaxError:
                logger.warning("LLM refactored code has syntax errors; discarding.")
                return None

        return None

    def commit_changes(
        self,
        repo_full_name: str,
        branch: str,
        actions: list[RefactorAction],
    ) -> list[str]:
        """
        Commit refactored files back to the PR branch.
        Groups all actions per file into a single commit to avoid SHA conflicts.
        Returns list of commit SHAs.
        """
        if not self.github_client:
            logger.warning("No GitHub client; skipping commit.")
            return []

        repo = self.github_client.get_repo(repo_full_name)
        commit_shas = []

        # Group actions by file — use the LAST applied action's code
        # (it contains the cumulative result of all fixes)
        files_to_commit: dict[str, tuple[str, str, list[str]]] = {}
        for action in actions:
            if action.status != "applied" or not action.refactored_code:
                continue
            # Each subsequent action's refactored_code builds on the previous one,
            # so the last one has all changes applied.
            existing = files_to_commit.get(action.file_path, (None, action.original_code, []))
            descriptions = existing[2]
            descriptions.append(f"  - {action.action_type}: {action.description}")
            files_to_commit[action.file_path] = (action.refactored_code, existing[1] or action.original_code, descriptions)

        for file_path, (final_code, original_code, descriptions) in files_to_commit.items():
            # ── Safety check: don't commit obviously corrupted content ────
            if len(final_code.strip()) < 50:
                logger.warning(
                    "Skipping commit for %s: refactored code too short (%d chars).",
                    file_path, len(final_code),
                )
                continue
            if final_code.strip().count("\n") < 3:
                logger.warning(
                    "Skipping commit for %s: refactored code has too few lines.",
                    file_path,
                )
                continue
            if original_code and len(final_code) < len(original_code) * 0.3:
                logger.warning(
                    "Skipping commit for %s: refactored code is suspiciously "
                    "smaller (%d → %d chars).",
                    file_path, len(original_code), len(final_code),
                )
                continue


            try:
                message = (
                    f"refactor: automated fixes for {file_path}\n\n"
                    + "\n".join(descriptions)
                    + "\n\nApplied by Code Review Refactoring Agent."
                )
                sha = self.github_client.commit_file_change(
                    repo=repo,
                    path=file_path,
                    new_content=final_code,
                    commit_message=message,
                    branch=branch,
                )
                # Mark all actions for this file with the commit SHA
                for action in actions:
                    if action.file_path == file_path and action.status == "applied":
                        action.commit_sha = sha
                commit_shas.append(sha)
                logger.info("Committed %d fixes to %s.", len(descriptions), file_path)
            except Exception as exc:
                for action in actions:
                    if action.file_path == file_path:
                        action.status = "commit_failed"
                        action.error = str(exc)
                logger.error("Failed to commit %s: %s", file_path, exc)

        return commit_shas

    def get_summary(self) -> dict:
        """Return a summary of all actions taken."""
        return {
            "total_actions": len(self.actions_taken),
            "applied": sum(1 for a in self.actions_taken if a.status == "applied"),
            "failed": sum(1 for a in self.actions_taken if a.status == "failed"),
            "skipped": sum(1 for a in self.actions_taken if a.status == "skipped"),
            "actions": [a.to_dict() for a in self.actions_taken],
        }

    @staticmethod
    def _to_snake_case(name: str) -> str:
        """Convert a CamelCase or mixedCase name to snake_case."""
        s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
        s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
        return s.lower()
