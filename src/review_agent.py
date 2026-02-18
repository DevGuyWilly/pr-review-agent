"""
Review Agent — Main Orchestrator
─────────────────────────────────
End-to-end pipeline: fetch PR → parse diffs → analyse →
generate comments → delegate if needed → post review.

Supports both live GitHub integration and dry-run/sample mode.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from .code_analyzer import CodeAnalyzer, compute_complexity_score
from .comment_formatter import (
    format_llm_comment,
    format_summary_comment,
    format_violation_comment,
)
from .diff_parser import parse_pr_files
from .github_client import GitHubClient
from .llm_reviewer import LLMReviewer
from .rules_engine import RulesEngine
from .refactoring_agent import RefactoringAgent
from .agent_coordinator import AgentCoordinator

load_dotenv()

logger = logging.getLogger(__name__)

# ── Logging Setup ─────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with console and file handlers."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(name)-24s | %(levelname)-7s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_DIR / "review_agent.log"),
        ],
    )


# ── Sample Data for Dry-Run ──────────────────────────────────────────────

SAMPLE_PR_FILES = [
    {
        "filename": "app/utils.py",
        "status": "modified",
        "additions": 25,
        "deletions": 5,
        "changes": 30,
        "patch": (
            "@@ -1,10 +1,35 @@\n"
            "+import os\n"
            "+import json\n"
            "+import sys\n"
            " import logging\n"
            " \n"
            "-logger = logging.getLogger(__name__)\n"
            "+PASSWORD = \"super_secret_123\"\n"
            "+api_key = \"sk-abc123def456ghi789\"\n"
            " \n"
            "+def processData(input_data, config, db, cache, logger, debug_mode):\n"
            "+    result = eval(input_data)\n"
            "+    if result:\n"
            "+        if config:\n"
            "+            if db:\n"
            "+                if cache:\n"
            "+                    data = cache.get(result)\n"
            "+                    if data:\n"
            "+                        return data\n"
            "+    print(result)\n"
            "+    return result\n"
            " \n"
            "+class my_class:\n"
            "+    def Calculate(self, x, y):\n"
            "+        return x + y\n"
            "+\n"
            "+def unused_function():\n"
            "+    # TODO: implement this properly\n"
            "+    pass\n"
        ),
        "sha": "abc123",
    }
]

SAMPLE_PR_METADATA = {
    "number": 42,
    "title": "Add utility functions",
    "body": "Adding new utility functions for data processing.",
    "state": "open",
    "author": "developer",
    "base_branch": "main",
    "head_branch": "feature/utils",
    "head_sha": "abc123def456",
    "created_at": "2025-01-15T10:00:00Z",
    "updated_at": "2025-01-15T12:00:00Z",
    "changed_files": 1,
    "additions": 25,
    "deletions": 5,
}

SAMPLE_SOURCE_CODE = '''import os
import json
import sys
import logging

PASSWORD = "super_secret_123"
api_key = "sk-abc123def456ghi789"

def processData(input_data, config, db, cache, logger, debug_mode):
    result = eval(input_data)
    if result:
        if config:
            if db:
                if cache:
                    data = cache.get(result)
                    if data:
                        return data
    print(result)
    return result

class my_class:
    def Calculate(self, x, y):
        return x + y

def unused_function():
    # TODO: implement this properly
    pass
'''


class ReviewAgent:
    """Main orchestrator for the code review pipeline."""

    def __init__(
        self,
        github_token: Optional[str] = None,
        config_path: Optional[str] = None,
        llm_provider: Optional[str] = None,
    ):
        """Initialise the review agent with GitHub credentials, rules, and analysers."""
        self.github_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self.rules_engine = RulesEngine(config_path)
        self.code_analyzer = CodeAnalyzer()
        self.llm_reviewer = None
        self.github_client = None
        self.coordinator = None


        # Initialise LLM reviewer (graceful fallback if no API key)
        try:
            self.llm_reviewer = LLMReviewer(provider=llm_provider)
        except Exception as exc:
            logger.warning("LLM reviewer unavailable: %s", exc)

        # Initialise GitHub client
        if self.github_token:
            try:
                self.github_client = GitHubClient(self.github_token)
            except Exception as exc:
                logger.warning("GitHub client unavailable: %s", exc)

        # Initialise multi-agent system
        refactoring_agent = RefactoringAgent(
            github_client=self.github_client,
            llm_reviewer=self.llm_reviewer,
        )
        self.coordinator = AgentCoordinator(
            refactoring_agent=refactoring_agent,
            delegation_config=self.rules_engine.delegation_config,
        )

    # ── Main Entry Points ─────────────────────────────────────────────────

    def review_pull_request(
        self, repo_full_name: str, pr_number: int, dry_run: bool = False
    ) -> dict:
        """
        Review a live GitHub PR end-to-end.
        If dry_run is True, fetches and analyses the PR but does not
        post comments or commit refactoring changes.
        Returns the full analysis result as a dict.
        """
        if not self.github_client:
            raise RuntimeError("GitHub client not initialised. Set GITHUB_TOKEN.")

        mode_label = " (dry-run)" if dry_run else ""
        logger.info("Starting review of %s#%d%s", repo_full_name, pr_number, mode_label)
        start_time = time.time()

        # 1. Fetch PR data
        pr = self.github_client.get_pull_request(repo_full_name, pr_number)
        pr_metadata = self.github_client.get_pr_metadata(pr)
        pr_files = self.github_client.get_pr_diff(pr)
        repo = self.github_client.get_repo(repo_full_name)

        # 2. Run analysis pipeline
        result = self._run_pipeline(
            pr_metadata=pr_metadata,
            pr_files=pr_files,
            repo=repo,
            head_ref=pr_metadata["head_sha"],
        )

        # 3. Post review to GitHub (skip in dry-run)
        if not dry_run:
            self._post_review(pr, pr_metadata, result)

        # 4. Handle delegations and commit refactoring changes (skip in dry-run)
        if not dry_run and result["delegation_actions"]:
            for handoff in self.coordinator.handoffs:
                if handoff.status.value == "completed":
                    self.coordinator.commit_handoff_changes(
                        handoff.handoff_id,
                        repo_full_name,
                        pr_metadata["head_branch"],
                    )

        elapsed = time.time() - start_time
        result["elapsed_seconds"] = round(elapsed, 2)

        # 5. Save results
        self._save_results(result, pr_number)

        # 6. Print summary
        self._print_summary(result)

        logger.info(
            "Review of %s#%d completed in %.1fs. "
            "Found %d issues.",
            repo_full_name, pr_number, elapsed, result["total_issues"],
        )
        return result

    def review_sample(self) -> dict:
        """
        Run the review pipeline on built-in sample data (dry-run mode).
        No GitHub API calls needed.
        """
        logger.info("Running sample review (dry-run mode).")
        start_time = time.time()

        result = self._run_pipeline(
            pr_metadata=SAMPLE_PR_METADATA,
            pr_files=SAMPLE_PR_FILES,
            sample_source=SAMPLE_SOURCE_CODE,
        )

        elapsed = time.time() - start_time
        result["elapsed_seconds"] = round(elapsed, 2)

        # Save results
        self._save_results(result, SAMPLE_PR_METADATA["number"])

        # Print summary
        self._print_summary(result)

        logger.info(
            "Sample review completed in %.1fs. Found %d issues.",
            elapsed, result["total_issues"],
        )
        return result

    # ── Analysis Pipeline ─────────────────────────────────────────────────

    def _run_pipeline(
        self,
        pr_metadata: dict,
        pr_files: list[dict],
        repo=None,
        head_ref: str = "",
        sample_source: Optional[str] = None,
    ) -> dict:
        """Core analysis pipeline shared by live and dry-run modes."""

        # Parse diffs
        file_diffs = parse_pr_files(pr_files)

        all_violations = []
        all_findings = []
        all_llm_comments = []
        delegation_actions = []
        position_maps: dict[str, dict[int, int]] = {}  # filename -> {line -> diff_position}

        for file_diff in file_diffs:
            if not file_diff.filename.endswith(".py"):
                continue

            # Get full file content
            if sample_source:
                source_code = sample_source
            elif repo and head_ref:
                source_code = self.github_client.get_file_content(
                    repo, file_diff.filename, head_ref
                )
                if not source_code:
                    continue
            else:
                continue

            changed_lines = file_diff.added_line_numbers
            position_maps[file_diff.filename] = file_diff.line_to_position_map

            # Step 1: Rules engine
            violations = self.rules_engine.apply_rules(
                file_diff.filename, source_code, changed_lines
            )
            violation_dicts = [v.to_dict() for v in violations]
            all_violations.extend(violation_dicts)

            # Step 2: Static analysis (AST + patterns)
            findings = self.code_analyzer.analyze_file(
                file_diff.filename, source_code, changed_lines
            )
            finding_dicts = [f.to_dict() for f in findings]
            all_findings.extend(finding_dicts)

            # Step 3: LLM semantic review
            if self.llm_reviewer:
                try:
                    llm_comments = self.llm_reviewer.review_code(
                        file_path=file_diff.filename,
                        source_code=source_code,
                        diff_content=pr_files[0].get("patch", ""),
                    )
                    llm_dicts = [c.to_dict() for c in llm_comments]
                    all_llm_comments.extend(llm_dicts)
                except Exception as exc:
                    logger.warning("LLM review skipped for %s: %s", file_diff.filename, exc)

            # Step 4: Check delegation criteria
            combined = violation_dicts + finding_dicts
            complexity = compute_complexity_score(source_code)

            if self.coordinator:
                should_delegate, reason = self.coordinator.should_delegate(
                    file_diff.filename, combined, complexity
                )
                if should_delegate:
                    logger.info(
                        "Delegating %s to refactoring agent: %s",
                        file_diff.filename, reason,
                    )
                    self.coordinator.initiate_handoff(
                        file_path=file_diff.filename,
                        source_code=source_code,
                        violations=combined,
                        complexity_score=complexity,
                        reason=reason,
                    )

        if self.coordinator:
            delegation_actions = self.coordinator.get_delegation_summary()

        # Mark which issues were resolved by the refactoring agent
        self._mark_resolved_issues(all_violations, all_findings, all_llm_comments)

        total_issues = len(all_violations) + len(all_findings) + len(all_llm_comments)
        resolved_count = sum(
            1 for item in all_violations + all_findings + all_llm_comments
            if item.get("resolved")
        )

        return {
            "pr_metadata": pr_metadata,
            "total_issues": total_issues,
            "resolved_issues": resolved_count,
            "unresolved_issues": total_issues - resolved_count,
            "violations": all_violations,
            "findings": all_findings,
            "llm_comments": all_llm_comments,
            "delegation_actions": delegation_actions,
            "coordinator_report": (
                self.coordinator.get_full_report() if self.coordinator else {}
            ),
            "position_maps": position_maps,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Resolution Tracking ────────────────────────────────────────────────

    def _mark_resolved_issues(
        self,
        violations: list[dict],
        findings: list[dict],
        llm_comments: list[dict],
    ) -> None:
        """
        Cross-reference refactoring agent actions with findings/violations
        and mark each item as resolved or unresolved.
        """
        if not self.coordinator:
            # No delegation happened — nothing can be resolved
            for item in violations + findings + llm_comments:
                item["resolved"] = False
            return

        # Collect descriptions of all successfully applied actions
        applied_descriptions: set[str] = set()
        applied_action_types: dict[str, str] = {}  # description -> action_type

        for handoff in self.coordinator.handoffs:
            for action_dict in handoff.actions:
                if action_dict.get("status") == "applied":
                    desc = action_dict.get("description", "")
                    applied_descriptions.add(desc)
                    applied_action_types[desc] = action_dict.get("action_type", "")

        # Mark each violation/finding
        for item in violations + findings:
            desc = item.get("description", "")
            if desc in applied_descriptions:
                item["resolved"] = True
                item["resolved_by"] = applied_action_types.get(desc, "refactoring_agent")
            else:
                item["resolved"] = False

        # LLM comments are never auto-resolved (they're advisory)
        for item in llm_comments:
            item["resolved"] = False

    # ── Post Review ───────────────────────────────────────────────────────

    def _post_review(self, pr, pr_metadata: dict, result: dict) -> None:
        """Format and post review comments to GitHub."""
        if not self.github_client:
            return

        position_maps = result.get("position_maps", {})
        inline_comments = []
        out_of_diff_comments = []

        # Format rule violations
        for v in result["violations"]:
            comment = format_violation_comment(v)
            file_map = position_maps.get(v["file_path"], {})
            line = v["line_number"]
            if line in file_map:
                comment["position"] = file_map[line]
                inline_comments.append(comment)
            else:
                out_of_diff_comments.append(comment)

        # Format static analysis findings as comments too
        for f in result["findings"]:
            comment = format_violation_comment(f)
            file_map = position_maps.get(f["file_path"], {})
            line = f["line_number"]
            if line in file_map:
                comment["position"] = file_map[line]
                inline_comments.append(comment)
            else:
                out_of_diff_comments.append(comment)

        # Format LLM comments
        for c in result["llm_comments"]:
            comment = format_llm_comment(c)
            file_map = position_maps.get(c["file_path"], {})
            line = c["line_number"]
            if line in file_map:
                comment["position"] = file_map[line]
                inline_comments.append(comment)
            else:
                out_of_diff_comments.append(comment)

        # Build the out-of-diff section for the summary
        out_of_diff_section = ""
        if out_of_diff_comments:
            out_of_diff_section = (
                f"\n\n---\n\n### 📌 Additional Findings (outside diff)\n\n"
                + "\n".join(
                    f"- **{c['path']}** (line {c['line']}): "
                    + c['body'].split('\n')[0]
                    for c in out_of_diff_comments
                )
            )

        # Generate summary
        summary = format_summary_comment(
            pr_metadata=pr_metadata,
            all_violations=result["violations"],
            all_llm_comments=result["llm_comments"],
            all_findings=result["findings"],
            delegation_actions=result["delegation_actions"],
        ) + out_of_diff_section

        # Post to GitHub
        self.github_client.post_review_comments(pr, inline_comments, summary)

    # ── Output & Logging ──────────────────────────────────────────────────

    def _save_results(self, result: dict, pr_number: int) -> None:
        """Save results to JSON and JSONL files."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Full JSON result (strip internal position_maps)
        save_result = {k: v for k, v in result.items() if k != "position_maps"}
        json_path = LOG_DIR / f"review_pr{pr_number}_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(save_result, f, indent=2, default=str)
        logger.info("Saved full results to %s.", json_path)

        # JSONL log (one line per finding)
        jsonl_path = LOG_DIR / f"review_pr{pr_number}_{timestamp}.jsonl"
        with open(jsonl_path, "w") as f:
            for v in result["violations"]:
                entry = {**v, "source": "rules_engine", "timestamp": result["timestamp"]}
                f.write(json.dumps(entry, default=str) + "\n")
            for finding in result["findings"]:
                entry = {**finding, "source": "static_analysis", "timestamp": result["timestamp"]}
                f.write(json.dumps(entry, default=str) + "\n")
            for c in result["llm_comments"]:
                entry = {**c, "source": "llm_review", "timestamp": result["timestamp"]}
                f.write(json.dumps(entry, default=str) + "\n")
        logger.info("Saved JSONL log to %s.", jsonl_path)

    def _print_summary(self, result: dict) -> None:
        """Print a human-readable summary to stdout."""
        print("\n" + "=" * 70)
        print("  CODE REVIEW AGENT — ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"\n  PR: #{result['pr_metadata']['number']} — {result['pr_metadata']['title']}")
        print(f"  Total Issues: {result['total_issues']}")
        resolved = result.get("resolved_issues", 0)
        unresolved = result.get("unresolved_issues", result["total_issues"])
        print(f"  ✅ Resolved: {resolved}  |  ❌ Unresolved: {unresolved}")
        print(f"  Elapsed: {result.get('elapsed_seconds', 0):.1f}s")

        print(f"\n  📋 Rule Violations: {len(result['violations'])}")
        for v in result["violations"]:
            sev = v["severity"].upper().ljust(8)
            tag = "✅" if v.get("resolved") else "❌"
            print(f"     {tag} [{sev}] {v['file_path']}:{v['line_number']} — {v['description']}")

        print(f"\n  🔍 Static Analysis: {len(result['findings'])}")
        for f in result["findings"]:
            sev = f["severity"].upper().ljust(8)
            tag = "✅" if f.get("resolved") else "❌"
            print(f"     {tag} [{sev}] {f['file_path']}:{f['line_number']} — {f['description']}")

        if result["llm_comments"]:
            print(f"\n  🤖 AI Review: {len(result['llm_comments'])}")
            for c in result["llm_comments"]:
                sev = c["severity"].upper().ljust(8)
                print(f"     [{sev}] {c['file_path']}:{c['line_number']} — {c['problem']}")

        if result["delegation_actions"]:
            print(f"\n  🤝 Delegations: {len(result['delegation_actions'])}")
            for d in result["delegation_actions"]:
                print(f"     {d['file']} — {d['status']}")

        print("\n" + "=" * 70 + "\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────

def main():
    """CLI entry point — parse arguments and run a review or start the server."""
    parser = argparse.ArgumentParser(
        description="Automated Code Review Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run with sample data (no API keys needed):
  python -m src.review_agent --dry-run --sample

  # Review a real PR:
  python -m src.review_agent --repo owner/repo --pr 42
        """,
    )
    parser.add_argument("--repo", help="GitHub repo (owner/repo)")
    parser.add_argument("--pr", type=int, help="PR number")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run without posting to GitHub",
    )
    parser.add_argument(
        "--sample", action="store_true",
        help="Use built-in sample data",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to coding standards YAML config",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    agent = ReviewAgent(config_path=args.config)

    if args.repo and args.pr:
        if args.dry_run:
            # Fetch and analyse the real PR but don't post comments
            result = agent.review_pull_request(args.repo, args.pr, dry_run=True)
        else:
            result = agent.review_pull_request(args.repo, args.pr)
    elif args.sample or args.dry_run:
        # Use built-in sample data
        result = agent.review_sample()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
