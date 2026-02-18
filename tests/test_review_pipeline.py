"""
Test Suite — Code Review Pipeline
───────────────────────────────────
End-to-end and unit tests for the review agent system.
"""

import json
import os
import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.diff_parser import parse_pr_files, FileDiff, LineChangeType
from src.rules_engine import RulesEngine, Violation
from src.code_analyzer import CodeAnalyzer, compute_complexity_score
from src.comment_formatter import (
    format_inline_comment,
    format_violation_comment,
    format_summary_comment,
)
from src.refactoring_agent import RefactoringAgent, DelegationRequest
from src.agent_coordinator import AgentCoordinator


# ── Sample Data ───────────────────────────────────────────────────────────

SAMPLE_PATCH = (
    "@@ -1,5 +1,15 @@\n"
    "+import os\n"
    "+import json\n"
    " import logging\n"
    " \n"
    "+PASSWORD = \"super_secret_123\"\n"
    "+\n"
    "+def processData(data):\n"
    "+    result = eval(data)\n"
    "+    return result\n"
)

SAMPLE_PR_FILE = {
    "filename": "app/utils.py",
    "status": "modified",
    "additions": 8,
    "deletions": 0,
    "changes": 8,
    "patch": SAMPLE_PATCH,
    "sha": "abc123",
}

SAMPLE_SOURCE = '''import os
import json
import logging

PASSWORD = "super_secret_123"

def processData(data):
    result = eval(data)
    return result
'''

SAMPLE_COMPLEX_SOURCE = '''import os
import sys
import json
import logging
import re

def process_all_data(data, config, db, cache, logger, metrics):
    """Process data with many branches."""
    if data:
        if config.get("enabled"):
            for item in data:
                if item.get("type") == "A":
                    if item.get("status") == "active":
                        while not cache.get(item["id"]):
                            try:
                                result = db.query(item["id"])
                                if result and result.valid:
                                    if result.score > 0.5 or result.priority == "high":
                                        cache.set(item["id"], result)
                                    else:
                                        logger.warning("Low score")
                                elif not result:
                                    raise ValueError("Missing data")
                            except Exception:
                                pass
    return None
'''


class TestDiffParser(unittest.TestCase):
    """Tests for the diff parser module."""

    def test_parse_pr_files(self):
        diffs = parse_pr_files([SAMPLE_PR_FILE])
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].filename, "app/utils.py")
        self.assertEqual(diffs[0].modification_type.value, "modified")

    def test_hunk_parsing(self):
        diffs = parse_pr_files([SAMPLE_PR_FILE])
        self.assertGreater(len(diffs[0].hunks), 0)
        hunk = diffs[0].hunks[0]
        self.assertGreater(len(hunk.lines), 0)

    def test_added_lines(self):
        diffs = parse_pr_files([SAMPLE_PR_FILE])
        hunk = diffs[0].hunks[0]
        added = [l for l in hunk.lines if l.change_type == LineChangeType.ADDITION]
        self.assertGreater(len(added), 0)

    def test_line_numbers(self):
        diffs = parse_pr_files([SAMPLE_PR_FILE])
        added_lines = diffs[0].added_line_numbers
        self.assertIsInstance(added_lines, list)
        for ln in added_lines:
            self.assertIsInstance(ln, int)
            self.assertGreater(ln, 0)

    def test_empty_patch(self):
        file_data = {**SAMPLE_PR_FILE, "patch": ""}
        diffs = parse_pr_files([file_data])
        self.assertEqual(len(diffs[0].hunks), 0)


class TestRulesEngine(unittest.TestCase):
    """Tests for the rules engine module."""

    def setUp(self):
        config_path = Path(__file__).parent.parent / "config" / "coding_standards.yaml"
        self.engine = RulesEngine(str(config_path))

    def test_rules_loaded(self):
        self.assertGreater(len(self.engine.rules), 0)
        self.assertEqual(len(self.engine.rules), 7)

    def test_line_length_violation(self):
        long_line = "x = " + "a" * 200
        source = f"import os\n\n{long_line}\n"
        violations = self.engine.apply_rules("test.py", source)
        line_violations = [v for v in violations if v.rule_name == "line_length"]
        self.assertGreater(len(line_violations), 0)

    def test_naming_convention_violation(self):
        source = "def processData(x):\n    return x\n"
        violations = self.engine.apply_rules("test.py", source)
        naming_violations = [v for v in violations if v.rule_name == "naming_conventions"]
        self.assertGreater(len(naming_violations), 0)

    def test_hardcoded_secrets(self):
        violations = self.engine.apply_rules("test.py", SAMPLE_SOURCE)
        secret_violations = [v for v in violations if v.rule_name == "no_hardcoded_secrets"]
        self.assertGreater(len(secret_violations), 0)

    def test_dangerous_functions(self):
        violations = self.engine.apply_rules("test.py", SAMPLE_SOURCE)
        dangerous = [v for v in violations if v.rule_name == "no_dangerous_functions"]
        self.assertGreater(len(dangerous), 0)

    def test_unused_imports(self):
        source = "import os\nimport json\n\nprint('hello')\n"
        violations = self.engine.apply_rules("test.py", source)
        unused = [v for v in violations if v.rule_name == "unused_imports"]
        self.assertGreater(len(unused), 0)

    def test_docstring_coverage(self):
        source = "def my_function(x):\n    return x\n"
        violations = self.engine.apply_rules("test.py", source)
        docstring = [v for v in violations if v.rule_name == "docstring_coverage"]
        self.assertGreater(len(docstring), 0)

    def test_non_python_skipped(self):
        violations = self.engine.apply_rules("readme.md", "# Hello\nsome text")
        self.assertEqual(len(violations), 0)

    def test_changed_lines_filter(self):
        source = "import os\nimport json\n\ndef foo():\n    pass\n"
        # Only check line 4
        violations = self.engine.apply_rules("test.py", source, changed_lines=[4])
        # Should only get violations for line 4
        for v in violations:
            self.assertEqual(v.line_number, 4)


class TestCodeAnalyzer(unittest.TestCase):
    """Tests for the static code analyzer."""

    def setUp(self):
        self.analyzer = CodeAnalyzer()

    def test_bare_except(self):
        source = "try:\n    pass\nexcept:\n    pass\n"
        findings = self.analyzer.analyze_file("test.py", source)
        bare_except = [f for f in findings if "except" in f.description.lower()]
        self.assertGreater(len(bare_except), 0)

    def test_mutable_default(self):
        source = "def foo(items=[]):\n    items.append(1)\n    return items\n"
        findings = self.analyzer.analyze_file("test.py", source)
        mutable = [f for f in findings if "mutable default" in f.description.lower()]
        self.assertGreater(len(mutable), 0)

    def test_deep_nesting(self):
        findings = self.analyzer.analyze_file("test.py", SAMPLE_COMPLEX_SOURCE)
        nesting = [f for f in findings if "nested" in f.description.lower()]
        self.assertGreater(len(nesting), 0)

    def test_many_parameters(self):
        findings = self.analyzer.analyze_file("test.py", SAMPLE_COMPLEX_SOURCE)
        params = [f for f in findings if "parameter" in f.description.lower()]
        self.assertGreater(len(params), 0)

    def test_complexity_score(self):
        score = compute_complexity_score(SAMPLE_COMPLEX_SOURCE)
        self.assertGreater(score, 5)

    def test_syntax_error_handling(self):
        source = "def broken(\n"
        findings = self.analyzer.analyze_file("test.py", source)
        syntax = [f for f in findings if f.finding_type == "syntax"]
        self.assertGreater(len(syntax), 0)

    def test_todo_detection(self):
        source = "# TODO: fix this later\nx = 1\n"
        findings = self.analyzer.analyze_file("test.py", source)
        todos = [f for f in findings if "TODO" in f.description]
        self.assertGreater(len(todos), 0)

    def test_print_detection(self):
        source = "def foo():\n    print('debug')\n"
        findings = self.analyzer.analyze_file("test.py", source)
        prints = [f for f in findings if "print" in f.description.lower()]
        self.assertGreater(len(prints), 0)


class TestCommentFormatter(unittest.TestCase):
    """Tests for the comment formatter."""

    def test_inline_comment(self):
        body = format_inline_comment(
            severity="warning",
            description="Test issue",
            suggestion="Fix it",
            rule_id="TEST_001",
        )
        self.assertIn("WARNING", body)
        self.assertIn("Test issue", body)
        self.assertIn("Fix it", body)

    def test_violation_comment_format(self):
        violation = {
            "severity": "error",
            "description": "Dangerous function",
            "file_path": "test.py",
            "line_number": 10,
            "suggestion": "Use safer alternative",
            "rule_id": "SEC_001",
            "confidence": 0.9,
        }
        comment = format_violation_comment(violation)
        self.assertEqual(comment["path"], "test.py")
        self.assertEqual(comment["line"], 10)
        self.assertIn("Dangerous function", comment["body"])

    def test_summary_comment(self):
        summary = format_summary_comment(
            pr_metadata={"number": 1, "title": "Test", "author": "dev"},
            all_violations=[
                {"severity": "error", "file_path": "a.py"},
                {"severity": "warning", "file_path": "b.py", "category": "security"},
            ],
            all_llm_comments=[],
            all_findings=[],
        )
        self.assertIn("Code Review Summary", summary)
        self.assertIn("Total issues", summary)


class TestRefactoringAgent(unittest.TestCase):
    """Tests for the refactoring agent."""

    def setUp(self):
        self.agent = RefactoringAgent()

    def test_remove_unused_import(self):
        source = "import os\nimport json\n\nx = 1\n"
        request = DelegationRequest(
            file_path="test.py",
            source_code=source,
            violations=[{
                "rule_name": "unused_imports",
                "severity": "warning",
                "description": "Import 'json' appears to be unused.",
                "file_path": "test.py",
                "line_number": 2,
            }],
        )
        actions = self.agent.process_delegation(request)
        applied = [a for a in actions if a.status == "applied"]
        if applied:
            self.assertNotIn("import json", applied[0].refactored_code)

    def test_fix_naming(self):
        source = "def processData(x):\n    return x\n"
        request = DelegationRequest(
            file_path="test.py",
            source_code=source,
            violations=[{
                "rule_name": "naming_conventions",
                "severity": "warning",
                "description": "Function 'processData' does not follow snake_case convention.",
                "file_path": "test.py",
                "line_number": 1,
            }],
        )
        actions = self.agent.process_delegation(request)
        applied = [a for a in actions if a.status == "applied"]
        if applied:
            self.assertIn("process_data", applied[0].refactored_code)


class TestAgentCoordinator(unittest.TestCase):
    """Tests for the agent coordinator."""

    def setUp(self):
        self.refactoring_agent = RefactoringAgent()
        self.coordinator = AgentCoordinator(
            refactoring_agent=self.refactoring_agent,
            delegation_config={
                "enabled": True,
                "max_violations_per_file": 3,
                "min_complexity_for_refactor": 10,
                "auto_refactor_severities": ["critical", "error"],
            },
        )

    def test_should_delegate_many_violations(self):
        violations = [
            {"file_path": "test.py", "severity": "warning"} for _ in range(5)
        ]
        should, reason = self.coordinator.should_delegate("test.py", violations)
        self.assertTrue(should)

    def test_should_delegate_critical_severity(self):
        violations = [{"file_path": "test.py", "severity": "critical"}]
        should, reason = self.coordinator.should_delegate("test.py", violations)
        self.assertTrue(should)

    def test_should_not_delegate_few_violations(self):
        violations = [{"file_path": "test.py", "severity": "info"}]
        should, reason = self.coordinator.should_delegate("test.py", violations)
        self.assertFalse(should)

    def test_should_delegate_high_complexity(self):
        violations = []
        should, reason = self.coordinator.should_delegate("test.py", violations, 15)
        self.assertTrue(should)

    def test_handoff_lifecycle(self):
        source = "import json\n\nx = 1\n"
        violations = [
            {"rule_name": "unused_imports", "severity": "warning",
             "description": "Import 'json' appears to be unused.",
             "file_path": "test.py", "line_number": 1},
        ] * 4  # 4 violations triggers delegation

        record = self.coordinator.initiate_handoff(
            file_path="test.py",
            source_code=source,
            violations=violations,
            complexity_score=5,
            reason="Too many violations",
        )
        self.assertEqual(record.status.value, "completed")
        self.assertGreater(len(self.coordinator.message_log), 0)

    def test_delegation_summary(self):
        summary = self.coordinator.get_delegation_summary()
        self.assertIsInstance(summary, list)

    def test_full_report(self):
        report = self.coordinator.get_full_report()
        self.assertIn("total_handoffs", report)
        self.assertIn("message_log", report)


class TestEndToEnd(unittest.TestCase):
    """End-to-end integration test using sample data."""

    def test_sample_review(self):
        """Run the full pipeline on sample data."""
        from src.review_agent import ReviewAgent

        agent = ReviewAgent()
        result = agent.review_sample()

        # Verify structure
        self.assertIn("total_issues", result)
        self.assertIn("violations", result)
        self.assertIn("findings", result)
        self.assertIn("pr_metadata", result)
        self.assertIn("delegation_actions", result)
        self.assertIn("timestamp", result)

        # Should find issues in the intentionally bad sample code
        self.assertGreater(result["total_issues"], 0)
        self.assertGreater(len(result["violations"]), 0)

        # Check violation structure
        for v in result["violations"]:
            self.assertIn("rule_id", v)
            self.assertIn("severity", v)
            self.assertIn("file_path", v)
            self.assertIn("line_number", v)
            self.assertIn("description", v)

        # Should detect security issues
        security_violations = [
            v for v in result["violations"]
            if v.get("category") == "security"
        ]
        self.assertGreater(len(security_violations), 0)

        print(f"\n✅ End-to-end test passed: {result['total_issues']} issues found.")

    def test_output_files_created(self):
        """Verify that log files are created."""
        from src.review_agent import ReviewAgent, LOG_DIR

        agent = ReviewAgent()
        agent.review_sample()

        json_files = list(LOG_DIR.glob("review_pr42_*.json"))
        jsonl_files = list(LOG_DIR.glob("review_pr42_*.jsonl"))

        self.assertGreater(len(json_files), 0, "JSON output file not created")
        self.assertGreater(len(jsonl_files), 0, "JSONL output file not created")

        # Verify JSON is valid
        with open(json_files[-1]) as f:
            data = json.load(f)
            self.assertIn("total_issues", data)

        # Verify JSONL is valid
        with open(jsonl_files[-1]) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    self.assertIn("source", entry)


if __name__ == "__main__":
    unittest.main(verbosity=2)
