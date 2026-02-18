"""
Code Analyzer
──────────────
Static analysis engine using AST parsing and pattern matching.
Provides deeper structural analysis beyond simple rule checking.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AnalysisFinding:
    """A finding from static code analysis."""
    finding_type: str         # e.g. "complexity", "security", "style"
    severity: str             # critical, error, warning, info
    file_path: str
    line_number: int
    line_content: str
    description: str
    suggestion: str = ""
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise the finding to a plain dictionary for JSON output."""
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "description": self.description,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class CodeAnalyzer:
    """Static analysis via AST parsing and pattern matching."""

    def analyze_file(
        self,
        file_path: str,
        source_code: str,
        changed_lines: Optional[list[int]] = None,
    ) -> list[AnalysisFinding]:
        """Run all analysis passes on a source file."""
        if not file_path.endswith(".py"):
            return []

        findings: list[AnalysisFinding] = []

        # AST-based analysis
        try:
            tree = ast.parse(source_code, filename=file_path)
            findings.extend(self._analyze_ast(tree, file_path, source_code, changed_lines))
        except SyntaxError as exc:
            findings.append(AnalysisFinding(
                finding_type="syntax",
                severity="error",
                file_path=file_path,
                line_number=exc.lineno or 1,
                line_content=exc.text or "",
                description=f"Syntax error: {exc.msg}",
                confidence=1.0,
            ))

        # Pattern-based analysis
        findings.extend(self._pattern_analysis(file_path, source_code, changed_lines))

        logger.info("Code analysis found %d findings in %s.", len(findings), file_path)
        return findings

    # ── AST Analysis ──────────────────────────────────────────────────────

    def _analyze_ast(
        self,
        tree: ast.AST,
        file_path: str,
        source_code: str,
        changed_lines: Optional[list[int]],
    ) -> list[AnalysisFinding]:
        """Walk the AST to detect structural issues (nesting, bare except, mutable defaults, etc.)."""
        findings = []
        lines = source_code.split("\n")

        for node in ast.walk(tree):
            # Detect deeply nested code
            if isinstance(node, (ast.If, ast.For, ast.While, ast.With)):
                depth = self._get_nesting_depth(node)
                if depth > 3:
                    line_no = node.lineno
                    if changed_lines and line_no not in changed_lines:
                        continue
                    findings.append(AnalysisFinding(
                        finding_type="complexity",
                        severity="warning",
                        file_path=file_path,
                        line_number=line_no,
                        line_content=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                        description=f"Code is nested {depth} levels deep. Consider refactoring.",
                        suggestion="Extract inner logic into separate helper functions.",
                        confidence=0.85,
                        metadata={"nesting_depth": depth},
                    ))

            # Detect bare except clauses
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                line_no = node.lineno
                if changed_lines and line_no not in changed_lines:
                    continue
                findings.append(AnalysisFinding(
                    finding_type="best_practice",
                    severity="warning",
                    file_path=file_path,
                    line_number=line_no,
                    line_content=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                    description="Bare 'except:' clause catches all exceptions including SystemExit and KeyboardInterrupt.",
                    suggestion="Catch specific exceptions, e.g. 'except ValueError:' or 'except Exception:'.",
                    confidence=0.95,
                ))

            # Detect mutable default arguments
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        line_no = node.lineno
                        if changed_lines and line_no not in changed_lines:
                            continue
                        findings.append(AnalysisFinding(
                            finding_type="best_practice",
                            severity="warning",
                            file_path=file_path,
                            line_number=line_no,
                            line_content=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                            description=f"Function '{node.name}' uses a mutable default argument.",
                            suggestion="Use None as default and initialise inside the function body.",
                            confidence=0.95,
                            metadata={"function_name": node.name},
                        ))
                        break  # One per function

            # Detect functions with too many parameters
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                param_count = (
                    len(node.args.args) +
                    len(node.args.kwonlyargs) +
                    (1 if node.args.vararg else 0) +
                    (1 if node.args.kwarg else 0)
                )
                # Subtract 'self'/'cls'
                if node.args.args and node.args.args[0].arg in ("self", "cls"):
                    param_count -= 1

                if param_count > 5:
                    line_no = node.lineno
                    if changed_lines and line_no not in changed_lines:
                        continue
                    findings.append(AnalysisFinding(
                        finding_type="complexity",
                        severity="warning",
                        file_path=file_path,
                        line_number=line_no,
                        line_content=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                        description=f"Function '{node.name}' has {param_count} parameters (recommended max: 5).",
                        suggestion="Consider grouping related parameters into a dataclass or dict.",
                        confidence=0.8,
                        metadata={"param_count": param_count, "function_name": node.name},
                    ))

            # Detect global variable usage
            if isinstance(node, ast.Global):
                line_no = node.lineno
                if changed_lines and line_no not in changed_lines:
                    continue
                findings.append(AnalysisFinding(
                    finding_type="best_practice",
                    severity="info",
                    file_path=file_path,
                    line_number=line_no,
                    line_content=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                    description=f"Use of 'global' keyword for: {', '.join(node.names)}.",
                    suggestion="Consider passing values as parameters or using a class to manage state.",
                    confidence=0.7,
                ))

        return findings

    def _get_nesting_depth(self, node: ast.AST, depth: int = 0) -> int:
        """Recursively compute the maximum nesting depth of a node."""
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                child_depth = self._get_nesting_depth(child, depth + 1)
                max_depth = max(max_depth, child_depth)
        return max_depth

    # ── Pattern-Based Analysis ────────────────────────────────────────────

    def _pattern_analysis(
        self,
        file_path: str,
        source_code: str,
        changed_lines: Optional[list[int]],
    ) -> list[AnalysisFinding]:
        """Regex-based checks for print(), TODO/FIXME markers, and broad type: ignore."""
        findings = []
        lines = source_code.split("\n")

        patterns = [
            # TODO/FIXME/HACK comments
            {
                "pattern": re.compile(r"#\s*(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE),
                "finding_type": "maintenance",
                "severity": "info",
                "description_template": "Found '{match}' comment — consider addressing or tracking as a ticket.",
                "suggestion": "Create a tracking ticket and reference it in the comment.",
                "confidence": 0.6,
            },
            # Print statements (should use logging)
            {
                "pattern": re.compile(r"^\s*print\s*\("),
                "finding_type": "best_practice",
                "severity": "info",
                "description_template": "Use of print() detected; consider using the logging module instead.",
                "suggestion": "Replace with logging.info(), logging.debug(), etc.",
                "confidence": 0.7,
            },
            # Type: ignore without specific error code
            {
                "pattern": re.compile(r"#\s*type:\s*ignore(?!\[)"),
                "finding_type": "best_practice",
                "severity": "info",
                "description_template": "Broad 'type: ignore' suppresses all type errors on this line.",
                "suggestion": "Use specific error codes: # type: ignore[assignment]",
                "confidence": 0.8,
            },
        ]

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue
            stripped = line.strip()
            if not stripped:
                continue

            for p in patterns:
                match = p["pattern"].search(line)
                if match:
                    description = p["description_template"]
                    if "{match}" in description:
                        description = description.replace("{match}", match.group(0).strip("# "))
                    findings.append(AnalysisFinding(
                        finding_type=p["finding_type"],
                        severity=p["severity"],
                        file_path=file_path,
                        line_number=i,
                        line_content=stripped,
                        description=description,
                        suggestion=p["suggestion"],
                        confidence=p["confidence"],
                    ))

        return findings


def compute_complexity_score(source_code: str) -> int:
    """
    Compute an overall complexity score for a source file.
    Used by the delegation system to decide whether to hand off to refactoring agent.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return 0

    score = 0
    branching = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            score += 1
        if isinstance(node, branching):
            score += 1
        if isinstance(node, ast.BoolOp):
            score += len(node.values) - 1

    return score
