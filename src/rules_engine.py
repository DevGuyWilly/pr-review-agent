"""
Rules Engine
─────────────
Loads coding standards from YAML configuration and applies rules
against source code to produce structured violations.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "coding_standards.yaml"


@dataclass
class Violation:
    """A single rule violation found in source code."""
    rule_id: str
    rule_name: str
    category: str
    severity: str          # critical, error, warning, info
    description: str
    file_path: str
    line_number: int
    line_content: str
    suggestion: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        """Serialise the violation to a plain dictionary for JSON output."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }


@dataclass
class RuleDefinition:
    """A single rule loaded from config."""
    id: str
    name: str
    category: str
    severity: str
    description: str
    params: dict = field(default_factory=dict)
    enabled: bool = True


class RulesEngine:
    """Load and apply coding standard rules against source code."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialise the engine, loading rules from the YAML config file."""
        self.config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self.rules: list[RuleDefinition] = []
        self.delegation_config: dict = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load rules from YAML configuration."""
        with open(self.config_path, "r") as f:
            config = yaml.safe_load(f)

        for rule_data in config.get("rules", []):
            rule = RuleDefinition(
                id=rule_data["id"],
                name=rule_data["name"],
                category=rule_data["category"],
                severity=rule_data["severity"],
                description=rule_data["description"],
                params=rule_data.get("params", {}),
                enabled=rule_data.get("enabled", True),
            )
            self.rules.append(rule)

        self.delegation_config = config.get("delegation", {})
        logger.info(
            "Loaded %d rules (%d enabled) from %s.",
            len(self.rules),
            sum(1 for r in self.rules if r.enabled),
            self.config_path,
        )

    def get_enabled_rules(self) -> list[RuleDefinition]:
        """Return only enabled rules."""
        return [r for r in self.rules if r.enabled]

    def apply_rules(
        self, file_path: str, source_code: str, changed_lines: Optional[list[int]] = None
    ) -> list[Violation]:
        """
        Apply all enabled rules to the given source code.
        If changed_lines is provided, only report violations on those lines.
        """
        if not file_path.endswith(".py"):
            logger.debug("Skipping non-Python file: %s", file_path)
            return []

        violations: list[Violation] = []
        lines = source_code.split("\n")

        for rule in self.get_enabled_rules():
            checker = self._get_checker(rule.name)
            if checker:
                rule_violations = checker(rule, file_path, lines, changed_lines)
                violations.extend(rule_violations)

        logger.info(
            "Found %d violations in %s (%d rules applied).",
            len(violations), file_path, len(self.get_enabled_rules()),
        )
        return violations

    def _get_checker(self, rule_name: str):
        """Map rule name to its checker function."""
        checkers = {
            "line_length": self._check_line_length,
            "naming_conventions": self._check_naming_conventions,
            "function_complexity": self._check_function_complexity,
            "unused_imports": self._check_unused_imports,
            "no_hardcoded_secrets": self._check_hardcoded_secrets,
            "no_dangerous_functions": self._check_dangerous_functions,
            "docstring_coverage": self._check_docstring_coverage,
        }
        return checkers.get(rule_name)

    # ── Rule Checkers ─────────────────────────────────────────────────────

    def _check_line_length(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """STYLE_001: Flag lines that exceed the configured max length."""
        max_len = rule.params.get("max_length", 120)
        violations = []
        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue
            if len(line) > max_len:
                violations.append(Violation(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"Line exceeds {max_len} characters ({len(line)} chars).",
                    file_path=file_path,
                    line_number=i,
                    line_content=line,
                    suggestion=f"Break this line to stay under {max_len} characters.",
                    confidence=1.0,
                ))
        return violations

    def _check_naming_conventions(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """STYLE_002: Enforce PEP 8 naming — snake_case functions, PascalCase classes."""
        violations = []
        func_pattern = re.compile(r"^\s*def\s+([a-zA-Z_]\w*)\s*\(")
        class_pattern = re.compile(r"^\s*class\s+([a-zA-Z_]\w*)")

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue

            # Check function names (should be snake_case)
            func_match = func_pattern.match(line)
            if func_match:
                name = func_match.group(1)
                if not name.startswith("_") and name != name.lower() and not re.match(r"^[a-z_][a-z0-9_]*$", name):
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"Function '{name}' does not follow snake_case convention.",
                        file_path=file_path,
                        line_number=i,
                        line_content=line.strip(),
                        suggestion=f"Rename to '{_to_snake_case(name)}'.",
                        confidence=0.9,
                    ))

            # Check class names (should be PascalCase)
            class_match = class_pattern.match(line)
            if class_match:
                name = class_match.group(1)
                if not re.match(r"^[A-Z][a-zA-Z0-9]*$", name):
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"Class '{name}' does not follow PascalCase convention.",
                        file_path=file_path,
                        line_number=i,
                        line_content=line.strip(),
                        suggestion=f"Rename to '{_to_pascal_case(name)}'.",
                        confidence=0.9,
                    ))

        return violations

    def _check_function_complexity(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """Check cyclomatic complexity and function length."""
        violations = []
        max_complexity = rule.params.get("max_cyclomatic_complexity", 10)
        max_lines = rule.params.get("max_function_lines", 50)

        # Simple complexity heuristic: count branching keywords
        complexity_keywords = {"if", "elif", "else", "for", "while", "except", "and", "or"}
        func_pattern = re.compile(r"^(\s*)def\s+(\w+)\s*\(")

        in_function = False
        func_name = ""
        func_start = 0
        func_indent = 0
        func_complexity = 1
        func_line_count = 0

        for i, line in enumerate(lines, 1):
            func_match = func_pattern.match(line)
            if func_match:
                # Report previous function if applicable
                if in_function:
                    self._report_complexity(
                        violations, rule, file_path, func_name, func_start,
                        lines[func_start - 1], func_complexity, func_line_count,
                        max_complexity, max_lines, changed_lines,
                    )
                in_function = True
                func_name = func_match.group(2)
                func_start = i
                func_indent = len(func_match.group(1))
                func_complexity = 1
                func_line_count = 0
                continue

            if in_function:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    # Check if we've exited the function
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= func_indent and stripped and not line.strip().startswith("@"):
                        self._report_complexity(
                            violations, rule, file_path, func_name, func_start,
                            lines[func_start - 1], func_complexity, func_line_count,
                            max_complexity, max_lines, changed_lines,
                        )
                        in_function = False
                        # Check if this line starts a new function
                        new_func_match = func_pattern.match(line)
                        if new_func_match:
                            in_function = True
                            func_name = new_func_match.group(2)
                            func_start = i
                            func_indent = len(new_func_match.group(1))
                            func_complexity = 1
                            func_line_count = 0
                        continue

                    func_line_count += 1
                    tokens = set(re.findall(r"\b\w+\b", stripped))
                    func_complexity += len(tokens & complexity_keywords)

        # Handle last function
        if in_function:
            self._report_complexity(
                violations, rule, file_path, func_name, func_start,
                lines[func_start - 1], func_complexity, func_line_count,
                max_complexity, max_lines, changed_lines,
            )

        return violations

    def _report_complexity(
        self, violations, rule, file_path, func_name, func_start,
        line_content, complexity, line_count, max_complexity, max_lines,
        changed_lines,
    ):
        """Emit violations if a function exceeds complexity or length limits."""
        if changed_lines and func_start not in changed_lines:
            return
        if complexity > max_complexity:
            violations.append(Violation(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                description=(
                    f"Function '{func_name}' has cyclomatic complexity "
                    f"of {complexity} (max {max_complexity})."
                ),
                file_path=file_path,
                line_number=func_start,
                line_content=line_content.strip(),
                suggestion="Consider breaking this function into smaller, focused functions.",
                confidence=0.85,
            ))
        if line_count > max_lines:
            violations.append(Violation(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                description=(
                    f"Function '{func_name}' is {line_count} lines long "
                    f"(max {max_lines})."
                ),
                file_path=file_path,
                line_number=func_start,
                line_content=line_content.strip(),
                suggestion="Extract helper functions to reduce the function length.",
                confidence=0.9,
            ))

    def _check_unused_imports(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """QUALITY_002: Detect import statements whose names are never used."""
        violations = []
        import_pattern = re.compile(
            r"^\s*(?:from\s+\S+\s+)?import\s+(.+)$"
        )
        full_text = "\n".join(lines)

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue
            match = import_pattern.match(line)
            if not match:
                continue

            imported_names = []
            raw = match.group(1)
            # Handle "import a, b" and "from x import a, b"
            for part in raw.split(","):
                part = part.strip()
                # Handle "import x as y"
                if " as " in part:
                    imported_names.append(part.split(" as ")[-1].strip())
                else:
                    imported_names.append(part.split(".")[-1].strip())

            for name in imported_names:
                if not name or name == "*":
                    continue
                # Count occurrences in the file (excluding the import line itself)
                other_lines = lines[:i-1] + lines[i:]
                other_text = "\n".join(other_lines)
                if re.search(r"\b" + re.escape(name) + r"\b", other_text) is None:
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"Import '{name}' appears to be unused.",
                        file_path=file_path,
                        line_number=i,
                        line_content=line.strip(),
                        suggestion=f"Remove the unused import: '{name}'.",
                        confidence=0.8,
                    ))

        return violations

    def _check_hardcoded_secrets(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """SECURITY_001: Flag strings that match known secret patterns."""
        violations = []
        patterns = rule.params.get("patterns", [])

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern in patterns:
                if re.search(pattern, line):
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description="Possible hardcoded secret detected.",
                        file_path=file_path,
                        line_number=i,
                        line_content=line.strip(),
                        suggestion="Use environment variables or a secrets manager instead.",
                        confidence=0.75,
                    ))
                    break  # One match per line is sufficient

        return violations

    def _check_dangerous_functions(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """SECURITY_002: Flag calls to eval(), exec(), and other forbidden functions."""
        violations = []
        forbidden = rule.params.get("forbidden_functions", [])

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for func_name in forbidden:
                # Match function call pattern: eval(, exec(, etc.
                pattern = rf"\b{re.escape(func_name)}\s*\("
                if re.search(pattern, line):
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"Use of dangerous function '{func_name}()' detected.",
                        file_path=file_path,
                        line_number=i,
                        line_content=stripped,
                        suggestion=f"Avoid '{func_name}()'. Use safer alternatives like ast.literal_eval() for eval().",
                        confidence=0.95,
                    ))

        return violations

    def _check_docstring_coverage(
        self, rule: RuleDefinition, file_path: str,
        lines: list[str], changed_lines: Optional[list[int]]
    ) -> list[Violation]:
        """BEST_001: Flag public functions and classes that lack a docstring."""
        violations = []
        func_pattern = re.compile(r"^(\s*)def\s+(\w+)\s*\(")
        class_pattern = re.compile(r"^(\s*)class\s+(\w+)")

        for i, line in enumerate(lines, 1):
            if changed_lines and i not in changed_lines:
                continue

            for pattern, kind in [(func_pattern, "Function"), (class_pattern, "Class")]:
                match = pattern.match(line)
                if not match:
                    continue
                name = match.group(2)
                # Skip private/dunder methods
                if name.startswith("_") and kind == "Function":
                    continue

                # Check if next non-empty line is a docstring
                has_docstring = False
                for j in range(i, min(i + 3, len(lines))):
                    next_line = lines[j].strip()
                    if next_line == "":
                        continue
                    if next_line.startswith('"""') or next_line.startswith("'''"):
                        has_docstring = True
                    break

                if not has_docstring:
                    violations.append(Violation(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"{kind} '{name}' is missing a docstring.",
                        file_path=file_path,
                        line_number=i,
                        line_content=line.strip(),
                        suggestion=f"Add a docstring describing the purpose of '{name}'.",
                        confidence=0.95,
                    ))

        return violations

    def should_delegate(self, violations: list[Violation], file_path: str) -> bool:
        """Check if violations meet delegation criteria for refactoring agent."""
        if not self.delegation_config.get("enabled", False):
            return False

        max_violations = self.delegation_config.get("max_violations_per_file", 3)
        auto_severities = set(self.delegation_config.get("auto_refactor_severities", []))

        file_violations = [v for v in violations if v.file_path == file_path]
        if len(file_violations) > max_violations:
            return True

        for v in file_violations:
            if v.severity in auto_severities:
                return True

        return False


# ── Helpers ───────────────────────────────────────────────────────────────

def _to_snake_case(name: str) -> str:
    """Convert a CamelCase or mixedCase name to snake_case."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower()


def _to_pascal_case(name: str) -> str:
    """Convert a snake_case or space-separated name to PascalCase."""
    return "".join(word.capitalize() for word in re.split(r"[_\s]+", name))
