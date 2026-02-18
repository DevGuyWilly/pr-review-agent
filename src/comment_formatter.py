"""
Comment Formatter
──────────────────
Formats analysis findings into GitHub-compatible markdown review
comments, including severity badges, statistics, and summaries.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Severity badge mapping
SEVERITY_BADGES = {
    "critical": "🔴 **CRITICAL**",
    "error": "🟠 **ERROR**",
    "warning": "🟡 **WARNING**",
    "info": "🔵 **INFO**",
}

SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3}

CATEGORY_ICONS = {
    "style_formatting": "🎨",
    "code_quality": "⚙️",
    "security": "🔒",
    "best_practices": "✅",
    "complexity": "📊",
    "maintenance": "🔧",
    "syntax": "❌",
    "best_practice": "✅",
}


def format_inline_comment(
    severity: str,
    description: str,
    suggestion: str = "",
    code_example: str = "",
    rule_id: str = "",
    confidence: float = 1.0,
    category: str = "",
    resolved: bool = False,
    line_content: str = "",
) -> str:
    """
    Format a single inline review comment as GitHub markdown.
    """
    badge = SEVERITY_BADGES.get(severity, f"**{severity.upper()}**")
    cat_icon = CATEGORY_ICONS.get(category, "")
    resolved_tag = " ✅ *auto-fixed*" if resolved else ""

    parts = [f"{cat_icon} {badge}: {description}{resolved_tag}"]

    if suggestion:
        parts.append(f"\n💡 **What to do:** {suggestion}")

    if line_content:
        parts.append(f"\n**Current code:**\n```python\n{line_content}\n```")

    if code_example:
        parts.append(f"\n**Suggested fix:**\n```python\n{code_example}\n```")

    if rule_id:
        parts.append(f"\n`Rule: {rule_id}`")

    if confidence < 1.0:
        parts.append(f" | Confidence: {confidence:.0%}")

    return "\n".join(parts)


def format_violation_comment(violation: dict) -> dict:
    """
    Convert a Violation or Finding dict into a GitHub review comment dict.

    Works with both rules engine violations (have rule_id) and
    static analysis findings (have finding_type).

    Returns dict with: path, line, body, side
    """
    # Determine rule_id — violations have it, findings use finding_type
    rule_id = violation.get("rule_id", "")
    if not rule_id and violation.get("finding_type"):
        rule_id = f"AST:{violation['finding_type']}"

    category = violation.get("category", violation.get("finding_type", ""))

    body = format_inline_comment(
        severity=violation["severity"],
        description=violation["description"],
        suggestion=violation.get("suggestion", ""),
        code_example=violation.get("code_example", ""),
        rule_id=rule_id,
        confidence=violation.get("confidence", 1.0),
        category=category,
        resolved=violation.get("resolved", False),
        line_content=violation.get("line_content", ""),
    )

    return {
        "path": violation["file_path"],
        "line": violation["line_number"],
        "body": body,
        "side": "RIGHT",
    }


def format_llm_comment(llm_comment: dict) -> dict:
    """
    Convert an LLM review comment dict into a GitHub review comment dict.
    """
    parts = [
        SEVERITY_BADGES.get(llm_comment["severity"], "**INFO**")
        + f": {llm_comment['problem']}"
    ]

    if llm_comment.get("suggestion"):
        parts.append(f"\n💡 **Suggestion:** {llm_comment['suggestion']}")

    if llm_comment.get("code_example"):
        parts.append(f"\n```python\n{llm_comment['code_example']}\n```")

    if llm_comment.get("reasoning"):
        parts.append(f"\n<details><summary>Reasoning</summary>\n\n{llm_comment['reasoning']}\n\n</details>")

    parts.append(f"\n`AI Review` | Confidence: {llm_comment.get('confidence', 0.8):.0%}")

    return {
        "path": llm_comment["file_path"],
        "line": llm_comment["line_number"],
        "body": "\n".join(parts),
        "side": "RIGHT",
    }


def format_summary_comment(
    pr_metadata: dict,
    all_violations: list[dict],
    all_llm_comments: list[dict],
    all_findings: list[dict],
    delegation_actions: Optional[list[dict]] = None,
) -> str:
    """
    Generate a comprehensive summary comment for the PR.
    """
    total_issues = len(all_violations) + len(all_llm_comments) + len(all_findings)

    # Count by severity
    severity_counts = {"critical": 0, "error": 0, "warning": 0, "info": 0}
    for item in all_violations + all_llm_comments + all_findings:
        sev = item.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Count by category
    category_counts: dict[str, int] = {}
    for item in all_violations:
        cat = item.get("category", "other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Files reviewed
    files_reviewed = set()
    for item in all_violations + all_llm_comments + all_findings:
        files_reviewed.add(item.get("file_path", "unknown"))

    # Build summary
    lines = [
        "## 🤖 Automated Code Review Summary\n",
        f"**PR:** #{pr_metadata.get('number', '?')} — {pr_metadata.get('title', 'Untitled')}\n",
        f"**Author:** @{pr_metadata.get('author', 'unknown')}\n",
        f"**Files reviewed:** {len(files_reviewed)} | "
        f"**Total issues:** {total_issues}\n",
        "---\n",
        "### 📊 Issue Breakdown\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in ["critical", "error", "warning", "info"]:
        count = severity_counts.get(sev, 0)
        badge = SEVERITY_BADGES.get(sev, sev)
        lines.append(f"| {badge} | {count} |")

    lines.append("")

    if category_counts:
        lines.append("### 📂 By Category\n")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, count in sorted(category_counts.items()):
            icon = CATEGORY_ICONS.get(cat, "📌")
            display_name = cat.replace("_", " ").title()
            lines.append(f"| {icon} {display_name} | {count} |")
        lines.append("")

    # Analysis sources
    lines.append("### 🔍 Analysis Sources\n")
    lines.append(f"- **Static Analysis (Rules Engine):** {len(all_violations)} findings")
    lines.append(f"- **AST/Pattern Analysis:** {len(all_findings)} findings")
    lines.append(f"- **AI Semantic Review:** {len(all_llm_comments)} findings")
    lines.append("")

    # Delegation actions
    if delegation_actions:
        lines.append("### 🤝 Agent Delegation\n")
        for action in delegation_actions:
            status = action.get("status", "pending")
            icon = "✅" if status == "completed" else "🔄"
            lines.append(
                f"- {icon} **{action.get('file', 'unknown')}**: "
                f"{action.get('action', 'refactoring')} — {status}"
            )
        lines.append("")

    # Overall assessment
    if severity_counts.get("critical", 0) > 0:
        lines.append("> ⚠️ **Critical issues found — changes requested.**")
    elif severity_counts.get("error", 0) > 0:
        lines.append("> 🔍 **Errors found — please review before merging.**")
    elif total_issues > 0:
        lines.append("> 💡 **Minor suggestions — overall looking good!**")
    else:
        lines.append("> ✅ **No issues found — LGTM!**")

    lines.append("\n---")
    lines.append("*Generated by Code Review Agent v1.0.0*")

    return "\n".join(lines)
