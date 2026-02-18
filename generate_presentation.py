#!/usr/bin/env python3
"""Generate the presentation PDF for the Automated Code Review Agent."""

from fpdf import FPDF

# ── Custom PDF class ──────────────────────────────────────────────
class SlideDeck(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(auto=False)
        # Colours
        self.BG = (15, 15, 26)
        self.SURFACE = (26, 26, 46)
        self.ACCENT = (108, 99, 255)
        self.ACCENT2 = (255, 101, 132)
        self.GREEN = (67, 233, 123)
        self.TEXT = (232, 232, 240)
        self.MUTED = (153, 153, 176)

    # ── helpers ────────────────────────────────────────────────────
    def _bg(self):
        self.set_fill_color(*self.BG)
        self.rect(0, 0, self.w, self.h, "F")

    def _footer_bar(self, num):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*self.MUTED)
        self.text(12, self.h - 8, "Automated Code Review Agent")
        self.text(self.w - 18, self.h - 8, str(num))

    def _title(self, txt, y=28, size=22):
        self.set_font("Helvetica", "B", size)
        self.set_text_color(*self.ACCENT)
        self.set_xy(15, y)
        self.cell(0, 10, txt)

    def _subtitle(self, txt, y=40, size=11):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*self.MUTED)
        self.set_xy(15, y)
        self.multi_cell(self.w - 30, 6, txt)

    def _heading(self, txt, y, size=13):
        self.set_font("Helvetica", "B", size)
        self.set_text_color(*self.GREEN)
        self.set_xy(15, y)
        self.cell(0, 8, txt)

    def _body(self, txt, x, y, w=120, size=10):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*self.TEXT)
        self.set_xy(x, y)
        self.multi_cell(w, 5.5, txt)

    def _bullet(self, txt, x, y, w=120, size=10):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*self.TEXT)
        self.set_xy(x, y)
        self.cell(5, 5.5, ">")
        self.set_xy(x + 6, y)
        self.multi_cell(w - 6, 5.5, txt)

    def _check(self, txt, x, y, w=120, checked=True):
        mark = "[OK]" if checked else "[!!]"
        col = self.GREEN if checked else self.ACCENT2
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*col)
        self.set_xy(x, y)
        self.cell(12, 5.5, mark)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*self.TEXT)
        self.set_xy(x + 7, y)
        self.set_xy(x + 13, y)
        self.multi_cell(w - 13, 5.5, txt)

    def _stat_box(self, x, y, value, label, w=42, h=28):
        self.set_fill_color(*self.SURFACE)
        self.set_draw_color(60, 60, 90)
        self.rect(x, y, w, h, "DF")
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(*self.ACCENT)
        self.set_xy(x, y + 3)
        self.cell(w, 10, str(value), align="C")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*self.MUTED)
        self.set_xy(x, y + 15)
        self.cell(w, 6, label, align="C")

    def _code_block(self, txt, x, y, w=260, size=8):
        self.set_fill_color(13, 13, 26)
        self.set_draw_color(50, 50, 80)
        lines = txt.strip().split("\n")
        h = len(lines) * 4.5 + 8
        self.rect(x, y, w, h, "DF")
        self.set_font("Courier", "", size)
        self.set_text_color(*self.TEXT)
        cy = y + 4
        for line in lines:
            self.set_xy(x + 4, cy)
            self.cell(w - 8, 4.5, line)
            cy += 4.5

    def _table(self, headers, rows, x, y, col_widths, size=9):
        self.set_font("Helvetica", "B", size)
        self.set_fill_color(*self.SURFACE)
        self.set_draw_color(60, 60, 90)
        self.set_text_color(*self.ACCENT)
        cx = x
        for i, h in enumerate(headers):
            self.set_xy(cx, y)
            self.cell(col_widths[i], 7, h, border=1, fill=True)
            cx += col_widths[i]
        y += 7
        self.set_font("Helvetica", "", size)
        self.set_text_color(*self.TEXT)
        for row in rows:
            cx = x
            for i, val in enumerate(row):
                self.set_xy(cx, y)
                self.cell(col_widths[i], 6.5, str(val), border=1)
                cx += col_widths[i]
            y += 6.5
        return y


# ── Build Slides ──────────────────────────────────────────────────
pdf = SlideDeck()

# ═══ SLIDE 1: TITLE ═══════════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf.set_font("Helvetica", "B", 36)
pdf.set_text_color(*pdf.ACCENT)
pdf.set_xy(0, 55)
pdf.cell(pdf.w, 16, "Automated Code Review Agent", align="C")

pdf.set_font("Helvetica", "", 16)
pdf.set_text_color(*pdf.MUTED)
pdf.set_xy(0, 78)
pdf.cell(pdf.w, 10, "An Intelligent, Multi-Agent Code Review System", align="C")
pdf.set_xy(0, 88)
pdf.cell(pdf.w, 10, "with GitHub PR Integration", align="C")

pdf.set_font("Helvetica", "", 12)
pdf.set_xy(0, 115)
pdf.cell(pdf.w, 8, "Software Engineer Take-Home Assignment", align="C")
pdf.set_xy(0, 130)
pdf.set_text_color(*pdf.TEXT)
pdf.cell(pdf.w, 8, "Wilson Dagah", align="C")
pdf._footer_bar(1)

# ═══ SLIDE 2: OVERVIEW ════════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Project Overview")
pdf._subtitle(
    "An end-to-end agentic code review pipeline that autonomously analyses pull requests, "
    "provides actionable inline feedback, and delegates to a refactoring agent for automated fixes.",
    y=40
)

# Stats
pdf._stat_box(15,  56, 11, "Source Modules")
pdf._stat_box(62,  56, 7,  "Coding Rules")
pdf._stat_box(109, 56, 36, "Automated Tests")
pdf._stat_box(156, 56, 2,  "Agents")
pdf._stat_box(203, 56, 3,  "LLM Providers")

# Tech stack
pdf._heading("Technology Stack", 92)
pdf._body(
    "Python  |  FastAPI  |  PyGithub  |  Ollama / OpenAI / Anthropic  |  "
    "AST Parsing  |  YAML Config  |  Multi-Agent  |  Webhooks",
    15, 102, w=260
)

# Submission checklist
pdf._heading("Submission Deliverables", 114)
y = 124
for item in [
    "Source code (well-structured Python, clear separation of concerns)",
    "README.md (setup instructions, architecture overview, usage examples)",
    "Configuration (YAML coding standards, customisable rules)",
    "Examples directory (real PR review outputs, JSONL logs)",
    "Presentation (this slide deck)",
    "Logs / Output (JSON + JSONL, machine-readable, auditable)",
]:
    pdf._check(item, 15, y, w=260)
    y += 7

pdf._footer_bar(2)

# ═══ SLIDE 3: ARCHITECTURE ════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("System Architecture")

arch = """
  +---------------------------------------------------------------+
  |                   WEBHOOK SERVER (FastAPI)                     |
  |   Receives PR events  ->  Triggers review pipeline            |
  +-------------------------------+-------------------------------+
                                  |
                                  v
  +---------------------------------------------------------------+
  |                   REVIEW AGENT (Orchestrator)                  |
  |                                                                |
  |   GitHub Client  +  Diff Parser  +  Comment Formatter         |
  |                                                                |
  |   ANALYSIS PIPELINE:                                           |
  |     Rules Engine  -  Code Analyzer  -  LLM Reviewer           |
  +-------------------------------+-------------------------------+
                                  |
                                  v
  +---------------------------------------+
  |        AGENT COORDINATOR              |        Commits changes
  |   Delegation criteria -> Handoff      |------> back to PR
  |            |                          |        branch
  |   +------------------------+          |
  |   |  REFACTORING AGENT     |          |
  |   |  Fix -> Validate -> Push          |
  |   +------------------------+          |
  +---------------------------------------+
"""
pdf._code_block(arch, 15, 42, w=260, size=8)

pdf._footer_bar(3)

# ═══ SLIDE 4: BASELINE ════════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Baseline: Code Review Agent")
pdf.set_font("Helvetica", "B", 10)
pdf.set_text_color(*pdf.ACCENT2)
pdf.text(215, 33, "REQUIRED")

# Left column
pdf._heading("GitHub Integration", 44)
y = 53
for b in [
    "FastAPI webhook server (auto-generated OpenAPI docs)",
    "HMAC SHA-256 signature verification",
    "PAT authentication with rate limiting + retry",
    "Inline diff-positioned review comments",
]:
    pdf._bullet(b, 15, y, w=130); y += 7

pdf._heading("Diff Parsing", y + 3)
y += 12
for b in [
    "Unified diff parser with hunk extraction",
    "Line-to-diff-position mapping for GitHub API",
    "Added / deleted / context line detection",
]:
    pdf._bullet(b, 15, y, w=130); y += 7

# Right column
pdf._heading("7 Coding Standard Rules (YAML)", 44, size=12)
pdf.set_xy(155, 44); pdf.cell(0, 8, "7 Coding Standard Rules (YAML)")
y = 53
for b in [
    "Style: Line length, naming conventions (PEP 8)",
    "Quality: Function complexity, unused imports",
    "Security: Hardcoded secrets, dangerous functions",
    "Best Practices: Docstring coverage",
]:
    pdf._bullet(b, 155, y, w=130); y += 7

pdf._heading("Analysis Pipeline", y + 3)
pdf.set_xy(155, y + 3); pdf.cell(0, 8, "Analysis Pipeline")
y += 12
for b in [
    "AST parsing + pattern matching (zero deps)",
    "LLM semantic review (Ollama / OpenAI / Anthropic)",
    "Severity levels + confidence scoring",
    "Actionable fix suggestions with code examples",
]:
    pdf._bullet(b, 155, y, w=130); y += 7

pdf._footer_bar(4)

# ═══ SLIDE 5: PIPELINE FLOW ═══════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Analysis Pipeline Flow")

# Flow boxes
flow_steps = ["PR Opened", "Webhook", "Fetch Diff", "Parse Hunks", "Rules Engine",
              "AST Analysis", "LLM Review", "Post Comments"]
bx = 15
for i, step in enumerate(flow_steps):
    is_analysis = step in ("Parse Hunks", "Rules Engine", "AST Analysis", "LLM Review")
    if is_analysis:
        pdf.set_fill_color(108, 99, 255)
        pdf.set_text_color(255, 255, 255)
    else:
        pdf.set_fill_color(*pdf.SURFACE)
        pdf.set_text_color(*pdf.TEXT)
    pdf.set_draw_color(60, 60, 90)
    pdf.rect(bx, 44, 30, 14, "DF")
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_xy(bx, 47)
    pdf.cell(30, 7, step, align="C")
    bx += 30
    if i < len(flow_steps) - 1:
        pdf.set_text_color(*pdf.ACCENT)
        pdf.set_font("Helvetica", "B", 12)
        pdf.text(bx + 1, 53, ">")
        bx += 5

# Two columns: detections
pdf._heading("Static Analysis Detects", 68)
y = 77
for item in [
    "Mutable default arguments",
    "Deep nesting (configurable threshold)",
    "Bare except: clauses",
    "Excessive function parameters",
    "print() instead of logging",
    "TODO / FIXME / HACK comments",
]:
    pdf._check(item, 15, y, w=120); y += 7

pdf._heading("Rules Engine Checks", 68)
pdf.set_xy(155, 68); pdf.cell(0, 8, "Rules Engine Checks")
y = 77
for item in [
    "PascalCase classes, snake_case functions",
    "Line length limits (configurable)",
    "Hardcoded secrets (passwords, tokens, keys)",
    "Dangerous eval(), exec(), pickle, subprocess",
    "Function complexity scoring",
    "Missing docstrings",
]:
    pdf._check(item, 155, y, w=130); y += 7

pdf._footer_bar(5)

# ═══ SLIDE 6: MULTI-AGENT ═════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Multi-Agent Delegation System")
pdf.set_font("Helvetica", "B", 10)
pdf.set_text_color(*pdf.GREEN)
pdf.text(240, 33, "ENHANCEMENT")

# Agent Coordinator
pdf._heading("Agent Coordinator", 44)
y = 53
for item in [
    "Delegation criteria (configurable thresholds)",
    "Structured message protocol (request -> result)",
    "Full audit trail with handoff records",
    "State management across handoffs",
]:
    pdf._check(item, 15, y, w=120); y += 7

pdf._heading("Delegation Triggers", y + 2)
pdf._table(
    ["Criterion", "Threshold"],
    [
        ["Violations per file", "> 3"],
        ["Complexity score", "> 10"],
        ["Critical severity", "Any"],
    ],
    15, y + 12, [60, 40]
)

# Refactoring Agent
pdf._heading("Refactoring Agent", 44)
pdf.set_xy(155, 44); pdf.cell(0, 8, "Refactoring Agent")
y = 53
for item in [
    "Rename variables to snake_case",
    "Remove unused imports",
    "LLM-powered complex refactoring",
    "Syntax validation via ast.parse()",
    "Content size validation before commit",
    "Commits changes back to PR branch",
]:
    pdf._check(item, 155, y, w=130); y += 7

pdf._heading("Safety Mechanisms", y + 2)
pdf.set_xy(155, y + 2); pdf.cell(0, 8, "Safety Mechanisms")
y += 11
for item in [
    "Infinite loop prevention (agent commit detection)",
    "Content corruption safeguards",
    "Batch commits per file (avoids SHA conflicts)",
]:
    pdf._check(item, 155, y, w=130); y += 7

pdf._footer_bar(6)

# ═══ SLIDE 7: RESULTS ═════════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Results: Live Test Review")
pdf._subtitle(
    "Tested with real PRs containing intentionally flawed Python code "
    "(hardcoded secrets, SQL injection, eval(), deep nesting, bad naming, etc.)",
    y=40
)

pdf._stat_box(15,  56, 40, "Issues Found",       w=55)
pdf._stat_box(78,  56, 15, "Auto-Resolved",      w=55)
pdf._stat_box(141, 56, 25, "Flagged for Review",  w=55)
pdf._stat_box(204, 56, 1,  "Agent Handoffs",      w=55)

# Issue breakdown
pdf._heading("Issue Breakdown by Severity", 92)
pdf._table(
    ["Severity", "Count", "Examples"],
    [
        ["CRITICAL", "5", "Hardcoded secrets, eval(), exec()"],
        ["WARNING", "23", "Naming violations, complexity, nesting"],
        ["INFO", "12", "Missing docstrings, TODOs, print()"],
    ],
    15, 102, [35, 20, 80]
)

# Output formats
pdf._heading("Output Formats", 92)
pdf.set_xy(155, 92); pdf.cell(0, 8, "Output Formats")
y = 102
for item in [
    "JSON: Full review with resolved status",
    "JSONL: Streamable per-finding log",
    "Console: Human-readable summary",
    "GitHub: Inline diff comments + PR summary",
]:
    pdf._check(item, 155, y, w=130); y += 7

pdf._footer_bar(7)

# ═══ SLIDE 8: EXAMPLE OUTPUT ══════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Example: Inline Review Comment")

comment_example = """
  CRITICAL: Use of dangerous function 'eval()' detected.

  What to do: Avoid 'eval()'. Use safer alternatives like ast.literal_eval().

  Current code:
    result = eval(f"self.conn.execute('{raw_query}')")

  Rule: SECURITY_002 | Confidence: 95%
"""
pdf._code_block(comment_example, 15, 42, w=260, size=9)

pdf._heading("Console Output with Resolution Tracking", 100)

console_example = """
  ======================================================================
    CODE REVIEW AGENT  -  ANALYSIS SUMMARY
  ======================================================================

    PR: #5  -  Add authentication service module
    Total Issues: 40
    Resolved: 15  |  Unresolved: 25

    Rule Violations: 28
      [OK]  [WARNING ] Function 'authenticateUser' -> snake_case  (auto-fixed)
      [!!]  [CRITICAL] Possible hardcoded secret detected

    Static Analysis: 12
      [!!]  [WARNING ] Mutable default argument in '__init__'
      [OK]  [WARNING ] Bare 'except:' clause  (auto-fixed)
"""
pdf._code_block(console_example, 15, 110, w=260, size=8)

pdf._footer_bar(8)

# ═══ SLIDE 9: TECH DECISIONS ══════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Architectural Decisions")

pdf._table(
    ["Decision", "Choice", "Rationale"],
    [
        ["Language", "Python", "Rich ecosystem, stdlib ast module, PyGithub"],
        ["LLM Integration", "Multi-provider", "Ollama (free), OpenAI, Anthropic - switchable"],
        ["Rule System", "YAML Config", "Easy customisation without code changes"],
        ["Static Analysis", "AST + Regex", "Zero external deps (tree-sitter as option)"],
        ["Multi-Agent", "Custom Protocol", "Lightweight, deterministic delegation"],
        ["Webhook Server", "FastAPI", "Async, auto OpenAPI docs, Pydantic validation"],
        ["Output", "JSON + JSONL", "Machine-readable, auditable, streamable"],
        ["Comment Placement", "Diff Position", "Inline on exact diff line, not fallback"],
        ["Resolution Track", "Cross-reference", "Shows auto-fixed vs needs human review"],
    ],
    15, 44, [45, 45, 170]
)

pdf._footer_bar(9)

# ═══ SLIDE 10: TESTING ════════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Testing & Quality")

pdf._stat_box(15,  44, 36, "Tests Passing", w=55)
pdf._stat_box(78,  44, 7,  "Test Categories", w=55)
pdf._stat_box(141, 44, 5,  "Live PR Tests", w=55)

pdf._table(
    ["Component", "Tests", "Coverage"],
    [
        ["Diff Parser",        "5", "Hunks, line numbers, empty patches, context"],
        ["Rules Engine",       "9", "All 7 checkers, filtering, scoping, non-Python skip"],
        ["Code Analyzer",      "5", "Bare except, mutable defaults, nesting, params, print"],
        ["Comment Formatter",  "3", "Inline format, violation format, summary generation"],
        ["Refactoring Agent",  "4", "Import removal, naming, action mapping, LLM fallback"],
        ["Agent Coordinator",  "5", "Delegation criteria, handoff lifecycle, messaging"],
        ["End-to-End",         "5", "Full pipeline, dry-run, file output, integration"],
    ],
    15, 80, [50, 15, 195]
)

pdf._footer_bar(10)

# ═══ SLIDE 11: SECURITY ═══════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Security & Observability")

pdf._heading("Security Measures", 44)
y = 53
for item in [
    "All secrets via environment variables (.env, gitignored)",
    "Webhook HMAC SHA-256 signature verification",
    "Rate limit handling with exponential backoff retry",
    "Content validation before committing (size + syntax)",
    "Infinite loop prevention (agent commit detection)",
    "No hardcoded credentials anywhere in codebase",
    ".gitignore protects secrets, logs, and cache files",
]:
    pdf._check(item, 15, y, w=120); y += 7

pdf._heading("Observability", 44)
pdf.set_xy(155, 44); pdf.cell(0, 8, "Observability")
y = 53
for item in [
    "JSON output with full review result",
    "JSONL log (streamable, per-finding)",
    "Console summary with resolved/unresolved markers",
    "Confidence scores on every finding",
    "Resolution tracking (auto-fixed vs flagged)",
    "Coordinator audit trail (message log)",
    "Structured logging with configurable levels",
]:
    pdf._check(item, 155, y, w=130); y += 7

pdf._footer_bar(11)

# ═══ SLIDE 12: NEXT STEPS ═════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf._title("Known Limitations & Next Steps")

pdf._heading("Current Limitations", 44)
y = 53
for item in [
    "LLM review requires running Ollama or API key (graceful fallback)",
    "Python-only static analysis",
    "Single-file refactoring scope (no cross-file analysis)",
    "Complex refactoring quality depends on LLM model",
    "Inline comments only for lines within the diff",
]:
    pdf._bullet(item, 15, y, w=120); y += 7

pdf._heading("Planned Enhancements (with more time)", 44)
pdf.set_xy(155, 44); pdf.cell(0, 8, "Planned Enhancements (with more time)")
y = 53
for item in [
    "Verification agent: run tests after refactoring",
    "Rollback capability on test failure",
    "Multi-language support via Tree-sitter",
    "Test coverage analysis + suggestions",
    "Caching layer for LLM responses",
    "GitHub Actions: reusable action package",
    "Dashboard for analysis history & trends",
    "Batch comments on adjacent lines",
]:
    pdf._bullet(item, 155, y, w=130); y += 7

pdf._footer_bar(12)

# ═══ SLIDE 13: THANK YOU ══════════════════════════════════════════
pdf.add_page()
pdf._bg()
pdf.set_font("Helvetica", "B", 36)
pdf.set_text_color(*pdf.ACCENT)
pdf.set_xy(0, 60)
pdf.cell(pdf.w, 16, "Thank You", align="C")

pdf.set_font("Helvetica", "", 16)
pdf.set_text_color(*pdf.TEXT)
pdf.set_xy(0, 85)
pdf.cell(pdf.w, 10, "Automated Code Review Agent", align="C")

pdf.set_font("Helvetica", "", 12)
pdf.set_text_color(*pdf.MUTED)
pdf.set_xy(0, 105)
pdf.cell(pdf.w, 8, "github.com/DevGuyWilly/pr-review-agent", align="C")

pdf.set_font("Helvetica", "", 12)
pdf.set_text_color(*pdf.TEXT)
pdf.set_xy(0, 120)
pdf.cell(pdf.w, 8, "Wilson Dagah", align="C")

pdf._footer_bar(13)

# ── Save ──────────────────────────────────────────────────────────
output_path = "/Users/willydee/Documents/description/presentation.pdf"
pdf.output(output_path)
print(f"PDF saved to: {output_path}")
