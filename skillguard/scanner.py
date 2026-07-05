"""Scanner: walk a skill/plugin directory and apply the rule engine.

A "skill" in the agent ecosystem is typically a folder containing a
SKILL.md (or CLAUDE.md) plus optional scripts, hooks, and a plugin
manifest. SkillGuard reads every relevant file's *content* and reports
findings. This is the layer package scanners never look at.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .rules import Finding, SEVERITY_ORDER, run_rules


# Files whose content we inspect. Markdown/instruction files are the
# prompt-injection surface; scripts are the code-execution surface.
_SCANNABLE_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".mdx",
    ".sh", ".bash", ".zsh",
    ".py", ".js", ".ts", ".rb", ".pl",
    ".json", ".yaml", ".yml", ".toml",
}

# Named files always worth scanning even without a recognised extension.
_ALWAYS_SCAN_NAMES = {
    "skill.md", "claude.md", "agents.md", "readme.md",
    "dockerfile", "makefile", ".cursorrules",
}

# Directories we never descend into.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
              "dist", "build", ".mypy_cache", ".pytest_cache"}

_MAX_FILE_BYTES = 2 * 1024 * 1024  # skip files larger than 2 MB

_IGNORE_FILE = ".skillguardignore"


@dataclass
class FileReport:
    path: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class ScanResult:
    root: str
    file_reports: List[FileReport] = field(default_factory=list)
    files_scanned: int = 0
    skipped: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for fr in self.file_reports:
            out.extend(fr.findings)
        return out

    def severity_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def max_severity_rank(self) -> int:
        return max((f.severity_rank() for f in self.findings), default=-1)

    def risk_score(self) -> int:
        """A 0-100 risk score weighted by severity. Saturates at 100."""
        weights = {"critical": 40, "high": 15, "medium": 5, "low": 2, "info": 0}
        score = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(score, 100)


def _should_scan(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name in _ALWAYS_SCAN_NAMES:
        return True
    _, ext = os.path.splitext(name)
    return ext in _SCANNABLE_EXTENSIONS


def _load_ignore_patterns(root: str) -> List[str]:
    patterns: List[str] = []
    ignore_path = os.path.join(root, _IGNORE_FILE) if os.path.isdir(root) else None
    if ignore_path and os.path.isfile(ignore_path):
        with open(ignore_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


def _is_excluded(rel_path: str, patterns: List[str]) -> bool:
    rel_posix = rel_path.replace(os.sep, "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat + "/*"):
            return True
        # Allow bare directory names like "tests" to match anything beneath.
        if rel_posix == pat or rel_posix.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def _iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def scan_path(root: str, exclude: Optional[List[str]] = None) -> ScanResult:
    root = os.path.abspath(root)
    result = ScanResult(root=root)
    patterns = list(exclude or []) + _load_ignore_patterns(root)
    base = root if os.path.isdir(root) else os.path.dirname(root)

    for path in _iter_files(root):
        if not _should_scan(path):
            continue
        rel = os.path.relpath(path, base)
        if patterns and _is_excluded(rel, patterns):
            result.skipped.append(path)
            continue
        try:
            if os.path.getsize(path) > _MAX_FILE_BYTES:
                result.skipped.append(path)
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, UnicodeError) as exc:
            result.file_reports.append(FileReport(path=path, error=str(exc)))
            continue

        result.files_scanned += 1
        findings = run_rules(text)
        if findings:
            findings.sort(key=lambda f: (-f.severity_rank(), f.line))
            result.file_reports.append(FileReport(path=path, findings=findings))

    return result
