"""Output formatters for SkillGuard: terminal, JSON, and SARIF."""

from __future__ import annotations

import json
import os
from typing import Dict

from .scanner import ScanResult


_COLORS = {
    "critical": "\033[41m\033[97m",  # white on red
    "high": "\033[91m",              # red
    "medium": "\033[93m",            # yellow
    "low": "\033[94m",               # blue
    "info": "\033[90m",              # grey
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[92m",
}


def _c(key: str, use_color: bool) -> str:
    return _COLORS.get(key, "") if use_color else ""


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
    except ValueError:
        return path


def render_terminal(result: ScanResult, use_color: bool = True) -> str:
    R = lambda k: _c(k, use_color)
    lines = []
    lines.append(f"{R('bold')}SkillGuard scan:{R('reset')} {result.root}")
    lines.append(f"{R('dim')}{result.files_scanned} file(s) scanned"
                 f"{R('reset')}")
    lines.append("")

    if not result.findings:
        lines.append(f"{R('green')}✓ No security findings.{R('reset')}")
        return "\n".join(lines)

    for fr in result.file_reports:
        if not fr.findings:
            continue
        lines.append(f"{R('bold')}{_rel(fr.path, result.root)}{R('reset')}")
        for f in fr.findings:
            badge = f"{R(f.severity)} {f.severity.upper()} {R('reset')}"
            lines.append(f"  {badge} [{f.rule_id}] {f.title}  "
                         f"{R('dim')}(line {f.line}){R('reset')}")
            lines.append(f"      {f.detail}")
            if f.excerpt:
                lines.append(f"      {R('dim')}> {f.excerpt}{R('reset')}")
        lines.append("")

    counts = result.severity_counts()
    summary = "  ".join(
        f"{R(s)} {counts[s]} {s} {R('reset')}"
        for s in ("critical", "high", "medium", "low")
        if counts[s]
    )
    lines.append(f"{R('bold')}Summary:{R('reset')} {summary}")
    lines.append(f"{R('bold')}Risk score:{R('reset')} {result.risk_score()}/100")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload: Dict = {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score(),
        "severity_counts": result.severity_counts(),
        "findings": [
            {
                "file": _rel(fr.path, result.root),
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "line": f.line,
                "excerpt": f.excerpt,
                "remediation": f.remediation,
            }
            for fr in result.file_reports
            for f in fr.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# Minimal SARIF 2.1.0 so results drop into GitHub code scanning.
_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note", "info": "note"}


def render_sarif(result: ScanResult) -> str:
    rules_seen: Dict[str, Dict] = {}
    sarif_results = []
    for fr in result.file_reports:
        for f in fr.findings:
            rules_seen.setdefault(f.rule_id, {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "helpUri": "https://github.com/skillguard/skillguard",
                "properties": {"category": f.category},
            })
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.detail} ({f.severity})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _rel(fr.path, result.root)},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }],
            })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SkillGuard",
                "informationUri": "https://github.com/skillguard/skillguard",
                "version": "0.1.0",
                "rules": list(rules_seen.values()),
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
