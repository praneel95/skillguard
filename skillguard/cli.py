"""SkillGuard command-line interface.

    skillguard scan <path> [--format text|json|sarif] [--fail-on LEVEL]
                           [--no-color] [--output FILE]

Exit codes:
    0  clean, or findings below the --fail-on threshold
    1  findings at or above the --fail-on threshold
    2  usage / runtime error
"""

from __future__ import annotations

import argparse
import sys

from .rules import RULES, SEVERITY_ORDER
from .report import render_json, render_sarif, render_terminal
from .scanner import scan_path

__version__ = "0.1.0"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillguard",
        description="Static security scanner for AI agent skills and plugins "
                    "(SKILL.md, CLAUDE.md, hooks, and bundled scripts).",
    )
    p.add_argument("--version", action="version",
                   version=f"skillguard {__version__}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a skill/plugin path.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument("--format", choices=["text", "json", "sarif"],
                      default="text", help="Output format (default: text).")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER.keys()),
                      default="high",
                      help="Minimum severity that triggers a non-zero exit "
                           "(default: high).")
    scan.add_argument("--no-color", action="store_true",
                      help="Disable ANSI colour in text output.")
    scan.add_argument("--output", "-o", help="Write the report to a file.")
    scan.add_argument("--exclude", action="append", default=[],
                      metavar="GLOB",
                      help="Path glob to skip (repeatable). Also reads .skillguardignore.")

    rules_cmd = sub.add_parser("rules", help="List the detection rules.")
    rules_cmd.add_argument("--format", choices=["text", "json"], default="text")

    return p


def _cmd_rules(args) -> int:
    if args.format == "json":
        import json
        print(json.dumps([
            {"id": r.id, "category": r.category, "severity": r.severity,
             "title": r.title, "remediation": r.remediation}
            for r in RULES
        ], indent=2))
    else:
        for r in RULES:
            print(f"{r.id}  [{r.severity:<8}] {r.category:<18} {r.title}")
    return 0


def _cmd_scan(args) -> int:
    result = scan_path(args.path, exclude=args.exclude)

    if args.format == "json":
        out = render_json(result)
    elif args.format == "sarif":
        out = render_sarif(result)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty() and not args.output
        out = render_terminal(result, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"Report written to {args.output}")
    else:
        print(out)

    threshold = SEVERITY_ORDER[args.fail_on]
    if result.max_severity_rank() >= threshold:
        return 1
    return 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
