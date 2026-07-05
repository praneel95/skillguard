"""SkillGuard — static security scanner for AI agent skills and plugins."""

from .scanner import scan_path, ScanResult, FileReport
from .rules import Finding, RULES, run_rules

__version__ = "0.1.0"
__all__ = ["scan_path", "ScanResult", "FileReport", "Finding", "RULES", "run_rules"]
