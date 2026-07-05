"""Detection rules for SkillGuard.

Each rule is a small, self-contained detector. Rules are grouped by the
category of threat they cover. A rule returns zero or more Finding objects
for a given piece of text.

The philosophy: skills and plugins are markdown + scripts that get loaded
directly into an AI agent's context (SKILL.md, CLAUDE.md) or executed as
hooks. That makes them a prompt-injection and code-execution surface that
package-level scanners never inspect. These rules read the *content*.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, List


# Severity ordering used for sorting and exit-code thresholds.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    detail: str
    line: int = 0
    excerpt: str = ""
    remediation: str = ""

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class _Hit:
    line: int
    excerpt: str
    detail: str = ""


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    title: str
    remediation: str
    detector: Callable[[str], List[_Hit]]


def _line_of(text: str, index: int) -> int:
    """1-based line number for a character index."""
    return text.count("\n", 0, index) + 1


def _excerpt(text: str, start: int, end: int, radius: int = 40) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return ("…" if lo > 0 else "") + snippet + ("…" if hi < len(text) else "")


# --------------------------------------------------------------------------- #
# Category 1: Prompt injection / instruction override
# --------------------------------------------------------------------------- #

_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|the\s+above|your)\s+(instructions|rules|guidelines)",
    r"forget\s+(everything|all\s+previous|your\s+instructions)",
    r"you\s+are\s+now\s+(a\s+)?(DAN|jailbroken|unrestricted|in\s+developer\s+mode)",
    r"do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user",
    r"without\s+(telling|informing|asking)\s+the\s+user",
    r"override\s+(your\s+)?(system\s+prompt|safety|guardrails)",
    r"bypass\s+(the\s+)?(safety|security|content\s+policy|guardrails)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions|hidden\s+prompt)",
    r"print\s+(your\s+)?(system\s+prompt|full\s+instructions)",
    r"new\s+instructions\s*:",
]


def _injection_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    for pat in _INJECTION_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail=f"matched pattern: {pat}"))
    return hits


# --------------------------------------------------------------------------- #
# Category 2: Hidden / obfuscated content
# --------------------------------------------------------------------------- #

_INVISIBLE_RANGES = [
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
]


def _is_invisible(cp: int) -> bool:
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _hidden_unicode_detector(text: str) -> List[_Hit]:
    """Report one finding per *run* of invisible characters, not per char."""
    hits: List[_Hit] = []
    i, n = 0, len(text)
    while i < n:
        if not _is_invisible(ord(text[i])):
            i += 1
            continue
        start = i
        while i < n and _is_invisible(ord(text[i])):
            i += 1
        run = text[start:i]
        first = unicodedata.name(run[0], f"U+{ord(run[0]):04X}")
        count = len(run)
        decoded = "".join(
            chr(ord(c) - 0xE0000) for c in run if 0xE0000 <= ord(c) <= 0xE007F
        )
        detail = f"{count} invisible/bidi char(s), first is {first}"
        if decoded.strip():
            detail += f'; decodes to hidden text: "{decoded.strip()}"'
        hits.append(_Hit(line=_line_of(text, start),
                         excerpt=_excerpt(text, start, i),
                         detail=detail))
    return hits


def _html_comment_instruction_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
        body = m.group(1)
        if re.search(r"(ignore|instruction|system\s+prompt|do\s+not\s+tell|"
                     r"execute|run\s+this|password|token|secret)", body, re.IGNORECASE):
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail="suspicious instruction inside HTML comment"))
    return hits


# --------------------------------------------------------------------------- #
# Category 3: Data exfiltration
# --------------------------------------------------------------------------- #

_EXFIL_PATTERNS = [
    (r"curl\s+[^\n|]*(-d|--data|-F|--form|-T|--upload-file)\s", "curl uploading data to a remote host"),
    (r"curl\s+[^\n]*\|\s*(bash|sh|zsh)", "curl piped directly into a shell (remote code execution)"),
    (r"wget\s+[^\n]*\|\s*(bash|sh|zsh)", "wget piped directly into a shell"),
    (r"wget\s+[^\n]*--post-(data|file)", "wget posting data to a remote host"),
    (r"(cat|type)\s+[^\n]*(\.env|\.aws/credentials|\.ssh/id_|credentials|secrets)", "reading credential/secret files"),
    (r"(https?://[^\s\"']*\?[^\s\"']*=)\s*\$?\{?[A-Z_]{3,}", "sending a variable/secret in a URL query string"),
    (r"nc\s+(-[a-z]+\s+)*[\w.-]+\s+\d+", "netcat connection (possible reverse shell / exfil)"),
    (r"/dev/tcp/\d", "raw /dev/tcp socket (possible reverse shell)"),
    (r"base64\s+[^\n]*\|\s*(curl|wget|nc)", "base64-encoding data before sending it off-host"),
]


def _exfil_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    for pat, detail in _EXFIL_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail=detail))
    return hits


# --------------------------------------------------------------------------- #
# Category 4: Dangerous shell / destructive commands
# --------------------------------------------------------------------------- #

_DANGEROUS_PATTERNS = [
    (r"rm\s+-rf?\s+(/|~|\$HOME|\*)", "recursive delete of home/root/wildcard"),
    (r":\(\)\s*\{\s*:\|:&\s*\}\s*;", "fork bomb"),
    (r"chmod\s+-R?\s*777\s+/", "world-writable permissions on a broad path"),
    (r"dd\s+if=/dev/(zero|random)\s+of=/dev/", "raw disk overwrite"),
    (r"mkfs\.\w+\s+/dev/", "formatting a block device"),
    (r">\s*/dev/sd[a-z]", "writing directly to a disk device"),
    (r"eval\s+[\"']?\$\(", "eval of a command substitution"),
    (r"(sudo\s+)?(systemctl|service)\s+\w+\s+(stop|disable)\s+(firewalld|ufw|apparmor|auditd)", "disabling security services"),
    (r"history\s+-c", "clearing shell history (anti-forensics)"),
    (r"(export\s+)?HISTFILE=/dev/null", "disabling shell history (anti-forensics)"),
]


def _dangerous_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    for pat, detail in _DANGEROUS_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail=detail))
    return hits


# --------------------------------------------------------------------------- #
# Category 5: Secrets committed into the skill itself
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}", "Anthropic API key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style secret key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"gh[opsu]_[A-Za-z0-9]{36}", "GitHub token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----", "embedded private key"),
    (r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']", "hardcoded credential"),
]


def _secret_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    seen = set()
    for pat, detail in _SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            key = (m.start(), m.end())
            if key in seen:
                continue
            seen.add(key)
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail=detail))
    return hits


# --------------------------------------------------------------------------- #
# Category 6: Suspicious network endpoints referenced from a skill
# --------------------------------------------------------------------------- #

_URL_RE = re.compile(r"https?://([a-z0-9.\-]+)(:\d+)?(/[^\s\"'`)]*)?", re.IGNORECASE)

_ALLOWLIST_HOSTS = {
    "github.com", "githubusercontent.com", "docs.claude.com", "claude.com",
    "anthropic.com", "example.com", "localhost", "pypi.org", "npmjs.com",
    "python.org", "mozilla.org",
}

_SUSPICIOUS_TLDS = re.compile(r"\.(ru|tk|top|xyz|gq|cf|ml|zip|mov|click)$", re.IGNORECASE)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "cutt.ly"}


def _suspicious_url_detector(text: str) -> List[_Hit]:
    hits: List[_Hit] = []
    for m in _URL_RE.finditer(text):
        host = m.group(1).lower()
        base = ".".join(host.split(".")[-2:])
        reasons = []
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            reasons.append("hardcoded raw IP address")
        if _SUSPICIOUS_TLDS.search(host):
            reasons.append("high-risk TLD")
        if base in _SHORTENERS:
            reasons.append("URL shortener hides destination")
        if reasons and base not in _ALLOWLIST_HOSTS:
            hits.append(_Hit(line=_line_of(text, m.start()),
                             excerpt=_excerpt(text, m.start(), m.end()),
                             detail="; ".join(reasons)))
    return hits


# --------------------------------------------------------------------------- #
# Rule registry
# --------------------------------------------------------------------------- #

RULES: List[Rule] = [
    Rule("SG001", "prompt-injection", "high",
         "Instruction-override / prompt-injection phrasing",
         "Remove imperative instructions that try to override the agent's system prompt or hide actions from the user.",
         _injection_detector),
    Rule("SG002", "hidden-content", "critical",
         "Invisible or bidirectional Unicode characters",
         "Strip zero-width, bidi-override, and Unicode tag characters. They are invisible to reviewers but reach the model.",
         _hidden_unicode_detector),
    Rule("SG003", "hidden-content", "high",
         "Instructions hidden in HTML comments",
         "Move real content out of HTML comments; comments are invisible in rendered markdown but still fed to the model.",
         _html_comment_instruction_detector),
    Rule("SG004", "exfiltration", "critical",
         "Possible data exfiltration",
         "Do not upload local files/secrets to remote hosts or pipe remote content into a shell.",
         _exfil_detector),
    Rule("SG005", "dangerous-command", "critical",
         "Destructive or anti-forensic shell command",
         "Remove destructive commands; a skill should never delete broad paths, format disks, or clear history.",
         _dangerous_detector),
    Rule("SG006", "secret", "high",
         "Hardcoded secret or credential",
         "Never commit API keys, tokens, or private keys into a skill. Rotate any exposed credential immediately.",
         _secret_detector),
    Rule("SG007", "suspicious-network", "medium",
         "Suspicious network endpoint",
         "Verify hardcoded IPs, high-risk TLDs, and URL shorteners; prefer named, documented hosts.",
         _suspicious_url_detector),
]


def run_rules(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for rule in RULES:
        for hit in rule.detector(text):
            findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                detail=hit.detail or rule.title,
                line=hit.line,
                excerpt=hit.excerpt,
                remediation=rule.remediation,
            ))
    return findings
