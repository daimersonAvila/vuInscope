"""Static scanner: pure function over in-memory files. Never executes or imports scanned code."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .redaction import redact
from .rules import FILE_RULES, RULES, find_rule_meta

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MAX_FINDINGS = 1500
MAX_PER_RULE_PER_FILE = 15
MAX_LINE_LEN = 1000
CONTEXT = 2
COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", "--")


@dataclass(frozen=True)
class SourceFile:
    path: str
    size: int
    content: Optional[str] = None  # None when not readable text (binary / too large / unsupported)


@dataclass
class ArchiveContents:
    files: List[SourceFile]
    ignored_dirs: List[str] = field(default_factory=list)  # e.g. ['.venv', 'node_modules']
    skipped_unsafe: int = 0
    skipped_large: int = 0
    truncated: bool = False


def _ext(path: str) -> str:
    base = os.path.basename(path).lower()
    if base.startswith("dockerfile"):
        return ".dockerfile"
    return os.path.splitext(base)[1]


def scan(contents: ArchiveContents) -> dict:
    findings: List[dict] = []
    scanned = 0
    seen = set()

    def add(rule_id, path, line, context):
        key = (rule_id, path, line)
        if key in seen or len(findings) >= MAX_FINDINGS:
            return
        seen.add(key)
        title, cwe, sev, cat, fix, example = find_rule_meta(rule_id)
        findings.append({"rule_id": rule_id, "title": title, "cwe": cwe, "severity": sev, "category": cat,
                         "path": path, "line": line, "context": context, "fix": fix, "example": example})

    for f in contents.files:
        for fid, _title, _cwe, _sev, _cat, rx, _fix in FILE_RULES:
            if rx.search(f.path):
                add(fid, f.path, 0, [])
        if f.content is None:
            continue
        scanned += 1
        ext = _ext(f.path)
        lines = f.content.splitlines()
        per_rule: Dict[str, int] = {}
        for rule in RULES:
            if rule.exts is not None and ext not in rule.exts:
                continue
            for idx, raw in enumerate(lines):
                if per_rule.get(rule.id, 0) >= MAX_PER_RULE_PER_FILE:
                    break
                line = raw[:MAX_LINE_LEN]
                stripped = line.lstrip()
                if rule.category != "secrets" and stripped.startswith(COMMENT_PREFIXES):
                    continue
                m = rule.pattern.search(line)
                if not m or (rule.validator and not rule.validator(m)):
                    continue
                per_rule[rule.id] = per_rule.get(rule.id, 0) + 1
                lo, hi = max(0, idx - CONTEXT), min(len(lines), idx + CONTEXT + 1)
                ctx = [{"n": n + 1, "text": redact(lines[n][:200]), "hit": n == idx} for n in range(lo, hi)]
                add(rule.id, f.path, idx + 1, ctx)

    if contents.ignored_dirs:
        heavy = sorted({d for d in contents.ignored_dirs if d in {".venv", "venv", "env", "node_modules", "site-packages"}})
        if heavy:
            add("FIL004", ", ".join(heavy), 0, [])

    findings.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x["path"], x["line"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "findings": findings,
        "stats": {"files_total": len(contents.files), "files_scanned": scanned,
                  "ignored_dirs": sorted(set(contents.ignored_dirs)), "skipped_unsafe": contents.skipped_unsafe,
                  "skipped_large": contents.skipped_large, "truncated": contents.truncated,
                  "by_severity": counts, "total": len(findings)},
    }
