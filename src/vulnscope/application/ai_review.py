"""AI code review: the model reads the scanned source files and reports vulnerabilities by itself.

Unlike AIAdvisor (which only explains findings the static rules already produced), this module is what makes
the AI actually *analyse* the code, so a project the rules know nothing about (any language, any bug class)
still gets a real review. The model output is untrusted: every field is validated and clamped before it becomes
a finding, and a finding must point at a line that really exists in the file.
"""
from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Dict, List, Optional, Tuple

from ..domain.errors import AIUnavailableError
from ..domain.redaction import redact
from ..domain.risk import CATS
from ..domain.rules import AI_RULE_ID, CODE, TEMPLATES
from ..domain.scanner import ArchiveContents
from .ports import AIClient

log = logging.getLogger("vulnscope.ai")

SEVERITIES = ("critical", "high", "medium", "low")
CWE_RE = re.compile(r"^CWE-\d{1,4}$")
REVIEWABLE_EXTS = CODE | TEMPLATES | frozenset({".sh", ".bash", ".sql", ".kt", ".swift"})

MAX_CHUNKS = 10          # model calls per scan
CHUNK_CHARS = 12_000     # source characters per call
WORKERS = 4
BUDGET_SECONDS = 50      # total wall-clock budget for the whole review
MAX_AI_FINDINGS = 60
CONTEXT = 2
REVIEW_TOKENS = 2200

_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


# ------------------------------------------------------------------ validation helpers (also used for payloads
def _txt(value, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def meta_from_payload(payload: dict) -> Tuple[str, str, str, str, str, str]:
    """(title, cwe, severity, category, fix, example) for an AI finding sent back by the browser. Never trusted."""
    title = _txt(payload.get("title"), 120) or "Issue found by AI code review"
    cwe = payload.get("cwe") if isinstance(payload.get("cwe"), str) and CWE_RE.match(payload["cwe"]) else "CWE-710"
    sev = payload.get("severity") if payload.get("severity") in SEVERITIES else "medium"
    cat = payload.get("category") if payload.get("category") in CATS else "exposure"
    return title, cwe, sev, cat, _txt(payload.get("fix"), 600), _txt(payload.get("example"), 600)


def parse_model_json(text: str) -> Optional[list]:
    """Extract the JSON array from a model answer, tolerating markdown fences and surrounding prose."""
    if not isinstance(text, str):
        return None
    body = _FENCE.sub("", text.strip()).strip()
    candidates = [body]
    a, b = body.find("["), body.rfind("]")
    if 0 <= a < b:
        candidates.append(body[a:b + 1])
    for c in candidates:
        try:
            data = json.loads(c)
        except ValueError:
            continue
        if isinstance(data, dict):
            data = data.get("findings") or data.get("vulnerabilities") or data.get("issues")
        if isinstance(data, list):
            return data
    return None


# ------------------------------------------------------------------ chunking
class _Chunk:
    __slots__ = ("path", "start", "end", "total", "lines")

    def __init__(self, path, start, end, total, lines):
        self.path, self.start, self.end, self.total, self.lines = path, start, end, total, lines


def _chunks_for(path: str, text: str) -> List[_Chunk]:
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        size, j = 0, i
        while j < len(lines) and (size + len(lines[j]) + 8 <= CHUNK_CHARS or j == i):
            size += min(len(lines[j]), 400) + 8
            j += 1
        out.append(_Chunk(path, i + 1, j, len(lines), lines))
        i = j
    return out


def _render(chunk: _Chunk) -> str:
    return "\n".join(f"{n:>5}| {redact(chunk.lines[n - 1][:400])}" for n in range(chunk.start, chunk.end + 1))


def _prompt(chunk: _Chunk, lang: str) -> str:
    human = "Spanish" if lang == "es" else "English"
    return (
        f"Review this source code for security vulnerabilities.\nFile: {redact(chunk.path[:200])} "
        f"(lines {chunk.start}-{chunk.end} of {chunk.total}). Each line starts with its line number and a '|'.\n"
        f"<code>\n{_render(chunk)}\n</code>\n\n"
        "Return ONLY a JSON array, no markdown and no prose. Each element must be an object with exactly these keys:\n"
        '  "line": number of the first affected line (as shown on the left),\n'
        '  "title": short name of the problem,\n'
        '  "severity": one of "critical", "high", "medium", "low",\n'
        '  "category": one of "injection", "secrets", "execution", "exposure",\n'
        '  "cwe": the closest CWE id such as "CWE-120",\n'
        '  "explanation": 1-2 sentences on why this line is a problem and how it could be exploited,\n'
        '  "fix": how to fix it,\n'
        '  "example": the corrected code (may be an empty string).\n'
        "Report only real security problems you can tie to a specific line (memory safety, injection, unsafe "
        "functions, missing validation, hard-coded secrets, weak crypto, unsafe configuration, logic flaws that "
        "bypass authorisation). Do not report style issues. If there is nothing wrong return [].\n"
        f'Keep the JSON keys and the enum values in English; write "title", "explanation" and "fix" in {human}.')


# ------------------------------------------------------------------ the reviewer
class CodeReviewer:
    def __init__(self, client: Optional[AIClient], system_prompt):
        self.client, self._system = client, system_prompt

    def _select(self, contents: ArchiveContents, static: List[dict]) -> List[_Chunk]:
        hits: Dict[str, int] = {}
        for f in static:
            hits[f["path"]] = hits.get(f["path"], 0) + 1
        files = [f for f in contents.files
                 if f.content and f.content.strip() and os.path.splitext(f.path.lower())[1] in REVIEWABLE_EXTS]
        files.sort(key=lambda f: (-hits.get(f.path, 0), -len(f.content)))
        chunks: List[_Chunk] = []
        for f in files:
            chunks.extend(_chunks_for(f.path, f.content))
        return chunks

    def review(self, contents: ArchiveContents, static: List[dict], lang: str = "en") -> dict:
        info = {"status": "disabled", "engine": None, "chunks": 0, "chunks_ok": 0, "files_reviewed": 0,
                "truncated": False, "added": 0}
        if self.client is None:
            return {"findings": [], "info": info}
        info["engine"] = self.client.name
        chunks = self._select(contents, static)
        if not chunks:
            info["status"] = "nothing_to_review"
            return {"findings": [], "info": info}
        info["truncated"] = len(chunks) > MAX_CHUNKS
        chunks = chunks[:MAX_CHUNKS]
        info["chunks"] = len(chunks)
        info["files_reviewed"] = len({c.path for c in chunks})

        system = self._system(lang)
        pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="ai-review")
        futures = {pool.submit(self.client.complete, system, _prompt(c, lang), REVIEW_TOKENS): c for c in chunks}
        done, pending = wait(futures, timeout=BUDGET_SECONDS)
        pool.shutdown(wait=False, cancel_futures=True)

        unavailable = invalid = 0
        raw: List[Tuple[_Chunk, dict]] = []
        for fut in done:
            chunk = futures[fut]
            try:
                items = parse_model_json(fut.result())
            except AIUnavailableError:
                unavailable += 1
                continue
            except Exception:  # noqa: BLE001 - one bad call must never break the scan
                log.exception("AI review call failed")
                unavailable += 1
                continue
            if items is None:
                invalid += 1
                continue
            info["chunks_ok"] += 1
            raw.extend((chunk, it) for it in items[:25] if isinstance(it, dict))
        unavailable += len(pending)

        taken = {(f["path"], f["line"]) for f in static}
        found: List[dict] = []
        seen = set()
        for chunk, it in raw:
            f = self._to_finding(chunk, it)
            if f is None:
                continue
            key = (f["path"], f["line"])
            if key in taken or (key, f["title"].lower()) in seen:
                continue
            seen.add((key, f["title"].lower()))
            found.append(f)
            if len(found) >= MAX_AI_FINDINGS:
                break
        info["added"] = len(found)
        if info["chunks_ok"] == 0:
            info["status"] = "unavailable" if unavailable >= invalid else "invalid_response"
        else:
            info["status"] = "ok" if info["chunks_ok"] == info["chunks"] else "partial"
        return {"findings": found, "info": info}

    @staticmethod
    def _to_finding(chunk: _Chunk, it: dict) -> Optional[dict]:
        try:
            line = int(it.get("line"))
        except (TypeError, ValueError):
            return None
        if not chunk.start <= line <= chunk.end:
            return None  # the model invented a line: discard
        title, cwe, sev, cat, fix, example = meta_from_payload(it)
        if not _txt(it.get("title"), 120):
            return None
        lo, hi = max(1, line - CONTEXT), min(chunk.total, line + CONTEXT)
        ctx = [{"n": n, "text": redact(chunk.lines[n - 1][:200]), "hit": n == line} for n in range(lo, hi + 1)]
        return {"rule_id": AI_RULE_ID, "source": "ai", "title": title, "cwe": cwe, "severity": sev, "category": cat,
                "path": chunk.path, "line": line, "context": ctx, "fix": fix or "See the explanation.",
                "explanation": _txt(it.get("explanation"), 600), "example": example}
