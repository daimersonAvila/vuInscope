"""Secret redaction: applied to every snippet before it leaves the scanner (UI, AI, reports)."""
import re

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"),
    # name = "value" for secret-looking names
    re.compile(r"""(?i)((?:password|passwd|pwd|secret|api[_-]?key|token|private_key|clave)\w*['"\]]*\s*[:=]\s*)(['"])[^'"\n]{3,}\2"""),
    # "admin": "hunter2" style default credentials
    re.compile(r"""(?i)((?:['"](?:admin|root)['"])\s*:\s*)(['"])[^'"\n]{3,}\2"""),
]


def redact(text: str) -> str:
    out = text
    for i, pat in enumerate(_PATTERNS):
        if i >= 6:
            out = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]{m.group(2)}", out)
        elif i == 5:
            out = pat.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out
