"""Core entities and validation rules of the vulnerability registry."""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any, Optional

from .errors import ValidationError

# Wire values are kept identical to the original project's API contract.
SEVERITIES = ("baja", "media", "alta", "critica")
STATES = ("abierta", "en_revision", "mitigada", "cerrada")
IDENTIFIER_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|CWE-\d{1,4})$")
MAX_TITLE = 200

# Scan severities (English) -> registry severities / default CVSS score.
SCAN_TO_REGISTRY_SEVERITY = {"low": "baja", "medium": "media", "high": "alta", "critical": "critica"}
DEFAULT_CVSS = {"low": 3.1, "medium": 5.5, "high": 7.8, "critical": 9.5}


@dataclass(frozen=True)
class Vulnerability:
    titulo: str
    cve_codigo: str
    severidad: str
    estado: str
    puntaje_cvss: float
    id: Optional[int] = None

    @classmethod
    def from_payload(cls, data: Any, id: Optional[int] = None) -> "Vulnerability":
        if not isinstance(data, dict):
            raise ValidationError("Send a JSON object")
        clean = {}
        for field in ("titulo", "cve_codigo", "severidad", "estado"):
            value = data.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{field} must be a non-empty string")
            clean[field] = value.strip()
        if len(clean["titulo"]) > MAX_TITLE:
            raise ValidationError(f"titulo must be at most {MAX_TITLE} characters")
        if not IDENTIFIER_RE.match(clean["cve_codigo"]):
            raise ValidationError("cve_codigo must look like CVE-YYYY-NNNN (e.g. CVE-2024-12345) or CWE-NNN")
        if clean["severidad"] not in SEVERITIES:
            raise ValidationError("severidad must be one of: " + ", ".join(SEVERITIES))
        if clean["estado"] not in STATES:
            raise ValidationError("estado must be one of: " + ", ".join(STATES))
        score = data.get("puntaje_cvss")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) \
                or score < 0 or score > 10:
            raise ValidationError("puntaje_cvss must be a number between 0 and 10")
        return cls(id=id, puntaje_cvss=float(score), **clean)

    @property
    def fingerprint(self) -> str:
        """Stable hash of every business field: two records are 'exactly equal' iff this matches."""
        raw = "\x1f".join([self.titulo, self.cve_codigo, self.severidad, self.estado, repr(self.puntaje_cvss)])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {"id": self.id, "titulo": self.titulo, "cve_codigo": self.cve_codigo,
                "severidad": self.severidad, "estado": self.estado, "puntaje_cvss": self.puntaje_cvss}
