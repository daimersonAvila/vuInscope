"""SQLite adapter implementing VulnerabilityRepository and StateHistoryRepository."""
from __future__ import annotations

import os
import sqlite3
from collections import defaultdict
from contextlib import closing
from typing import List, Optional

from ...domain.errors import DuplicateVulnerabilityError
from ...domain.models import Vulnerability

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    cve_codigo TEXT NOT NULL,
    severidad TEXT NOT NULL CHECK (severidad IN ('baja','media','alta','critica')),
    estado TEXT NOT NULL CHECK (estado IN ('abierta','en_revision','cerrada','mitigada')),
    puntaje_cvss REAL NOT NULL CHECK (puntaje_cvss >= 0 AND puntaje_cvss <= 10),
    fingerprint TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS historial_estados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id INTEGER NOT NULL REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
    estado TEXT NOT NULL,
    fecha TEXT NOT NULL DEFAULT (datetime('now'))
);
"""
COLS = "id, titulo, cve_codigo, severidad, estado, puntaje_cvss"


def _row(r) -> Vulnerability:
    return Vulnerability(id=r["id"], titulo=r["titulo"], cve_codigo=r["cve_codigo"], severidad=r["severidad"],
                         estado=r["estado"], puntaje_cvss=r["puntaje_cvss"])


class SqliteStore:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with closing(self._conn()) as c:
            if path != ":memory:":
                c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            c.commit()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    # -- VulnerabilityRepository -------------------------------------------
    def add(self, v: Vulnerability) -> Vulnerability:
        with closing(self._conn()) as c:
            dup = c.execute("SELECT id FROM vulnerabilidades WHERE fingerprint=?", (v.fingerprint,)).fetchone()
            if dup:
                raise DuplicateVulnerabilityError(dup["id"])
            try:
                cur = c.execute(
                    "INSERT INTO vulnerabilidades (titulo, cve_codigo, severidad, estado, puntaje_cvss, fingerprint) "
                    "VALUES (?,?,?,?,?,?)",
                    (v.titulo, v.cve_codigo, v.severidad, v.estado, v.puntaje_cvss, v.fingerprint))
                c.commit()
            except sqlite3.IntegrityError:  # lost a race against a concurrent identical insert
                dup = c.execute("SELECT id FROM vulnerabilidades WHERE fingerprint=?", (v.fingerprint,)).fetchone()
                raise DuplicateVulnerabilityError(dup["id"] if dup else 0)
            return Vulnerability(**{**v.__dict__, "id": cur.lastrowid})

    def get(self, vuln_id: int) -> Optional[Vulnerability]:
        with closing(self._conn()) as c:
            r = c.execute(f"SELECT {COLS} FROM vulnerabilidades WHERE id=?", (vuln_id,)).fetchone()
        return _row(r) if r else None

    def list(self) -> List[Vulnerability]:
        with closing(self._conn()) as c:
            return [_row(r) for r in c.execute(f"SELECT {COLS} FROM vulnerabilidades ORDER BY id DESC")]

    def update(self, v: Vulnerability) -> Optional[Vulnerability]:
        with closing(self._conn()) as c:
            dup = c.execute("SELECT id FROM vulnerabilidades WHERE fingerprint=? AND id<>?", (v.fingerprint, v.id)).fetchone()
            if dup:
                raise DuplicateVulnerabilityError(dup["id"])
            try:
                cur = c.execute(
                    "UPDATE vulnerabilidades SET titulo=?, cve_codigo=?, severidad=?, estado=?, puntaje_cvss=?, fingerprint=? WHERE id=?",
                    (v.titulo, v.cve_codigo, v.severidad, v.estado, v.puntaje_cvss, v.fingerprint, v.id))
                c.commit()
            except sqlite3.IntegrityError:
                raise DuplicateVulnerabilityError(0)
            return v if cur.rowcount else None

    def delete(self, vuln_id: int) -> bool:
        with closing(self._conn()) as c:
            cur = c.execute("DELETE FROM vulnerabilidades WHERE id=?", (vuln_id,))
            c.commit()
            return cur.rowcount > 0

    # -- StateHistoryRepository -----------------------------------------------
    def record(self, vuln_id: int, state: str) -> None:
        with closing(self._conn()) as c:
            c.execute("INSERT INTO historial_estados (vuln_id, estado) VALUES (?,?)", (vuln_id, state))
            c.commit()

    def sequences(self) -> List[List[str]]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT vuln_id, estado FROM historial_estados ORDER BY vuln_id, fecha, id").fetchall()
        by = defaultdict(list)
        for r in rows:
            by[r["vuln_id"]].append(r["estado"])
        return list(by.values())
