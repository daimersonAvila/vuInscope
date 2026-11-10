"""Safe, in-memory reader for .zip / .tar / .tar.gz / .tar.bz2 / .tar.xz project archives.

Nothing is ever written to disk, executed or imported. Defences: format detection by magic bytes,
zip-slip / absolute path rejection, symlink skipping, bounded decompression (zip & tar bombs),
per-file / total / entry-count caps and ignored dependency folders.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import posixpath
import tarfile
import zipfile
from typing import Iterator, Optional, Tuple

from ...domain.errors import ArchiveError
from ...domain.scanner import ArchiveContents, SourceFile

IGNORED_DIRS = {".git", ".svn", ".hg", ".venv", "venv", "env", "node_modules", "__pycache__", ".idea", ".vscode",
                "site-packages", "dist", "build", ".pytest_cache", ".mypy_cache", "vendor", ".tox", ".next"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".php", ".java", ".kt", ".scala", ".go",
             ".rb", ".rs", ".cs", ".c", ".cpp", ".h", ".html", ".htm", ".jinja", ".jinja2", ".j2", ".tf", ".json",
             ".yml", ".yaml", ".sh", ".bash", ".toml", ".cfg", ".ini", ".conf", ".properties", ".xml", ".sql",
             ".md", ".txt", ".rst", ".env", ".pem", ".key", ".gradle", ".dockerfile"}
TEXT_NAMES = {"dockerfile", "makefile", "requirements.txt", "procfile"}


class ArchiveLimits:
    def __init__(self, max_entries=8000, max_file_bytes=1_000_000, max_total_bytes=80_000_000, max_ratio=200):
        self.max_entries, self.max_file_bytes = max_entries, max_file_bytes
        self.max_total_bytes, self.max_ratio = max_total_bytes, max_ratio


def _is_text_candidate(name: str) -> bool:
    base = posixpath.basename(name).lower()
    if base in TEXT_NAMES or base.startswith("dockerfile") or base.startswith(".env"):
        return True
    return posixpath.splitext(base)[1] in TEXT_EXTS


def _clean_path(name: str) -> Optional[str]:
    """Return a safe relative POSIX path or None when the entry is unsafe (zip-slip, absolute, drive letters)."""
    p = name.replace("\\", "/")
    if p.startswith("/") or (len(p) > 1 and p[1] == ":") or "\x00" in p:
        return None
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _decode(raw: bytes) -> Optional[str]:
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _bounded_read(fileobj, limit: int) -> bytes:
    out, total = [], 0
    while True:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ArchiveError("Archive expands to more than the allowed size (possible decompression bomb).")
        out.append(chunk)
    return b"".join(out)


class SafeArchiveReader:
    def __init__(self, limits: Optional[ArchiveLimits] = None):
        self.limits = limits or ArchiveLimits()

    def read(self, data: bytes) -> ArchiveContents:
        if not data:
            raise ArchiveError("The uploaded file is empty.")
        head = data[:8]
        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            return self._read_zip(data)
        if head.startswith(b"\x1f\x8b"):
            return self._read_tar(_bounded_read(gzip.GzipFile(fileobj=io.BytesIO(data)), self.limits.max_total_bytes))
        if head.startswith(b"BZh"):
            return self._read_tar(_bounded_read(bz2.BZ2File(io.BytesIO(data)), self.limits.max_total_bytes))
        if head.startswith(b"\xfd7zXZ"):
            return self._read_tar(_bounded_read(lzma.LZMAFile(io.BytesIO(data)), self.limits.max_total_bytes))
        if len(data) > 262 and data[257:262] == b"ustar":
            return self._read_tar(data)
        raise ArchiveError("Unsupported archive format. Upload a .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz file.")

    # ------------------------------------------------------------------
    def _walk(self, entries: Iterator[Tuple[str, int, bool, callable]]) -> ArchiveContents:
        lim = self.limits
        res = ArchiveContents(files=[])
        total = 0
        for i, (name, size, is_link, opener) in enumerate(entries):
            if i >= lim.max_entries:
                res.truncated = True
                break
            path = _clean_path(name)
            if path is None or is_link:
                res.skipped_unsafe += 1
                continue
            parts = path.split("/")
            ign = [p for p in parts[:-1] if p in IGNORED_DIRS]
            if ign:
                res.ignored_dirs.append(ign[0])
                continue
            content = None
            if _is_text_candidate(path):
                if size > lim.max_file_bytes:
                    res.skipped_large += 1
                else:
                    raw = opener(lim.max_file_bytes)
                    if raw is None:  # encrypted, corrupt or suspicious compression ratio
                        res.skipped_unsafe += 1
                    else:
                        total += len(raw)
                        if total > lim.max_total_bytes:
                            raise ArchiveError("Archive contents exceed the allowed size.")
                        content = _decode(raw)
            res.files.append(SourceFile(path=path, size=size, content=content))
        if not res.files and not res.ignored_dirs:
            raise ArchiveError("The archive contains no readable files.")
        return res

    def _read_zip(self, data: bytes) -> ArchiveContents:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ArchiveError("The file is not a valid zip archive.")
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if sum(i.file_size for i in infos) > self.limits.max_total_bytes * 5:
            raise ArchiveError("Archive declares an unreasonable uncompressed size.")

        def gen():
            for info in infos:
                ratio_bad = info.compress_size > 0 and info.file_size / info.compress_size > self.limits.max_ratio \
                    and info.file_size > 1_000_000
                mode = (info.external_attr >> 16) & 0o170000
                is_link = mode == 0o120000

                def opener(limit, info=info, bad=ratio_bad):
                    if bad or info.flag_bits & 0x1:  # suspicious ratio or encrypted
                        return None
                    try:
                        with zf.open(info) as fh:
                            return fh.read(limit + 1)[:limit]  # never trust the declared size
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                        return None
                yield info.filename, info.file_size, is_link, opener
        return self._walk(gen())

    def _read_tar(self, raw: bytes) -> ArchiveContents:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        except tarfile.TarError:
            raise ArchiveError("The file is not a valid tar archive.")

        def gen():
            for m in tf:
                if not m.isfile() and not m.issym() and not m.islnk():
                    continue

                def opener(limit, m=m):
                    fh = tf.extractfile(m)
                    return fh.read(limit + 1)[:limit] if fh else None
                yield m.name, m.size, (m.issym() or m.islnk()), opener
        try:
            return self._walk(gen())
        except tarfile.TarError:
            raise ArchiveError("The tar archive is corrupted.")
