"""Walk a checkout and keep only scannable source files (app_flow Phase 1, step 4)."""

from __future__ import annotations

import os
from pathlib import Path

from vibeguard.engine.models import SourceFile

IGNORED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".vercel",
        ".turbo",
        "dist",
        "build",
        "out",
        "coverage",
        ".cache",
        ".parcel-cache",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        "vendor",
    }
)

IGNORED_FILENAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "poetry.lock", "uv.lock"}
)

BINARY_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".svg",
        ".avif",
        ".bmp",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".mp4",
        ".webm",
        ".mov",
        ".wav",
        ".zip",
        ".gz",
        ".tar",
        ".tgz",
        ".7z",
        ".rar",
        ".pdf",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".wasm",
        ".pyc",
        ".class",
        ".jar",
        ".map",
        ".lock",
    }
)

LANGUAGE_BY_EXT = {
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
}


class RepoTooLargeError(Exception):
    pass


def index_files(root: Path, max_repo_bytes: int, max_file_bytes: int) -> list[SourceFile]:
    """Return text files under `root`, enforcing the total size budget on what we keep."""
    root = root.resolve()
    files: list[SourceFile] = []
    total = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in sorted(filenames):
            abs_path = Path(dirpath) / name
            if abs_path.is_symlink() or not _wanted(name):
                continue
            size = abs_path.stat().st_size
            if size == 0 or size > max_file_bytes:
                continue
            total += size
            if total > max_repo_bytes:
                raise RepoTooLargeError(
                    f"Repository exceeds {max_repo_bytes // (1024 * 1024)}MB of scannable source"
                )
            raw = abs_path.read_bytes()
            if b"\x00" in raw[:8192]:
                continue
            text = raw.decode("utf-8", errors="replace")
            rel = abs_path.relative_to(root).as_posix()
            files.append(
                SourceFile(
                    path=rel,
                    abs_path=abs_path,
                    text=text,
                    language=LANGUAGE_BY_EXT.get(abs_path.suffix.lower()),
                )
            )
    return files


def _wanted(name: str) -> bool:
    if name in IGNORED_FILENAMES:
        return False
    lower = name.lower()
    if lower.endswith((".min.js", ".min.css", ".bundle.js")):
        return False
    return Path(lower).suffix not in BINARY_EXTENSIONS
