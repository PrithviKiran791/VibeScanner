"""Ephemeral scan workspaces: shallow GitHub clones and ZIP uploads, always wiped afterwards."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

GITHUB_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)


class IngestError(Exception):
    pass


@dataclass(frozen=True)
class Workspace:
    root: Path
    target: str
    commit_hash: str | None = None


def parse_github_url(url: str) -> tuple[str, str]:
    m = GITHUB_URL.match(url.strip())
    if not m:
        raise IngestError("Only https://github.com/<owner>/<repo> URLs are supported")
    return m["owner"], m["repo"]


@contextmanager
def scratch_dir(prefix: str = "vibeguard-") -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        shutil.rmtree(path, onexc=_force_remove)


@contextmanager
def github_workspace(
    url: str,
    token: str | None = None,
    timeout_s: int = 30,
    max_bytes: int | None = None,
) -> Iterator[Workspace]:
    owner, repo = parse_github_url(url)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"

    with scratch_dir() as tmp:
        dest = tmp / "repo"
        _git(
            [
                "clone",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--no-recurse-submodules",
                "-c",
                "core.symlinks=false",
                clone_url,
                str(dest),
            ],
            timeout_s,
            f"Could not clone {owner}/{repo}",
        )
        if max_bytes is not None and dir_size(dest) > max_bytes:
            raise IngestError(
                f"{owner}/{repo} exceeds the {max_bytes // (1024 * 1024)}MB clone limit"
            )
        head = _git(["-C", str(dest), "rev-parse", "HEAD"], 10, "Could not read HEAD").strip()
        yield Workspace(root=dest, target=f"{owner}/{repo}", commit_hash=head)


def _git(args: list[str], timeout_s: int, error: str) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}  # never prompt
    try:
        proc = subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=timeout_s, env=env, check=True
        )
    except subprocess.TimeoutExpired:
        raise IngestError(f"{error}: timed out after {timeout_s}s") from None
    except (subprocess.CalledProcessError, OSError):
        # `from None`: git's stderr and argv include the clone URL, which may carry a token
        raise IngestError(error) from None
    return proc.stdout


def dir_size(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


@contextmanager
def zip_workspace(archive: Path, max_unpacked_bytes: int) -> Iterator[Workspace]:
    with scratch_dir() as tmp:
        dest = tmp / "repo"
        dest.mkdir()
        safe_extract(archive, dest, max_unpacked_bytes)
        yield Workspace(root=dest, target=archive.name)


@contextmanager
def local_workspace(path: Path) -> Iterator[Workspace]:
    if not path.is_dir():
        raise IngestError(f"{path} is not a directory")
    yield Workspace(root=path, target=str(path))


def safe_extract(archive: Path, dest: Path, max_unpacked_bytes: int) -> None:
    """Extract with zip-slip, symlink and zip-bomb protection."""
    dest = dest.resolve()
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise IngestError("Upload is not a valid ZIP archive") from exc

    with zf:
        total = 0
        for info in zf.infolist():
            name = PurePosixPath(info.filename.replace("\\", "/"))
            if name.is_absolute() or ".." in name.parts:
                raise IngestError(f"Unsafe path in archive: {info.filename}")
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            target = (dest / name).resolve()
            if not target.is_relative_to(dest):
                raise IngestError(f"Unsafe path in archive: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                # Count real decompressed bytes; header sizes can lie.
                while chunk := src.read(64 * 1024):
                    total += len(chunk)
                    if total > max_unpacked_bytes:
                        raise IngestError("Archive exceeds the unpacked size limit")
                    out.write(chunk)


def _force_remove(func, path, _exc) -> None:
    # Git pack files are read-only on Windows; clear the bit and retry.
    Path(path).chmod(stat.S_IWRITE)
    func(path)
