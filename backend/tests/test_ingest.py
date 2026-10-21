import zipfile

import pytest

from vibeguard.engine.ingest.file_index import RepoTooLargeError, index_files
from vibeguard.engine.ingest.workspace import (
    IngestError,
    parse_github_url,
    safe_extract,
    zip_workspace,
)


def _write(root, rel, data):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())


def test_index_skips_ignored_dirs_lockfiles_binaries(tmp_path):
    _write(tmp_path, "app/page.tsx", "export default 1")
    _write(tmp_path, "node_modules/x/index.js", "bad")
    _write(tmp_path, ".next/server.js", "bad")
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, "public/logo.png", b"\x89PNG")
    _write(tmp_path, "data.bin", b"abc\x00def")
    _write(tmp_path, "dist/app.min.js", "bad")
    files = index_files(tmp_path, 10_000, 1_000)
    assert [(f.path, f.language) for f in files] == [("app/page.tsx", "tsx")]


def test_index_enforces_size_budget(tmp_path):
    _write(tmp_path, "a.ts", "x" * 600)
    _write(tmp_path, "b.ts", "x" * 600)
    with pytest.raises(RepoTooLargeError):
        index_files(tmp_path, max_repo_bytes=1_000, max_file_bytes=1_000)
    # oversized single files are skipped, not fatal
    assert index_files(tmp_path, max_repo_bytes=10_000, max_file_bytes=500) == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/acme/vibe-app", ("acme", "vibe-app")),
        ("https://github.com/acme/vibe.app.git", ("acme", "vibe.app")),
    ],
)
def test_github_url_ok(url, expected):
    assert parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/a/b/../../x",
        "file:///etc",
        "https://github.com/a",
    ],
)
def test_github_url_rejected(url):
    with pytest.raises(IngestError):
        parse_github_url(url)


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_zip_slip_rejected(tmp_path):
    archive = _zip(tmp_path / "evil.zip", {"../../escape.txt": "x"})
    with pytest.raises(IngestError, match="Unsafe path"):
        safe_extract(archive, tmp_path / "out", 10_000)


def test_zip_bomb_rejected(tmp_path):
    archive = _zip(tmp_path / "bomb.zip", {"a.txt": "0" * 50_000})
    (tmp_path / "out").mkdir()
    with pytest.raises(IngestError, match="size limit"):
        safe_extract(archive, tmp_path / "out", 10_000)


def test_zip_workspace_extracts_and_cleans_up(tmp_path):
    archive = _zip(tmp_path / "ok.zip", {"src/a.ts": "const a = 1;"})
    with zip_workspace(archive, 10_000) as ws:
        root = ws.root
        assert (root / "src/a.ts").read_text() == "const a = 1;"
    assert not root.exists()
