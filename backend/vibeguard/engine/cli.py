"""`vibeguard scan <path | github-url | archive.zip>` — the Phase 1 standalone engine."""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import AbstractContextManager
from pathlib import Path

from vibeguard.config import Settings
from vibeguard.engine.ingest.file_index import RepoTooLargeError
from vibeguard.engine.ingest.workspace import (
    IngestError,
    Workspace,
    github_workspace,
    local_workspace,
    zip_workspace,
)
from vibeguard.engine.models import ScanResult, Severity
from vibeguard.engine.pipeline import run_scan
from vibeguard.engine.report import to_json, to_markdown

RED, GREEN, GREY, BOLD, RESET = "\033[31m", "\033[32m", "\033[90m", "\033[1m", "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vibeguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a directory, GitHub repo URL, or .zip archive")
    scan.add_argument("target")
    scan.add_argument("--no-llm", action="store_true", help="Deterministic passes only")
    scan.add_argument("--no-registry", action="store_true", help="Skip npm/PyPI existence checks")
    scan.add_argument("--json", type=Path, metavar="FILE", help="Write the JSON report here")
    scan.add_argument(
        "--markdown", type=Path, metavar="FILE", help="Write the Markdown report here"
    )
    scan.add_argument(
        "--fail-under", type=int, metavar="SCORE", help="Exit 1 if score is below this"
    )
    scan.add_argument("--no-diff", action="store_true", help="Don't print patches to the terminal")
    args = parser.parse_args(argv)

    overrides: dict = {}
    if args.no_llm:
        overrides["llm_provider"] = "none"
    if args.no_registry:
        overrides["registry_check"] = False
    settings = Settings(**overrides)

    try:
        with _open_workspace(args.target, settings) as ws:
            result = run_scan(ws, settings, progress=_progress)
    except (IngestError, RepoTooLargeError) as exc:
        print(f"{RED}error:{RESET} {exc}", file=sys.stderr)
        return 2
    finally:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    if args.json:
        args.json.write_text(to_json(result), encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(to_markdown(result), encoding="utf-8")
    _print_report(result, show_diff=not args.no_diff)

    if args.fail_under is not None and result.hardening_score < args.fail_under:
        return 1
    return 0


def _open_workspace(target: str, settings: Settings) -> AbstractContextManager[Workspace]:
    if target.startswith("https://"):
        return github_workspace(target, token=os.environ.get("GITHUB_TOKEN"))
    path = Path(target)
    if path.suffix.lower() == ".zip" and path.is_file():
        return zip_workspace(path, settings.max_repo_bytes)
    return local_workspace(path)


def _progress(stage: str, pct: int) -> None:
    print(f"\r{GREY}[{pct:>3}%] {stage.ljust(20)}{RESET}", end="", file=sys.stderr, flush=True)


def _print_report(result: ScanResult, show_diff: bool) -> None:
    score = result.hardening_score
    tone = GREEN if score >= 80 else RED if score < 60 else ""
    c = result.counts
    print(f"\n{BOLD}VIBEGUARD{RESET}  {result.target}")
    print(f"{BOLD}{tone}HARDENING INDEX {score}/100{RESET}")
    print(
        f"CRITICAL {c.critical}  HIGH {c.high}  MEDIUM {c.medium}  LOW {c.low}   "
        f"{GREY}{result.files_scanned} files | {result.duration_ms / 1000:.1f}s | "
        f"LLM {'on' if result.llm_used else 'off'}{RESET}\n"
    )
    for f in result.findings:
        sev_color = RED if f.severity in (Severity.CRITICAL, Severity.HIGH) else GREY
        print(f"{sev_color}{BOLD}[{f.severity}]{RESET} {BOLD}{f.title.upper()}{RESET}")
        print(f"  {GREY}{f.file_path}:{f.line_start}  {f.cwe_id or ''}  ({f.source}){RESET}")
        print(f"  {f.explanation}")
        if show_diff and f.unified_diff:
            for line in f.unified_diff.splitlines():
                color = RED if line.startswith("-") else GREEN if line.startswith("+") else GREY
                print(f"    {color}{line}{RESET}")
        print()
    for w in result.warnings:
        print(f"{GREY}note: {w}{RESET}")


if __name__ == "__main__":
    sys.exit(main())
