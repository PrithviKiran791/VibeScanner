from vibeguard.engine.diff import replace_lines, unified_diff
from vibeguard.engine.merge import merge_findings
from vibeguard.engine.models import Finding, FindingSource, Severity
from vibeguard.engine.scoring import count_by_severity, hardening_index


def _f(sev: Severity, line: int = 1, cwe: str | None = "CWE-1", src=FindingSource.STATIC, **kw):
    return Finding(
        rule_id="r",
        severity=sev,
        category="c",
        title="t",
        cwe_id=cwe,
        file_path="a.ts",
        line_start=line,
        line_end=line,
        snippet_original="x",
        explanation="e",
        source=src,
        **kw,
    )


def test_hardening_index_penalties_and_floor():
    assert hardening_index([]) == 100
    assert hardening_index([_f(Severity.CRITICAL), _f(Severity.HIGH)]) == 63
    assert hardening_index([_f(Severity.MEDIUM), _f(Severity.LOW), _f(Severity.INFO)]) == 94
    assert hardening_index([_f(Severity.CRITICAL)] * 5) == 0


def test_count_by_severity():
    c = count_by_severity([_f(Severity.CRITICAL), _f(Severity.CRITICAL), _f(Severity.LOW)])
    assert (c.critical, c.high, c.low) == (2, 0, 1)


def test_unified_diff_is_git_style_and_empty_when_unchanged():
    d = unified_diff("src/a.ts", "one\ntwo\n", "one\n2\n")
    assert d.startswith("--- a/src/a.ts\n+++ b/src/a.ts\n")
    assert "-two\n+2\n" in d
    assert unified_diff("a", "same", "same") == ""


def test_replace_lines_preserves_crlf_and_trailing_newline():
    out = replace_lines("a\r\nb\r\nc\r\n", 2, 2, "B1\nB2")
    assert out == "a\r\nB1\r\nB2\r\nc\r\n"


def test_merge_collapses_duplicate_static_hits_keeping_highest_severity():
    out = merge_findings([_f(Severity.HIGH), _f(Severity.CRITICAL)], [])
    assert [f.severity for f in out] == [Severity.CRITICAL]


def test_merge_static_and_llm_overlap_becomes_merged():
    static = _f(Severity.HIGH, unified_diff=None)
    llm = _f(Severity.CRITICAL, src=FindingSource.LLM, unified_diff="patch", snippet_fixed="fix")
    [m] = merge_findings([static], [llm])
    assert m.source == FindingSource.MERGED
    assert m.severity == Severity.CRITICAL
    assert m.unified_diff == "patch"


def test_merge_keeps_distinct_weaknesses_on_same_line():
    out = merge_findings([_f(Severity.HIGH, cwe="CWE-79"), _f(Severity.HIGH, cwe="CWE-89")], [])
    assert len(out) == 2
