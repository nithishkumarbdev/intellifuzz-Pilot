"""Tests for app.cli."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.cli import build_arg_parser, run

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"


# ---------------------------------------------------------------------------
# Argument parsing (pure, no I/O)
# ---------------------------------------------------------------------------


def test_required_args():
    parser = build_arg_parser()
    args = parser.parse_args(["--spec", "x.json", "--target", "http://localhost:8001"])
    assert args.spec == "x.json"
    assert args.target == "http://localhost:8001"


def test_missing_required_arg_raises():
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--spec", "x.json"])  # missing --target


def test_defaults():
    parser = build_arg_parser()
    args = parser.parse_args(["--spec", "x.json", "--target", "http://x"])
    assert args.timeout == 5.0
    assert args.max_mutations == 200
    assert args.formats == "json,markdown,html"
    assert args.report_dir == "reports"
    assert args.no_llm is False


def test_no_llm_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["--spec", "x.json", "--target", "http://x", "--no-llm"])
    assert args.no_llm is True


def test_skip_methods_and_formats_parsed_as_plain_strings():
    """The CLI itself just holds the raw strings — splitting happens in
    run(), keeping argparse simple."""
    parser = build_arg_parser()
    args = parser.parse_args(
        ["--spec", "x.json", "--target", "http://x", "--skip-methods", "DELETE,PUT", "--formats", "json"]
    )
    assert args.skip_methods == "DELETE,PUT"
    assert args.formats == "json"


# ---------------------------------------------------------------------------
# Live end-to-end run
# ---------------------------------------------------------------------------


async def test_run_end_to_end_against_live_vulnerable_api(isolated_live_vulnerable_api_url, tmp_path):
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--spec",
            str(VULN_API_SPEC),
            "--target",
            isolated_live_vulnerable_api_url,
            "--auth-header",
            "x-api-token",
            "--auth-value",
            "alice-token",
            "--timeout",
            "1.0",
            "--max-mutations",
            "60",
            "--skip-methods",
            "DELETE",
            "--report-dir",
            str(tmp_path),
            "--formats",
            "json,markdown",
            "--no-llm",
        ]
    )

    exit_code = await run(args)
    assert exit_code == 0

    assert (tmp_path / "security-report.json").exists()
    assert (tmp_path / "security-report.md").exists()
    assert not (tmp_path / "security-report.html").exists()  # only requested formats written

    import json

    report = json.loads((tmp_path / "security-report.json").read_text())
    assert report["metadata"]["target_base_url"] == isolated_live_vulnerable_api_url
    assert "Vulnerable Shop API" in report["metadata"]["spec_title"]
