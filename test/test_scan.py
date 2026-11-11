"""
Tests for the report card itself (scan.py).

Each check has its own tests, but this one makes sure every check
also runs correctly INSIDE the full scan, with no ERROR results.
"""

from scan import run_all_checks


def test_every_check_runs_without_error(aws):
    _, summary = run_all_checks(aws)
    errors = [(name, result) for name, result in summary if result.startswith("ERROR")]
    assert errors == [], f"These checks crashed inside the scan: {errors}"