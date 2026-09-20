"""Tests for app.analyzer.signatures."""

from __future__ import annotations

from app.analyzer.signatures import find_error_signatures


def test_detects_traceback():
    assert "Traceback" in find_error_signatures("Traceback (most recent call last): ...")


def test_detects_sql_error_case_insensitive():
    assert "SQL syntax" in find_error_signatures("you have an error in your sql syntax near line 1")


def test_detects_database_error():
    assert "database error" in find_error_signatures("A DATABASE ERROR occurred while processing")


def test_no_match_on_normal_response():
    assert find_error_signatures('{"id": 1, "name": "Alice"}') == []


def test_empty_and_none_text_returns_empty_list():
    assert find_error_signatures("") == []
    assert find_error_signatures(None) == []


def test_multiple_signatures_in_one_response():
    text = "Traceback: ... database error: connection refused"
    matches = find_error_signatures(text)
    assert "Traceback" in matches
    assert "database error" in matches


def test_innocuous_message_containing_the_phrase_still_matches_conservatively():
    """Documented tradeoff: this is a substring match, so a perfectly
    innocuous message that happens to contain the phrase would also
    match. That's the false-positive risk explicitly called out in the
    phase spec — this is a signal, not a verdict, and the evidence
    field always shows exactly what matched so a human/later rule can
    judge it."""
    text = '{"message": "no database error handling issues found in this run"}'
    assert "database error" in find_error_signatures(text)
