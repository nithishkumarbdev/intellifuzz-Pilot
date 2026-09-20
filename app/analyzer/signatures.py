"""
A small, deliberately conservative list of substrings that often show
up in raw server-error output (unhandled exceptions, stack traces,
database errors). Matching one is a SIGNAL worth recording as
evidence — never, on its own, a claim that something is a
vulnerability. These strings can and do appear in entirely legitimate
responses (a field literally named "database_error_count", for
instance), which is exactly why this stays a small, named, inspectable
list rather than a large regex database — every match is easy to
explain and easy to argue with.
"""

from __future__ import annotations

from typing import Optional

# Matched case-insensitively; kept here in their most natural casing so
# the list itself reads clearly.
ERROR_SIGNATURES = [
    "Traceback",
    "NullPointerException",
    "SQLException",
    "SQL syntax",
    "stack trace",
    "internal server error",
    "database error",
    "unhandled exception",
]


def find_error_signatures(text: Optional[str]) -> list[str]:
    """Returns the canonical signature strings (from ERROR_SIGNATURES)
    that appear in `text`, case-insensitively. Empty list if `text` is
    falsy or nothing matches."""
    if not text:
        return []
    lowered = text.lower()
    return [signature for signature in ERROR_SIGNATURES if signature.lower() in lowered]
