"""Safe WAF-evasion payload tampering utilities.

These transformations are used strictly to test WAF filtering behavior
(observing whether obfuscated payloads bypass detection), never to cause harm.
"""

from __future__ import annotations

import random
import urllib.parse


def random_case(payload: str) -> str:
    """Randomize the casing of every alphabetic character in the payload."""
    return "".join(char.upper() if random.random() > 0.5 else char.lower() for char in payload)


def url_encode(payload: str) -> str:
    """Apply single URL percent-encoding to the payload."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Apply double URL percent-encoding to the payload."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def insert_sql_comments(payload: str) -> str:
    """Insert inline SQL comments between characters to evade naive WAF regex."""
    return "/**/".join(list(payload))


def insert_whitespace_variants(payload: str) -> str:
    """Replace spaces with alternative whitespace-equivalent sequences."""
    variants = ["%09", "%0a", "/**/", "+"]
    return payload.replace(" ", random.choice(variants))


TAMPER_STRATEGIES = {
    "random_case": random_case,
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "sql_comments": insert_sql_comments,
    "whitespace_variants": insert_whitespace_variants,
}


def apply_tamper(payload: str, strategy: str) -> str:
    """Apply a named tampering strategy to the payload, returning it unchanged if unknown."""
    func = TAMPER_STRATEGIES.get(strategy)
    return func(payload) if func else payload
