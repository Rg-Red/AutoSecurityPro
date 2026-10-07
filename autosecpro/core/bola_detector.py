"""Safe, public heuristic BOLA/IDOR pattern detector.

This module never performs authenticated requests, never uses or requests
bearer tokens/session cookies, and never replays or tampers with requests
to compare authorization outcomes. It only inspects publicly observable
URL structure (path segments and query parameter names) that was already
collected during passive recon (crawling, robots/sitemap, documentation
probing) to flag endpoints that are plausible candidates for a manual or
authorized Broken Object Level Authorization (BOLA/IDOR) review.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

# Path segments that look like an object identifier: numeric IDs, UUIDs, or
# unresolved template/route placeholders (e.g. "{id}", ":userId").
ID_SEGMENT_PATTERN = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[a-z_]*id[a-z_]*\}|:[a-z_]*id[a-z_]*)$",
    re.IGNORECASE,
)

# Query parameter names that plausibly reference a specific object instance,
# limited to public, non-sensitive naming patterns only.
ID_QUERY_PARAM_PATTERN = re.compile(
    r"^(id|uid|user_?id|account_?id|order_?id|invoice_?id|profile_?id|customer_?id|"
    r"doc(?:ument)?_?id|file_?id|record_?id)$",
    re.IGNORECASE,
)


def has_id_path_segment(path: str) -> bool:
    """Return True if any path segment structurally resembles an object identifier."""
    return any(ID_SEGMENT_PATTERN.match(segment) for segment in path.strip("/").split("/") if segment)


def find_id_query_params(url: str) -> list[str]:
    """Return the query parameter names in `url` that resemble object identifiers."""
    query = urlparse(url).query
    if not query:
        return []
    params = parse_qs(query, keep_blank_values=True)
    return [name for name in params if ID_QUERY_PARAM_PATTERN.match(name)]


def is_bola_candidate(path: str, url: str) -> bool:
    """Return True if `path`/`url` structurally resembles a BOLA/IDOR candidate.

    This is a public, unauthenticated heuristic only: it never issues
    requests, never uses credentials, and never attempts to bypass
    authorization. A True result means "worth a manual/authorized review",
    not "confirmed vulnerable".
    """
    return has_id_path_segment(path) or bool(find_id_query_params(url))
