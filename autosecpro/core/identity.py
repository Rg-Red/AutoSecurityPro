"""Identity rotation utilities: User-Agent pools and spoofed client IP headers."""

from __future__ import annotations

import random

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


def random_user_agent() -> str:
    """Return a randomly selected, realistic desktop/mobile User-Agent string."""
    return random.choice(USER_AGENTS)


def random_ip() -> str:
    """Generate a plausible random public-looking IPv4 address for spoofing headers."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def build_identity_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a fresh set of randomized identity/spoofing HTTP headers."""
    spoofed_ip = random_ip()
    headers = {
        "User-Agent": random_user_agent(),
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
        "Client-IP": spoofed_ip,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra:
        headers.update(extra)
    return headers
