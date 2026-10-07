"""Google Dorking & passive search reconnaissance engine.

Generates dork queries and attempts to resolve results via DuckDuckGo's
HTML endpoint (non-JS), falling back to printable clickable dork links
when anti-bot measures block automated parsing.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from bs4 import BeautifulSoup

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import ScanContext

DORK_TEMPLATES = [
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} intitle:"index of"',
    'site:{domain} ext:sql',
    'site:{domain} ext:log',
    'site:{domain} ext:bak',
    'site:{domain} filetype:env',
    'site:{domain} inurl:wp-content',
    'site:{domain} inurl:config',
    'site:{domain} intext:"sql syntax near"',
]

DUCKDUCKGO_HTML_URL = "https://html.duckduckgo.com/html/?q={query}"
GOOGLE_URL = "https://www.google.com/search?q={query}"


def generate_dork_queries(domain: str) -> list[str]:
    """Generate a list of standard Google/search-engine dork query strings."""
    return [template.format(domain=domain) for template in DORK_TEMPLATES]


async def run_dorking(client: AsyncHttpClient, context: ScanContext) -> None:
    """Generate dork queries, attempt DuckDuckGo HTML resolution, and record results."""
    if context.target.is_ip:
        return
    domain = context.target.host
    queries = generate_dork_queries(domain)

    for query in queries:
        entry = {
            "query": query,
            "google_url": GOOGLE_URL.format(query=quote_plus(query)),
            "results": [],
        }
        ddg_url = DUCKDUCKGO_HTML_URL.format(query=quote_plus(query))
        response = await client.get(ddg_url)
        if response is not None and response.status == 200:
            try:
                html = await response.text(errors="ignore")
                soup = BeautifulSoup(html, "html.parser")
                for link in soup.select("a.result__a")[:5]:
                    href = link.get("href")
                    if href:
                        entry["results"].append(href)
            except Exception:
                pass
        context.google_dorks_found.append(entry)
