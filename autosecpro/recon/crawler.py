"""Asynchronous web spider / crawler.

Extracts internal links, form actions and input parameters, and inline /
external JavaScript file references from a target's HTML pages.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import ScanContext

LINK_ATTRS = ("href", "src", "action")


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).netloc.split(":")[0].lower().endswith(host.lower())
    except ValueError:
        return False


def extract_page_data(html: str, base_url: str, host: str) -> dict[str, Any]:
    """Parse an HTML document and extract links, forms, and JS references."""
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()
    js_files: set[str] = set()
    forms: list[dict[str, Any]] = []

    for tag in soup.find_all(["a", "script", "link"]):
        for attr in LINK_ATTRS:
            value = tag.get(attr)
            if not value:
                continue
            absolute = urljoin(base_url, value)
            if not _same_host(absolute, host):
                continue
            if tag.name == "script" or absolute.endswith(".js"):
                js_files.add(absolute)
            else:
                links.add(absolute.split("#")[0])

    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action", ""))
        method = (form.get("method") or "GET").upper()
        inputs = [
            inp.get("name")
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("name")
        ]
        forms.append({"action": action, "method": method, "parameters": inputs})

    return {"links": links, "js_files": js_files, "forms": forms}


async def crawl(
    client: AsyncHttpClient,
    context: ScanContext,
    max_pages: int = 60,
) -> None:
    """Breadth-first crawl of the target starting from its base URL."""
    host = context.target.host
    start_url = context.target.base_url + "/"
    queue: asyncio.Queue[str] = asyncio.Queue()
    await queue.put(start_url)
    visited: set[str] = set()

    while not queue.empty() and len(visited) < max_pages:
        url = await queue.get()
        if url in visited:
            continue
        visited.add(url)

        response = await client.get(url)
        if response is None or "text/html" not in response.headers.get("Content-Type", ""):
            if response is not None:
                response.release()
            continue

        try:
            html = await response.text(errors="ignore")
        except (UnicodeDecodeError, asyncio.TimeoutError):
            continue

        context.discovered_endpoints.add(url)
        context.endpoints_scanned += 1

        data = extract_page_data(html, url, host)
        context.discovered_js_files.update(data["js_files"])
        context.discovered_forms.extend(data["forms"])

        for link in data["links"]:
            if link not in visited:
                await queue.put(link)


PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z0-9_\-\[\]]+)=")


def extract_query_params(url: str) -> list[str]:
    """Extract query string parameter names from a URL."""
    return PARAM_PATTERN.findall(url)
