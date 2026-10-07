"""Async HTTP client wrapper providing OPSEC features.

Features: Tor/proxy pool routing, identity rotation, random jitter,
adaptive throttling, and exponential backoff on 429/403 responses.
"""

from __future__ import annotations

import asyncio
import random
from pathlib import Path
from typing import Any, Optional

import aiohttp

from autosecpro.core.identity import build_identity_headers
from autosecpro.core.tor_manager import TOR_SOCKS_HOST, TOR_SOCKS_PORT


def load_proxy_pool(proxy_file: Optional[str]) -> list[str]:
    """Load a list of proxy URLs from a plain text file, one per line."""
    if not proxy_file:
        return []
    path = Path(proxy_file)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


class AsyncHttpClient:
    """Wraps `aiohttp.ClientSession` with jitter, backoff, and OPSEC identity rotation."""

    def __init__(
        self,
        timeout: float = 10.0,
        tor_enabled: bool = False,
        proxy_file: Optional[str] = None,
        cookie: Optional[str] = None,
        jwt: Optional[str] = None,
        min_jitter: float = 0.1,
        max_jitter: float = 0.6,
        max_retries: int = 3,
    ) -> None:
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.tor_enabled = tor_enabled
        self.proxy_pool = load_proxy_pool(proxy_file)
        self.cookie = cookie
        self.jwt = jwt
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self.max_retries = max_retries
        self._session: Optional[aiohttp.ClientSession] = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.timeout_count = 0

    async def __aenter__(self) -> "AsyncHttpClient":
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        self._session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._session:
            await self._session.close()

    def _pick_proxy(self) -> Optional[str]:
        """Select the active proxy URL: Tor SOCKS5, a random pool entry, or None."""
        if self.tor_enabled:
            return f"socks5://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
        if self.proxy_pool:
            return random.choice(self.proxy_pool)
        return None

    def _build_headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        headers = build_identity_headers(extra)
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.jwt:
            headers["Authorization"] = f"Bearer {self.jwt}"
        return headers

    async def _jitter(self) -> None:
        await asyncio.sleep(random.uniform(self.min_jitter, self.max_jitter))

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Optional[aiohttp.ClientResponse]:
        """Perform an HTTP request with jitter and exponential backoff on 429/403."""
        if not self._session:
            raise RuntimeError("AsyncHttpClient must be used as an async context manager.")

        backoff = 1.0
        for attempt in range(self.max_retries + 1):
            await self._jitter()
            request_headers = self._build_headers(headers)
            proxy = self._pick_proxy()
            self.total_requests += 1
            try:
                response = await self._session.request(
                    method,
                    url,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    proxy=proxy,
                    ssl=False,
                    **kwargs,
                )
            except asyncio.TimeoutError:
                self.timeout_count += 1
                self.failed_requests += 1
                if attempt >= self.max_retries:
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            except (aiohttp.ClientError, ConnectionError):
                self.failed_requests += 1
                if attempt >= self.max_retries:
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            if response.status in (429, 403) and attempt < self.max_retries:
                response.release()
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            self.successful_requests += 1
            return response
        return None

    async def get(self, url: str, **kwargs: Any) -> Optional[aiohttp.ClientResponse]:
        """Perform a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Optional[aiohttp.ClientResponse]:
        """Perform a POST request."""
        return await self.request("POST", url, **kwargs)
