"""Smart target normalization engine.

Strips protocol/www prefixes, detects IPv4/IPv6 vs domain input, extracts
custom ports, and probes for the working HTTP scheme (https prioritized).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlsplit

import aiohttp

from autosecpro.core.models import Target


def _strip_input(raw: str) -> str:
    """Remove scheme prefixes, `www.`, and trailing slashes/whitespace."""
    value = raw.strip()
    if "://" not in value:
        value = f"//{value}"
    parsed = urlsplit(value, scheme="https")
    host_port = parsed.netloc or parsed.path
    host_port = host_port.strip("/")
    if host_port.lower().startswith("www."):
        host_port = host_port[4:]
    return host_port


def _split_host_port(host_port: str) -> tuple[str, Optional[int]]:
    """Split a host[:port] string, correctly handling bracketed IPv6 literals."""
    if host_port.startswith("["):
        end = host_port.find("]")
        host = host_port[1:end]
        remainder = host_port[end + 1 :]
        if remainder.startswith(":"):
            return host, int(remainder[1:])
        return host, None
    if host_port.count(":") == 1:
        host, _, port_str = host_port.partition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return host_port, None


def _detect_ip(host: str) -> bool:
    """Return True if `host` is a valid IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _probe_scheme(host: str, port: Optional[int], timeout: float) -> str:
    """Probe HTTPS first, then fall back to HTTP, returning the working scheme."""
    connector = aiohttp.TCPConnector(ssl=False, limit=5)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
        for scheme in ("https", "http"):
            netloc = host if not port else f"{host}:{port}"
            url = f"{scheme}://{netloc}/"
            try:
                async with session.get(url, allow_redirects=True, ssl=False) as response:
                    if response.status < 500:
                        return scheme
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError):
                continue
    return "https"


def _resolve_ip(host: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 address, if possible."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


async def normalize_target(raw_input: str, timeout: float = 6.0, probe: bool = True) -> Target:
    """Normalize raw user input into a fully resolved :class:`Target`."""
    host_port = _strip_input(raw_input)
    host, port = _split_host_port(host_port)
    is_ip = _detect_ip(host)

    scheme = "https"
    if probe:
        scheme = await _probe_scheme(host, port, timeout)

    resolved_ip = host if is_ip else _resolve_ip(host)

    return Target(
        raw_input=raw_input,
        host=host,
        is_ip=is_ip,
        scheme=scheme,
        port=port,
        resolved_ip=resolved_ip,
    )
