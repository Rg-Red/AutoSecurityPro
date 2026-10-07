"""Tor circuit management: preflight checks and NEWNYM identity rotation."""

from __future__ import annotations

import asyncio
import socket

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051


def is_tor_socks_reachable(host: str = TOR_SOCKS_HOST, port: int = TOR_SOCKS_PORT, timeout: float = 2.0) -> bool:
    """Check whether the local Tor SOCKS5 proxy port is open and accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def renew_tor_identity(control_port: int = TOR_CONTROL_PORT, password: str | None = None) -> bool:
    """Send a NEWNYM signal to the Tor ControlPort to rotate the exit circuit."""
    try:
        reader, writer = await asyncio.open_connection(TOR_SOCKS_HOST, control_port)
    except OSError:
        return False

    try:
        auth_cmd = f'AUTHENTICATE "{password}"\r\n' if password else "AUTHENTICATE\r\n"
        writer.write(auth_cmd.encode())
        await writer.drain()
        auth_response = await reader.readline()
        if not auth_response.startswith(b"250"):
            return False

        writer.write(b"SIGNAL NEWNYM\r\n")
        await writer.drain()
        signal_response = await reader.readline()
        return signal_response.startswith(b"250")
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def tor_preflight_message() -> str:
    """Return a diagnostic reminder message when the local Tor service is not active."""
    return (
        "Tor SOCKS5 proxy is not reachable at 127.0.0.1:9050. "
        "Please start the Tor service before using --tor "
        "(e.g. 'systemctl start tor' on Linux, or launch Tor Browser / tor.exe on Windows)."
    )
