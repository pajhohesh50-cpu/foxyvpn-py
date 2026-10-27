"""Local proxy server on a single port.

* SOCKS5 (CONNECT only, no auth)
* HTTP proxy: ``CONNECT host:port`` (https) and plain ``GET http://...`` requests,
  which is what the Windows "system proxy" setting speaks.

The protocol is detected from the first byte (0x05 = SOCKS5, anything else = HTTP).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Awaitable, Callable
from urllib.parse import urlsplit

log = logging.getLogger("foxyvpn.socks")

# opener(host, port) -> object with read_chunk()/write()/close_write()/reset()
TunnelOpener = Callable[[str, int], Awaitable["object"]]

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_HOST_UNREACHABLE = 0x04
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

HTTP_OK_CONNECT = b"HTTP/1.1 200 Connection Established\r\n\r\n"
HTTP_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
HTTP_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def reply(code: int) -> bytes:
    return bytes([0x05, code, 0x00, 0x01]) + b"\x00\x00\x00\x00" + b"\x00\x00"


async def read_request(reader: asyncio.StreamReader) -> tuple[int, str, int]:
    """Parse the SOCKS5 request after method negotiation. Returns (cmd, host, port)."""
    ver, cmd, _rsv, atyp = await reader.readexactly(4)
    if ver != 5:
        raise ValueError("bad SOCKS version")
    if atyp == 0x01:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif atyp == 0x03:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode("utf-8", "replace")
    elif atyp == 0x04:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    else:
        raise LookupError(atyp)
    port = int.from_bytes(await reader.readexactly(2), "big")
    return cmd, host, port


# --------------------------------------------------------------------------
# Byte relay
# --------------------------------------------------------------------------

async def _pump_up(reader: asyncio.StreamReader, stream) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await stream.write(data)
    finally:
        await stream.close_write()


async def _pump_down(stream, writer: asyncio.StreamWriter) -> None:
    while True:
        data = await stream.read_chunk()
        if not data:
            break
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream) -> None:
    up = asyncio.create_task(_pump_up(reader, stream))
    down = asyncio.create_task(_pump_down(stream, writer))
    try:
        await asyncio.gather(up, down)
    except Exception as e:  # noqa: BLE001 - any failure tears the tunnel down
        log.debug("relay ended: %s", e)
    finally:
        for t in (up, down):
            t.cancel()
        await asyncio.gather(up, down, return_exceptions=True)
        await stream.reset()


# --------------------------------------------------------------------------
# HTTP proxy helpers
# --------------------------------------------------------------------------

def split_host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):  # [v6]:port
        host, _, rest = authority[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif authority.count(":") == 1:
        host, _, port = authority.partition(":")
    else:
        host, port = authority, ""
    if not host:
        raise ValueError("empty host")
    number = int(port) if port else default_port
    if not 0 < number < 65536:
        raise ValueError("bad port")
    return host, number


def parse_http_head(head: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(None, 2)
    if len(parts) != 3:
        raise ValueError("bad request line")
    method, target, version = parts
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            raise ValueError("bad header line")
        headers.append((name.strip(), value.strip()))
    return method.upper(), target, version, headers


_HOP_BY_HOP = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}


def rewrite_plain_request(method: str, target: str, version: str,
                          headers: list[tuple[str, str]]) -> tuple[str, int, bytes]:
    """Turn `GET http://host/p HTTP/1.1` into an origin-form request for that host."""
    u = urlsplit(target)
    if u.scheme.lower() != "http" or not u.hostname:
        raise ValueError("only absolute http:// URLs can be proxied")
    port = u.port or 80
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    lines = [f"{method} {path} {version}"]
    lines += [f"{k}: {v}" for k, v in headers if k.lower() not in _HOP_BY_HOP]
    lines.append("Connection: close")  # one request per tunnel keeps routing simple
    return u.hostname, port, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


async def _handle_http(reader, writer, first: bytes, open_tunnel: TunnelOpener,
                       timeout: float, verbose: bool) -> None:
    head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    try:
        method, target, version, headers = parse_http_head(head)
        if method == "CONNECT":
            host, port = split_host_port(target, 443)
            initial = b""
        else:
            host, port, initial = rewrite_plain_request(method, target, version, headers)
    except ValueError as e:
        log.debug("bad HTTP proxy request: %s", e)
        writer.write(HTTP_BAD_REQUEST)
        await writer.drain()
        return

    name = f"{host}:{port}" if verbose else "<redacted>"
    try:
        stream = await open_tunnel(host, port)
    except Exception as e:  # noqa: BLE001
        log.warning("tunnel to %s failed: %s", name, e)
        writer.write(HTTP_BAD_GATEWAY)
        await writer.drain()
        return

    if method == "CONNECT":
        writer.write(HTTP_OK_CONNECT)
        await writer.drain()
    else:
        try:
            await stream.write(initial)
        except Exception as e:  # noqa: BLE001
            log.warning("sending request to %s failed: %s", name, e)
            await stream.reset()
            writer.write(HTTP_BAD_GATEWAY)
            await writer.drain()
            return
    await relay(reader, writer, stream)


# --------------------------------------------------------------------------
# SOCKS5
# --------------------------------------------------------------------------

async def _handle_socks5(reader, writer, open_tunnel: TunnelOpener,
                         timeout: float, verbose: bool) -> None:
    async def handshake():
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None
        writer.write(b"\x05\x00")
        await writer.drain()
        return await read_request(reader)

    try:
        req = await asyncio.wait_for(handshake(), timeout)
    except LookupError:
        writer.write(reply(REP_ATYP_NOT_SUPPORTED))
        await writer.drain()
        return
    if req is None:
        return
    cmd, host, port = req
    if cmd != 0x01:
        writer.write(reply(REP_CMD_NOT_SUPPORTED))
        await writer.drain()
        return

    try:
        stream = await open_tunnel(host, port)
    except Exception as e:  # noqa: BLE001
        log.warning("tunnel to %s failed: %s", f"{host}:{port}" if verbose else "<redacted>", e)
        writer.write(reply(REP_HOST_UNREACHABLE))
        await writer.drain()
        return

    writer.write(reply(REP_SUCCEEDED))
    await writer.drain()
    await relay(reader, writer, stream)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        open_tunnel: TunnelOpener, handshake_timeout: float = 10.0,
                        verbose: bool = False) -> None:
    try:
        first = await asyncio.wait_for(reader.readexactly(1), handshake_timeout)
        if first == b"\x05":
            await _handle_socks5(reader, writer, open_tunnel, handshake_timeout, verbose)
        else:
            await _handle_http(reader, writer, first, open_tunnel, handshake_timeout, verbose)
    except asyncio.LimitOverrunError:
        try:
            writer.write(HTTP_BAD_REQUEST)
        except Exception:  # noqa: BLE001
            pass
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def serve(host: str, port: int, open_tunnel: TunnelOpener, *,
                max_conns: int = 256, verbose: bool = False) -> asyncio.AbstractServer:
    sem = asyncio.Semaphore(max_conns)

    async def on_connect(r, w):
        async with sem:
            await handle_client(r, w, open_tunnel, verbose=verbose)

    return await asyncio.start_server(on_connect, host, port)
