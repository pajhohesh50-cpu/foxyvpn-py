"""Local SOCKS5 (CONNECT only, no auth) server that forwards through a tunnel opener."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Awaitable, Callable

log = logging.getLogger("foxyvpn.socks")

# opener(host, port) -> object with read_chunk()/write()/close_write()/reset()
TunnelOpener = Callable[[str, int], Awaitable["object"]]

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_HOST_UNREACHABLE = 0x04
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


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


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        open_tunnel: TunnelOpener, handshake_timeout: float = 10.0,
                        verbose: bool = False) -> None:
    try:
        async def handshake():
            ver, nmethods = await reader.readexactly(2)
            methods = await reader.readexactly(nmethods)
            if ver != 5 or 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return None
            writer.write(b"\x05\x00")
            await writer.drain()
            return await read_request(reader)

        try:
            req = await asyncio.wait_for(handshake(), handshake_timeout)
        except LookupError:
            writer.write(reply(REP_ATYP_NOT_SUPPORTED))
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
