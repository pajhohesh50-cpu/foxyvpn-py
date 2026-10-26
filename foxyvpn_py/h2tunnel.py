"""HTTP/2 CONNECT tunnelling to the upstream proxy (asyncio + the `h2` library)."""

from __future__ import annotations

import asyncio
import ssl
from typing import Awaitable, Callable, Optional

from . import USER_AGENT

try:  # imported lazily so the rest of the package works without `h2`
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions
    import h2.settings
except ImportError:  # pragma: no cover
    h2 = None  # type: ignore[assignment]


class TunnelError(Exception):
    pass


def format_authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"


class H2Stream:
    """One CONNECT tunnel: a bidirectional byte stream over an HTTP/2 stream."""

    def __init__(self, session: "H2Session", stream_id: int):
        loop = asyncio.get_running_loop()
        self.session = session
        self.id = stream_id
        self.headers_future: asyncio.Future = loop.create_future()
        self._queue: asyncio.Queue = asyncio.Queue()
        self.local_closed = False
        self.remote_closed = False

    async def read_chunk(self) -> bytes:
        """Next chunk of data from the remote end; b'' on clean EOF."""
        item = await self._queue.get()
        if item is None:
            self._queue.put_nowait(None)  # EOF is sticky
            return b""
        if isinstance(item, Exception):
            self._queue.put_nowait(item)
            raise item
        await self.session._ack(self.id, len(item))
        return item

    async def write(self, data: bytes) -> None:
        await self.session._send_data(self, data)

    async def close_write(self) -> None:
        """Half-close: tell the upstream we are done sending."""
        await self.session._end_stream(self)

    async def reset(self) -> None:
        await self.session._reset_stream(self)


class H2Session:
    def __init__(self, host: str, port: int, *, connect_timeout: float = 15.0):
        if h2 is None:
            raise RuntimeError("the 'h2' package is required: pip install h2")
        self.host, self.port = host, port
        self.connect_timeout = connect_timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._conn = None
        self._streams: dict[int, H2Stream] = {}
        self._window_changed = asyncio.Event()
        self._reader_task: Optional[asyncio.Task] = None
        self.closed = False

    # -- lifecycle -----------------------------------------------------

    async def connect(self) -> None:
        #ctx = ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host),
            self.connect_timeout)
        sslobj = self._writer.get_extra_info("ssl_object")
        if sslobj is None or sslobj.selected_alpn_protocol() != "h2":
            self._writer.close()
            raise TunnelError("upstream did not negotiate HTTP/2 via ALPN")

        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self._conn = h2.connection.H2Connection(config=config)
        self._conn.initiate_connection()
        self._conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1 << 20})
        self._conn.increment_flow_control_window((1 << 24) - 65535)
        await self._flush()
        self._reader_task = asyncio.create_task(self._read_loop())

    async def aclose(self) -> None:
        self._fail_all(TunnelError("session closed"))
        if self._reader_task:
            self._reader_task.cancel()
        if self._writer:
            self._writer.close()

    # -- tunnels -------------------------------------------------------

    async def open_tunnel(self, host: str, port: int, proxy_authorization: str,
                          timeout: float = 20.0) -> H2Stream:
        if self.closed:
            raise TunnelError("session closed")
        # Respect the server's MAX_CONCURRENT_STREAMS.
        deadline = asyncio.get_running_loop().time() + timeout
        while len(self._streams) >= self._conn.remote_settings.max_concurrent_streams:
            if asyncio.get_running_loop().time() > deadline:
                raise TunnelError("too many concurrent streams")
            await asyncio.sleep(0.05)

        try:
            sid = self._conn.get_next_available_stream_id()
            self._conn.send_headers(sid, [
                (":method", "CONNECT"),
                (":authority", format_authority(host, port)),
                ("proxy-authorization", proxy_authorization),
                ("user-agent", USER_AGENT),
            ])
        except h2.exceptions.H2Error as e:
            raise TunnelError(f"cannot open stream: {e}") from e

        stream = H2Stream(self, sid)
        self._streams[sid] = stream
        await self._flush()
        try:
            status = await asyncio.wait_for(stream.headers_future, timeout)
        except asyncio.TimeoutError:
            await stream.reset()
            raise TunnelError("timeout waiting for CONNECT response") from None
        if status != 200:
            await stream.reset()
            raise TunnelError(f"upstream refused CONNECT to {host}:{port}: HTTP {status}")
        return stream

    def usable(self) -> bool:
        # client stream ids are odd and limited to 2**31 - 1
        highest = getattr(self._conn, "highest_outbound_stream_id", 0)
        return not self.closed and highest < (1 << 31) - 1000

    # -- internals -----------------------------------------------------

    async def _flush(self) -> None:
        data = self._conn.data_to_send()
        if data and self._writer and not self._writer.is_closing():
            self._writer.write(data)
            await self._writer.drain()

    async def _ack(self, stream_id: int, nbytes: int) -> None:
        try:
            self._conn.acknowledge_received_data(nbytes, stream_id)
            await self._flush()
        except (h2.exceptions.H2Error, ConnectionError, OSError):
            pass

    async def _send_data(self, stream: H2Stream, data: bytes) -> None:
        view = memoryview(data)
        while len(view):
            if self.closed or stream.local_closed:
                raise TunnelError("stream closed")
            try:
                window = self._conn.local_flow_control_window(stream.id)
            except h2.exceptions.H2Error as e:
                raise TunnelError(f"stream closed: {e}") from e
            n = min(window, len(view), self._conn.max_outbound_frame_size)
            if n <= 0:
                self._window_changed.clear()
                await self._window_changed.wait()
                continue
            try:
                self._conn.send_data(stream.id, bytes(view[:n]))
            except h2.exceptions.H2Error as e:
                raise TunnelError(f"send failed: {e}") from e
            view = view[n:]
            await self._flush()

    async def _end_stream(self, stream: H2Stream) -> None:
        if stream.local_closed:
            return
        stream.local_closed = True
        try:
            self._conn.end_stream(stream.id)
            await self._flush()
        except (h2.exceptions.H2Error, ConnectionError, OSError):
            pass
        self._forget_if_done(stream)

    async def _reset_stream(self, stream: H2Stream) -> None:
        stream.local_closed = stream.remote_closed = True
        try:
            self._conn.reset_stream(stream.id)
            await self._flush()
        except (h2.exceptions.H2Error, ConnectionError, OSError):
            pass
        self._streams.pop(stream.id, None)

    def _forget_if_done(self, stream: H2Stream) -> None:
        if stream.local_closed and stream.remote_closed:
            self._streams.pop(stream.id, None)

    async def _read_loop(self) -> None:
        error: Exception = TunnelError("connection closed by upstream")
        try:
            while True:
                data = await self._reader.read(65536)
                if not data:
                    break
                try:
                    events = self._conn.receive_data(data)
                except h2.exceptions.ProtocolError as e:
                    error = TunnelError(f"HTTP/2 protocol error: {e}")
                    break
                for event in events:
                    self._handle_event(event)
                await self._flush()
        except (ConnectionError, OSError, ssl.SSLError) as e:
            error = TunnelError(f"connection error: {e}")
        except asyncio.CancelledError:
            raise
        finally:
            self._fail_all(error)

    def _handle_event(self, ev) -> None:
        stream = self._streams.get(getattr(ev, "stream_id", 0) or 0)
        if isinstance(ev, h2.events.ResponseReceived) and stream:
            headers = dict(ev.headers)
            if not stream.headers_future.done():
                stream.headers_future.set_result(int(headers.get(":status", 0)))
        elif isinstance(ev, h2.events.DataReceived):
            if stream:
                stream._queue.put_nowait(bytes(ev.data))
            else:  # stream already gone: still return the flow-control credit
                try:
                    self._conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                except h2.exceptions.H2Error:
                    pass
        elif isinstance(ev, h2.events.StreamEnded) and stream:
            stream.remote_closed = True
            stream._queue.put_nowait(None)
            self._forget_if_done(stream)
        elif isinstance(ev, h2.events.StreamReset) and stream:
            err = TunnelError(f"stream reset by upstream (code {ev.error_code})")
            if not stream.headers_future.done():
                stream.headers_future.set_exception(err)
            stream._queue.put_nowait(err)
            stream.local_closed = stream.remote_closed = True
            self._streams.pop(stream.id, None)
            self._window_changed.set()
        elif isinstance(ev, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
            self._window_changed.set()
        elif isinstance(ev, h2.events.ConnectionTerminated):
            self._fail_all(TunnelError(f"upstream sent GOAWAY (code {ev.error_code})"))

    def _fail_all(self, err: Exception) -> None:
        self.closed = True
        for stream in list(self._streams.values()):
            if not stream.headers_future.done():
                stream.headers_future.set_exception(err)
            stream._queue.put_nowait(err)
            stream.local_closed = stream.remote_closed = True
        self._streams.clear()
        self._window_changed.set()


class UpstreamPool:
    """Keeps one live HTTP/2 session to the chosen upstream and reconnects on failure."""

    def __init__(self, host: str, port: int,
                 auth_header: Callable[[], str],
                 session_factory: Callable[[str, int], H2Session] = H2Session):
        self.host, self.port = host, port
        self._auth_header = auth_header
        self._factory = session_factory
        self._session: Optional[H2Session] = None
        self._lock = asyncio.Lock()

    async def _get_session(self) -> H2Session:
        async with self._lock:
            if self._session is None or not self._session.usable():
                if self._session is not None:
                    await self._session.aclose()
                session = self._factory(self.host, self.port)
                await session.connect()
                self._session = session
            return self._session

    async def open_tunnel(self, host: str, port: int) -> H2Stream:
        last: Optional[Exception] = None
        for _ in range(2):  # one transparent retry on a dead session
            session = await self._get_session()
            try:
                return await session.open_tunnel(host, port, self._auth_header())
            except TunnelError as e:
                last = e
                if not session.closed:
                    break  # session is healthy: the target itself failed
        raise last or TunnelError("could not open tunnel")

    async def aclose(self) -> None:
        if self._session:
            await self._session.aclose()
