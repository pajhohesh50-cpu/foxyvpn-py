"""Glue: token management, proxy-pass renewal, upstream selection, SOCKS5/HTTP server."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from . import fxa, guardian, serverlist, tokens
from .h2tunnel import UpstreamPool
from .socks import serve

# ماژول مدیریت پروکسی سیستم (فقط روی ویندوز کار می‌کند)
try:
    from . import sysproxy
    _HAS_SYSPROXY = True
except ImportError:
    _HAS_SYSPROXY = False

log = logging.getLogger("foxyvpn")

RENEW_MARGIN = 120      # renew the proxy pass this many seconds before it expires
MIN_RENEW_WAIT = 30
MAX_RENEW_WAIT = 1800
QUOTA_RETRY_WAIT = 900


def ensure_access_token(path: Path = tokens.DEFAULT_PATH) -> str:
    """Return a valid OAuth access token, refreshing and persisting it when needed."""
    saved = tokens.load(path)
    if saved is None:
        raise RuntimeError("not logged in: run `python -m foxyvpn_py login` first")
    if saved.access_token_valid():
        return saved.access_token
    if not saved.refresh_token:
        raise RuntimeError("access token expired and no refresh token stored: log in again")
    new = fxa.refresh_token(saved.refresh_token)
    return tokens.save(new, path).access_token


class ProxyPassKeeper:
    """Holds the current proxy pass and renews it in the background."""

    def __init__(self, token_path: Path = tokens.DEFAULT_PATH):
        self.token_path = token_path
        self.current: Optional[guardian.ProxyPass] = None
        self._task: Optional[asyncio.Task] = None

    def header(self) -> str:
        if self.current is None:
            raise RuntimeError("no proxy pass yet")
        return self.current.bearer

    def _fetch(self) -> guardian.ProxyPass:
        return guardian.get_proxy_pass(ensure_access_token(self.token_path))

    async def start(self) -> guardian.ProxyPass:
        self.current = await asyncio.to_thread(self._fetch)
        self._task = asyncio.create_task(self._renew_loop())
        return self.current

    async def _renew_loop(self) -> None:
        while True:
            wait = MIN_RENEW_WAIT
            if self.current and self.current.exp:
                wait = self.current.exp - time.time() - RENEW_MARGIN
            wait = max(MIN_RENEW_WAIT, min(MAX_RENEW_WAIT, wait))
            await asyncio.sleep(wait)
            try:
                self.current = await asyncio.to_thread(self._fetch)
                log.info("proxy pass renewed (quota left: %s)", self.current.quota_left or "?")
            except guardian.QuotaExceeded:
                log.error("monthly quota exhausted; retrying in %d s", QUOTA_RETRY_WAIT)
                await asyncio.sleep(QUOTA_RETRY_WAIT)
            except Exception as e:  # noqa: BLE001
                log.warning("proxy pass renewal failed: %s", e)
                await asyncio.sleep(60)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()


async def choose_endpoint(country: Optional[str], proxy: Optional[str]) -> serverlist.Endpoint:
    if proxy:
        host, _, port = proxy.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError("--proxy must look like HOST:PORT")
        return serverlist.Endpoint("", "", "", host, int(port))
    if not country:
        raise ValueError("choose a location with --country (see `servers`) or an exact --proxy HOST:PORT")
    countries = await asyncio.to_thread(serverlist.fetch_server_list)
    candidates = serverlist.filter_country(serverlist.flatten(countries), country)
    if not candidates:
        raise ValueError(f"no usable servers for country {country!r} (see `servers`)")
    return await serverlist.pick_fastest(candidates)


async def run(listen_host: str, listen_port: int, country: Optional[str], proxy: Optional[str],
              token_path: Path = tokens.DEFAULT_PATH, max_conns: int = 256,
              verbose: bool = False) -> None:
    endpoint = await choose_endpoint(country, proxy)
    keeper = ProxyPassKeeper(token_path)
    pass_ = await keeper.start()
    log.info("proxy pass OK (quota left: %s of %s)", pass_.quota_left or "?", pass_.quota_max or "?")
    log.info("upstream: %s (%s %s)", endpoint.addr, endpoint.country_code or "-", endpoint.city_name or "-")

    pool = UpstreamPool(endpoint.hostname, endpoint.port, keeper.header)
    server = await serve(listen_host, listen_port, pool.open_tunnel,
                         max_conns=max_conns, verbose=verbose)
    log.info("SOCKS5/HTTP proxy listening on %s:%d", listen_host, listen_port)

    # --- فعال‌سازی پروکسی سیستم (فقط روی ویندوز) ---
    if _HAS_SYSPROXY:
        sysproxy.enable_system_proxy(listen_host, listen_port)

    try:
        async with server:
            await server.serve_forever()
    finally:
        # --- غیرفعال‌سازی پروکسی سیستم (فقط روی ویندوز) ---
        if _HAS_SYSPROXY:
            sysproxy.disable_system_proxy()
        await keeper.stop()
        await pool.aclose()