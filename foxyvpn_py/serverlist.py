"""Server list from Mozilla Remote Settings and endpoint selection."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

import requests

from . import USER_AGENT

REMOTE_SETTINGS_URL = ("https://firefox.settings.services.mozilla.com/v1/buckets/main/"
                       "collections/vpn-serverlist/records")


@dataclass(frozen=True)
class Endpoint:
    country_code: str
    country_name: str
    city_name: str
    hostname: str
    port: int

    @property
    def addr(self) -> str:
        return f"{self.hostname}:{self.port}"


def fetch_server_list(session: Optional[requests.Session] = None) -> list[dict]:
    sender = session or requests
    resp = sender.get(REMOTE_SETTINGS_URL, headers={"User-Agent": USER_AGENT,
                                                    "Accept": "application/json"}, timeout=30)
    resp.raise_for_status()
    return parse_server_list(resp.json())


def parse_server_list(payload: dict) -> list[dict]:
    countries = []
    for rec in payload.get("data", []):
        if isinstance(rec, dict) and rec.get("code") and rec.get("cities"):
            countries.append(rec)
    return countries


def flatten(countries: list[dict]) -> list[Endpoint]:
    """One Endpoint per usable (non-quarantined) HTTPS CONNECT server."""
    out: list[Endpoint] = []
    for country in countries:
        for city in country.get("cities", []):
            for srv in city.get("servers", []):
                if srv.get("quarantined"):
                    continue
                host, port = srv.get("hostname"), srv.get("port")
                protocols = srv.get("protocols") or []
                connect = next((p for p in protocols if p.get("name") == "connect"), None)
                if connect:
                    if connect.get("scheme", "https") != "https":
                        continue
                    host, port = connect.get("host") or host, connect.get("port") or port
                elif protocols:
                    continue  # only non-CONNECT protocols (e.g. MASQUE) are advertised
                if host and port:
                    out.append(Endpoint(country.get("code", ""), country.get("name", ""),
                                        city.get("name", ""), host, int(port)))
    return out


def filter_country(endpoints: list[Endpoint], query: str) -> list[Endpoint]:
    q = query.strip().lower()
    return [e for e in endpoints if e.country_code.lower() == q or e.country_name.lower() == q]


async def _probe(ep: Endpoint, timeout: float) -> float:
    start = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ep.hostname, ep.port), timeout)
    except (OSError, asyncio.TimeoutError):
        return float("inf")
    w.close()
    return time.perf_counter() - start


async def pick_fastest(candidates: list[Endpoint], sample: int = 6, timeout: float = 4.0) -> Endpoint:
    """TCP-connect latency probe over up to `sample` candidates."""
    if not candidates:
        raise ValueError("no candidate servers")
    subset = candidates[:sample]
    times = await asyncio.gather(*(_probe(e, timeout) for e in subset))
    best = min(range(len(subset)), key=lambda i: times[i])
    return subset[best]
