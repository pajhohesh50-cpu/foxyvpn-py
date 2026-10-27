"""Mozilla Guardian: exchange the OAuth access token for a proxy pass (JWT)."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Optional

import requests

from . import USER_AGENT
from .netutil import control_session

GUARDIAN_ENDPOINT = "https://vpn.mozilla.org"
HTTP_TIMEOUT = 30


class QuotaExceeded(Exception):
    """Monthly proxy quota exhausted (HTTP 429)."""


class TokenInvalid(Exception):
    """Guardian rejected the access token (HTTP 401/403)."""


class GuardianError(Exception):
    def __init__(self, op: str, status: int, body: str):
        super().__init__(f"{op} returned HTTP {status}: {body[:300]}")
        self.status = status


@dataclass
class ProxyPass:
    raw_token: str
    exp: int = 0
    iat: int = 0
    nbf: int = 0
    quota_max: str = ""
    quota_left: str = ""
    quota_reset: str = ""
    claims: dict = field(default_factory=dict)

    @property
    def bearer(self) -> str:
        return "Bearer " + self.raw_token


def parse_jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"invalid JWT: expected 3 parts, got {len(parts)}")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def fetch_proxy_pass(access_token: str, endpoint: str = GUARDIAN_ENDPOINT,
                     session: Optional[requests.Session] = None) -> ProxyPass:
    sender = session or control_session()
    resp = sender.get(endpoint.rstrip("/") + "/api/v1/fpn/token",
                      headers=_headers(access_token), timeout=HTTP_TIMEOUT)
    if resp.status_code == 429:
        raise QuotaExceeded(resp.text[:300])
    if resp.status_code in (401, 403):
        raise TokenInvalid(f"HTTP {resp.status_code}: {resp.text[:300]}")
    if resp.status_code != 200:
        raise GuardianError("guardian token", resp.status_code, resp.text)

    token = resp.json().get("token", "")
    if not token:
        raise GuardianError("guardian token", resp.status_code, "empty token in response")
    claims = parse_jwt_claims(token)
    return ProxyPass(
        raw_token=token,
        exp=int(claims.get("exp", 0)),
        iat=int(claims.get("iat", 0)),
        nbf=int(claims.get("nbf", 0)),
        quota_max=resp.headers.get("X-Quota-Limit", ""),
        quota_left=resp.headers.get("X-Quota-Remaining", ""),
        quota_reset=resp.headers.get("X-Quota-Reset", ""),
        claims=claims,
    )


def activate(access_token: str, endpoint: str = GUARDIAN_ENDPOINT,
             session: Optional[requests.Session] = None) -> dict:
    sender = session or control_session()
    resp = sender.post(endpoint.rstrip("/") + "/api/v1/fpn/activate",
                       headers=_headers(access_token), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        raise GuardianError("guardian activate", resp.status_code, resp.text)
    return resp.json()


def status(access_token: str, endpoint: str = GUARDIAN_ENDPOINT,
           session: Optional[requests.Session] = None) -> dict:
    sender = session or control_session()
    resp = sender.get(endpoint.rstrip("/") + "/api/v1/fpn/status",
                      headers=_headers(access_token), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        raise GuardianError("guardian status", resp.status_code, resp.text)
    return resp.json()


def get_proxy_pass(access_token: str, endpoint: str = GUARDIAN_ENDPOINT) -> ProxyPass:
    """Fetch a proxy pass, activating the account on the first 401/403."""
    try:
        return fetch_proxy_pass(access_token, endpoint)
    except TokenInvalid:
        activate(access_token, endpoint)
        return fetch_proxy_pass(access_token, endpoint)
