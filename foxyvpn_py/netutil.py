"""HTTP session for control-plane calls (Guardian, server list).

It deliberately ignores the operating system's proxy settings: when the Windows
system proxy points at this program's own local port, renewing the proxy pass
through it would loop back into the tunnel that needs that very pass.

If you really need a proxy for these calls, set FOXYVPN_API_PROXY, for example
``set FOXYVPN_API_PROXY=http://127.0.0.1:10809``.
"""

from __future__ import annotations

import os

import requests


def control_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    proxy = os.environ.get("FOXYVPN_API_PROXY", "").strip()
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s
