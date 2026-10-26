"""foxyvpn-py: an unofficial Python client for Firefox VPN's HTTP/2 CONNECT proxy.

It signs in with a Firefox Account, obtains a proxy pass from Mozilla's
Guardian service and exposes a local SOCKS5 proxy whose connections are
tunnelled through Firefox VPN's edge servers over HTTP/2 CONNECT.
"""

__version__ = "0.1.0"
USER_AGENT = f"foxyvpn-py/{__version__}"