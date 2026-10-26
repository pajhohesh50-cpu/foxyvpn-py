"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from pathlib import Path

from . import __version__, app, fxa, guardian, serverlist, tokens


def cmd_login(args) -> int:
    email = args.email or input("Firefox account email: ").strip()
    password = getpass.getpass("Password: ")
    try:
        login = fxa.login(email, password)
        if not login.verified:
            print("Mozilla sent a verification code to your email.")
            code = input("Code: ").strip()
            fxa.verify_session(login.session_token, code)
        tok = fxa.oauth_token(login.session_token)
    except fxa.ChallengeRequired:
        print("Mozilla's CDN answered with an anti-bot challenge (HTTP 406), which this client "
              "does not attempt to solve. Try again later or from a different network.",
              file=sys.stderr)
        return 2
    except fxa.FxaError as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1
    tokens.save(tok, Path(args.token_file))
    print(f"Logged in. Tokens saved to {args.token_file} (mode 0600).")
    try:
        info = guardian.get_proxy_pass(tok.access_token)
        print(f"Guardian OK. Quota: {info.quota_left or '?'} / {info.quota_max or '?'} bytes left.")
    except Exception as e:  # noqa: BLE001
        print(f"Warning: could not obtain a proxy pass yet: {e}", file=sys.stderr)
    return 0


def cmd_servers(args) -> int:
    countries = serverlist.fetch_server_list()
    for country in sorted(countries, key=lambda c: c.get("name", "")):
        if args.country and args.country.lower() not in (country.get("code", "").lower(),
                                                         country.get("name", "").lower()):
            continue
        print(f"\n=== {country.get('name')} ({country.get('code')}) ===")
        for ep in serverlist.flatten([country]):
            print(f"  {ep.city_name:<20} {ep.addr}")
    return 0


def cmd_status(args) -> int:
    path = Path(args.token_file)
    saved = tokens.load(path)
    if not saved:
        print("Not logged in.")
        return 1
    token = app.ensure_access_token(path)
    info = guardian.get_proxy_pass(token)
    print(f"Proxy pass expires at unix time {info.exp}")
    print(f"Quota left: {info.quota_left or '?'} / {info.quota_max or '?'} (resets: {info.quota_reset or '?'})")
    return 0


def cmd_logout(args) -> int:
    tokens.delete(Path(args.token_file))
    print("Tokens removed.")
    return 0


def cmd_run(args) -> int:
    host, _, port = args.listen.rpartition(":")
    try:
        asyncio.run(app.run(host or "127.0.0.1", int(port), args.country, args.proxy,
                            Path(args.token_file), args.max_conns, args.verbose))
    except KeyboardInterrupt:
        pass
    except (RuntimeError, ValueError, guardian.QuotaExceeded) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="foxyvpn_py", description="Unofficial Firefox VPN client (SOCKS5)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--token-file", default=str(tokens.DEFAULT_PATH))
    p.add_argument("-v", "--verbose", action="store_true", help="log tunnel targets (privacy-sensitive)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login", help="sign in with a Firefox account")
    s.add_argument("--email")
    s.set_defaults(func=cmd_login)

    s = sub.add_parser("servers", help="list available locations")
    s.add_argument("--country")
    s.set_defaults(func=cmd_servers)

    s = sub.add_parser("status", help="show quota information")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("logout", help="delete stored tokens")
    s.set_defaults(func=cmd_logout)

    s = sub.add_parser("run", help="start the local SOCKS5 proxy")
    s.add_argument("--country", help="country code or name, e.g. DE")
    s.add_argument("--proxy", help="exact upstream HOST:PORT (overrides --country)")
    s.add_argument("--listen", default="127.0.0.1:1088")
    s.add_argument("--max-conns", type=int, default=256)
    s.set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-5s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
