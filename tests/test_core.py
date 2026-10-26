import asyncio
import base64
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from foxyvpn_py import fxa, guardian, serverlist, socks, tokens  # noqa: E402
from foxyvpn_py.h2tunnel import format_authority  # noqa: E402


class HkdfTests(unittest.TestCase):
    def test_rfc5869_case1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865")
        self.assertEqual(fxa.hkdf_sha256(ikm, salt, info, 42), expected)

    def test_rfc5869_case3_empty_salt_and_info(self):
        ikm = bytes.fromhex("0b" * 22)
        expected = bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8")
        self.assertEqual(fxa.hkdf_sha256(ikm, None, b"", 42), expected)


class FxaTests(unittest.TestCase):
    def test_auth_pw_is_deterministic_32_bytes(self):
        a = fxa.derive_auth_pw("user@example.com", "hunter2")
        self.assertEqual(len(a), 32)
        self.assertEqual(a, fxa.derive_auth_pw("user@example.com", "hunter2"))
        self.assertNotEqual(a, fxa.derive_auth_pw("user@example.com", "hunter3"))
        self.assertNotEqual(a, fxa.derive_auth_pw("other@example.com", "hunter2"))

    def test_hawk_credentials_split(self):
        hid, key = fxa.derive_hawk_credentials("ab" * 32, "sessionToken")
        self.assertEqual(len(hid), 64)
        self.assertEqual(len(key), 32)
        raw = fxa.hkdf_sha256(bytes.fromhex("ab" * 32), None,
                              b"identity.mozilla.com/picl/v1/sessionToken", 96)
        self.assertEqual(hid, raw[:32].hex())
        self.assertEqual(key, raw[32:64])

    def test_hawk_header_mac(self):
        key = b"k" * 32
        body = '{"code":"123456"}'
        url = "https://api.accounts.firefox.com/v1/session/verify_code"
        header = fxa.hawk_header("post", url, "abc", key, body, ts=1700000000, nonce="n0nce")

        payload_hash = hashlib.sha256(
            b"hawk.1.payload\napplication/json\n" + body.encode() + b"\n").hexdigest()
        normalized = "\n".join(["hawk.1.header", "1700000000", "n0nce", "POST",
                                "/v1/session/verify_code", "api.accounts.firefox.com", "443",
                                payload_hash, "", ""])
        mac = hmac.new(key, normalized.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(
            header,
            f'Hawk id="abc", ts="1700000000", nonce="n0nce", mac="{mac}", hash="{payload_hash}"')

    def test_hawk_header_without_payload_has_no_hash(self):
        header = fxa.hawk_header("GET", "https://x.test/a?b=1", "id", b"k", ts=1, nonce="n")
        self.assertNotIn("hash=", header)


class GuardianTests(unittest.TestCase):
    def test_parse_jwt_claims_unpadded_base64url(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "x", "exp": 1234567890, "iat": 1234560000}).encode()
        ).rstrip(b"=").decode()
        claims = guardian.parse_jwt_claims(f"aaa.{payload}.bbb")
        self.assertEqual(claims["exp"], 1234567890)

    def test_parse_jwt_rejects_garbage(self):
        with self.assertRaises(ValueError):
            guardian.parse_jwt_claims("not-a-jwt")

    def test_bearer(self):
        self.assertEqual(guardian.ProxyPass(raw_token="T").bearer, "Bearer T")


class TokenStoreTests(unittest.TestCase):
    def test_save_load_permissions_and_expiry(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sub" / "tokens.json"
            tok = fxa.TokenResponse("acc", "ref", 3600, "scope")
            tokens.save(tok, path, now=1000.0)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            saved = tokens.load(path)
            self.assertEqual((saved.access_token, saved.refresh_token), ("acc", "ref"))
            self.assertTrue(saved.access_token_valid(now=1000.0 + 3000))
            self.assertFalse(saved.access_token_valid(now=1000.0 + 3600))
            tokens.delete(path)
            self.assertIsNone(tokens.load(path))


SAMPLE_LIST = {"data": [
    {"id": "1", "name": "Germany", "code": "DE", "cities": [
        {"name": "Frankfurt", "code": "FRA", "servers": [
            {"hostname": "a.example", "port": 443, "quarantined": False, "protocols": [
                {"name": "connect", "host": "a-connect.example", "port": 2499, "scheme": "https"},
                {"name": "masque", "host": "a.example", "port": 443}]},
            {"hostname": "b.example", "port": 443, "quarantined": True, "protocols": []},
            {"hostname": "c.example", "port": 443, "protocols": []},
            {"hostname": "d.example", "port": 443, "protocols": [{"name": "masque", "host": "d", "port": 1}]},
        ]}]},
    {"id": "2", "name": "Broken", "code": "", "cities": []},
]}


class ServerListTests(unittest.TestCase):
    def test_parse_flatten_filter(self):
        countries = serverlist.parse_server_list(SAMPLE_LIST)
        self.assertEqual(len(countries), 1)
        eps = serverlist.flatten(countries)
        self.assertEqual([e.addr for e in eps], ["a-connect.example:2499", "c.example:443"])
        self.assertEqual(len(serverlist.filter_country(eps, "de")), 2)
        self.assertEqual(len(serverlist.filter_country(eps, "Germany")), 2)
        self.assertEqual(serverlist.filter_country(eps, "FR"), [])


class FakeStream:
    """In-memory stand-in for an H2Stream that echoes what it receives."""

    def __init__(self):
        self.inbox = asyncio.Queue()
        self.sent = bytearray()
        self.write_closed = False
        self.was_reset = False

    async def read_chunk(self):
        return await self.inbox.get()

    async def write(self, data):
        self.sent += data
        await self.inbox.put(b"echo:" + data)

    async def close_write(self):
        self.write_closed = True
        await self.inbox.put(b"")

    async def reset(self):
        self.was_reset = True


class SocksTests(unittest.IsolatedAsyncioTestCase):
    async def _start(self, opener):
        server = await socks.serve("127.0.0.1", 0, opener)
        port = server.sockets[0].getsockname()[1]
        return server, port

    async def test_connect_domain_and_relay(self):
        seen, stream = [], FakeStream()

        async def opener(host, port):
            seen.append((host, port))
            return stream

        server, port = await self._start(opener)
        async with server:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            self.assertEqual(await r.readexactly(2), b"\x05\x00")
            name = b"example.com"
            w.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
            rep = await r.readexactly(10)
            self.assertEqual(rep[1], socks.REP_SUCCEEDED)
            w.write(b"hello")
            self.assertEqual(await asyncio.wait_for(r.readexactly(10), 3), b"echo:hello")
            w.write_eof()
            self.assertEqual(await asyncio.wait_for(r.read(), 3), b"")
            w.close()
        self.assertEqual(seen, [("example.com", 443)])
        self.assertEqual(bytes(stream.sent), b"hello")
        self.assertTrue(stream.write_closed)

    async def test_ipv4_and_ipv6_requests(self):
        seen = []

        async def opener(host, port):
            seen.append((host, port))
            raise RuntimeError("nope")

        server, port = await self._start(opener)
        async with server:
            for atyp_bytes, expected in (
                (b"\x01" + bytes([1, 2, 3, 4]), "1.2.3.4"),
                (b"\x04" + (b"\x00" * 15 + b"\x01"), "::1"),
            ):
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"\x05\x01\x00")
                await r.readexactly(2)
                w.write(b"\x05\x01\x00" + atyp_bytes + (80).to_bytes(2, "big"))
                rep = await r.readexactly(10)
                self.assertEqual(rep[1], socks.REP_HOST_UNREACHABLE)
                w.close()
        self.assertEqual(seen, [("1.2.3.4", 80), ("::1", 80)])

    async def test_rejects_unsupported_command_and_auth(self):
        async def opener(host, port):
            raise AssertionError("must not be called")

        server, port = await self._start(opener)
        async with server:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x02")  # only user/pass auth offered
            self.assertEqual(await r.readexactly(2), b"\x05\xff")
            w.close()

            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            await r.readexactly(2)
            w.write(b"\x05\x02\x00\x01" + bytes(4) + bytes(2))  # BIND
            rep = await r.readexactly(10)
            self.assertEqual(rep[1], socks.REP_CMD_NOT_SUPPORTED)
            w.close()


class BrowserSessionTests(unittest.TestCase):
    def test_clean_cookie(self):
        from foxyvpn_py import session
        self.assertEqual(session.clean_cookie("Cookie: a=b; c=d "), "a=b; c=d")
        self.assertEqual(session.clean_cookie("a=b"), "a=b")
        with self.assertRaises(ValueError):
            session.clean_cookie("garbage")
        with self.assertRaises(ValueError):
            session.clean_cookie("a=b\nX-Evil: 1")

    def test_save_load_permissions(self):
        from foxyvpn_py import session
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x" / "session.json"
            session.save(session.BrowserSession("a=b", "UA/1"), p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            self.assertEqual(session.load(p), session.BrowserSession("a=b", "UA/1"))
            session.delete(p)
            self.assertIsNone(session.load(p))

    def test_make_session_carries_cookie_and_ua(self):
        s = fxa.make_session("a=b; c=d", "Browser/9")
        self.assertEqual(s.headers["Cookie"], "a=b; c=d")
        self.assertEqual(s.headers["User-Agent"], "Browser/9")
        self.assertNotIn("Cookie", fxa.make_session().headers)

    def test_default_session_is_used_and_406_maps_to_challenge(self):
        calls = []

        class Resp:
            status_code = 406
            content = b""
            text = ""

        class Sess(fxa.requests.Session):
            def request(self, method, url, **kw):
                calls.append((method, url, kw["headers"]))
                return Resp()

        s = Sess()
        s.headers["Cookie"] = "a=b"
        fxa.set_default_session(s)
        try:
            with self.assertRaises(fxa.ChallengeRequired):
                fxa.refresh_token("r")
        finally:
            fxa.set_default_session(None)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("User-Agent", calls[0][2])  # the session's own UA is used


class MiscTests(unittest.TestCase):
    def test_format_authority(self):
        self.assertEqual(format_authority("example.com", 443), "example.com:443")
        self.assertEqual(format_authority("::1", 443), "[::1]:443")


if __name__ == "__main__":
    unittest.main()
