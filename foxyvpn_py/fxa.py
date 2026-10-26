"""Firefox Account (FxA) authentication with Fastly challenge solving."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from curl_cffi import requests as cffi_requests

from . import USER_AGENT

FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
FIREFOX_CLIENT_ID = "5882386c6d801776"
OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
PBKDF2_ROUNDS = 1000
HTTP_TIMEOUT = 30

VERIFICATION_EMAIL_2FA = "email-2fa"
ERRNO_INVALID_PARAMETER = 107


class FxaError(Exception):
    def __init__(self, status: int, errno: int, body: str):
        self.status, self.errno, self.body = status, errno, body
        super().__init__(f"FxA error (HTTP {status}, errno {errno}): {body[:300]}")


class ChallengeRequired(FxaError):
    pass


@dataclass
class LoginResponse:
    session_token: str
    uid: str
    verified: bool
    verification_method: str = ""
    verification_reason: str = ""


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: str
    expires_in: int
    scope: str = ""
    token_type: str = ""


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_auth_pw(email: str, password: str) -> bytes:
    salt = (PROTOCOL_VERSION + "quickStretch:" + email).encode()
    stretched = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS, 32)
    return hkdf_sha256(stretched, b"\x00", (PROTOCOL_VERSION + "authPW").encode(), 32)


def derive_hawk_credentials(token_hex: str, context: str) -> tuple[str, bytes]:
    token = bytes.fromhex(token_hex)
    out = hkdf_sha256(token, None, (PROTOCOL_VERSION + context).encode(), 96)
    return out[:32].hex(), out[32:64]


def hawk_header(method: str, url: str, hawk_id: str, hawk_key: bytes, payload: str = "",
                *, ts: Optional[int] = None, nonce: Optional[str] = None) -> str:
    u = urlsplit(url)
    nonce = nonce or secrets.token_hex(6)
    ts_str = str(int(time.time()) if ts is None else ts)
    port = u.port or (443 if u.scheme == "https" else 80)
    request_uri = u.path + (("?" + u.query) if u.query else "")

    payload_hash = ""
    if payload:
        h = hashlib.sha256()
        h.update(b"hawk.1.payload\napplication/json\n")
        h.update(payload.encode())
        h.update(b"\n")
        payload_hash = h.hexdigest()

    normalized = "\n".join([
        "hawk.1.header", ts_str, nonce, method.upper(), request_uri,
        u.hostname or "", str(port), payload_hash, "", "",
    ])
    mac = hmac.new(hawk_key, normalized.encode(), hashlib.sha256).hexdigest()
    header = f'Hawk id="{hawk_id}", ts="{ts_str}", nonce="{nonce}", mac="{mac}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    return header


# --------------------------------------------------------------------------
# Fastly challenge solver (Playwright + manual CAPTCHA)
# --------------------------------------------------------------------------

def solve_fastly_challenge() -> list[dict]:
    from playwright.sync_api import sync_playwright
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        
        # دسترسی به صفحه ورود واقعی، نه API endpoint
        page.goto("https://accounts.firefox.com/signin", wait_until="networkidle")
        page.wait_for_timeout(3000)
        
        print(f"[challenge] Page title: {page.title()}")
        print(f"[challenge] Page URL: {page.url}")
        
        # در اینجا می‌توانید به صورت دستی در مرورگر ورود کنید
        # یا از page.fill() برای پر کردن خودکار ایمیل و رمز عبور استفاده کنید
        
        input("[challenge] Please log in manually in the browser, then press Enter here...")
        
        cookies = context.cookies()
        print(f"[challenge] Collected {len(cookies)} cookies:")
        for c in cookies:
            print(f"  - {c['name']} (domain={c['domain']})")
        
        browser.close()
        return cookies
    """
    Launch a real Chromium browser, navigate to the FxA login endpoint.
    Fastly will auto-solve the JS challenge or present a CAPTCHA.
    User manually enters CAPTCHA if shown. Returns all cookies from the context.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        print("[challenge] Navigating to FxA login endpoint...")
        page.goto("https://api.accounts.firefox.com/v1/account/login",
                  wait_until="domcontentloaded", timeout=30000)

        # Wait for challenge page to settle
        page.wait_for_timeout(3000)
        title = page.title()
        url = page.url
        print(f"[challenge] Page title: {title}")
        print(f"[challenge] Page URL: {url}")

        # Check if CAPTCHA is present
        captcha_img = page.query_selector('img[src^="data:image"]')
        if captcha_img:
            print("[challenge] CAPTCHA image detected!")
            img_bytes = captcha_img.screenshot()
            with open("captcha.png", "wb") as f:
                f.write(img_bytes)
            print("[challenge] CAPTCHA saved to captcha.png")
            answer = input("[challenge] Enter the characters you see: ").strip()

            # Find input field and fill
            inp = page.query_selector('input[type="text"], input:not([type])')
            if inp:
                inp.fill(answer)
                inp.press("Enter")
                print("[challenge] CAPTCHA submitted, waiting for verification...")
                page.wait_for_timeout(5000)
            else:
                print("[challenge] WARNING: Could not find input field, trying Enter on body")
                page.keyboard.press("Enter")
                page.wait_for_timeout(5000)

        # Additional wait to ensure challenge completion cookies are set
        page.wait_for_timeout(2000)

        cookies = context.cookies()
        print(f"[challenge] Collected {len(cookies)} cookies:")
        for c in cookies:
            print(f"  - {c['name']} (domain={c['domain']}, path={c['path']})")

        browser.close()
        return cookies


# --------------------------------------------------------------------------
# API calls (using curl_cffi with matching TLS impersonation)
# --------------------------------------------------------------------------

def _request(method: str, path: str, body: Optional[dict] = None, *,
             hawk_token: Optional[str] = None,
             session: Optional[cffi_requests.Session] = None,
             challenge_cookies: Optional[list[dict]] = None) -> dict:
    url = FXA_AUTH_SERVER + path
    payload = json.dumps(body, separators=(",", ":")) if body is not None else ""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if hawk_token:
        hid, hkey = derive_hawk_credentials(hawk_token, "sessionToken")
        headers["Authorization"] = hawk_header(method, url, hid, hkey, payload)

    sender = session or cffi_requests.Session()

    if challenge_cookies:
        for c in challenge_cookies:
            sender.cookies.set(c["name"], c["value"], domain=c["domain"], path=c["path"])

    # Use chrome131 to match Playwright Chromium's TLS fingerprint
    resp = sender.request(
        method, url, data=payload or None, headers=headers,
        timeout=HTTP_TIMEOUT, impersonate="chrome131"
    )

    if resp.status_code == 406:
        raise ChallengeRequired(406, 0, "Fastly anti-bot challenge")
    if resp.status_code != 200:
        errno = 0
        try:
            errno = int(resp.json().get("errno", 0))
        except Exception:
            pass
        raise FxaError(resp.status_code, errno, resp.text)
    return resp.json() if resp.content else {}


def login(email: str, password: str) -> LoginResponse:
    auth_pw = derive_auth_pw(email, password).hex()
    session = cffi_requests.Session()

    def attempt(method: str, cookies=None) -> dict:
        body = {"email": email, "authPW": auth_pw}
        if method:
            body["verificationMethod"] = method
        return _request("POST", "/account/login", body, session=session,
                        challenge_cookies=cookies)

    try:
        data = attempt(VERIFICATION_EMAIL_2FA)
    except ChallengeRequired:
        print("[login] Fastly challenge detected. Launching browser...")
        cookies = solve_fastly_challenge()
        if not cookies:
            raise RuntimeError("No cookies obtained from browser challenge")
        data = attempt(VERIFICATION_EMAIL_2FA, cookies=cookies)
    except FxaError as e:
        if e.errno == ERRNO_INVALID_PARAMETER:
            data = attempt("")
        else:
            raise

    return LoginResponse(
        session_token=data["sessionToken"],
        uid=data.get("uid", ""),
        verified=bool(data.get("verified")),
        verification_method=data.get("verificationMethod", ""),
        verification_reason=data.get("verificationReason", ""),
    )


# --------------------------------------------------------------------------
# Remaining functions (unchanged)
# --------------------------------------------------------------------------

def verify_session(session_token: str, code: str, session=None) -> None:
    _request("POST", "/session/verify_code", {"code": code.strip()},
             hawk_token=session_token, session=session)


def _token_from(data: dict, fallback_refresh: str = "") -> TokenResponse:
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token") or fallback_refresh,
        expires_in=int(data.get("expires_in", 0)),
        scope=data.get("scope", ""),
        token_type=data.get("token_type", ""),
    )


def oauth_token(session_token: str, session=None) -> TokenResponse:
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "fxa-credentials",
        "scope": OAUTH_SCOPE,
        "access_type": "offline",
    }
    return _token_from(_request("POST", "/oauth/token", body, hawk_token=session_token, session=session))


def refresh_token(refresh: str, session=None) -> TokenResponse:
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "scope": OAUTH_SCOPE,
    }
    return _token_from(_request("POST", "/oauth/token", body, session=session), fallback_refresh=refresh)