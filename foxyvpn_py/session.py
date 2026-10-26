"""Browser session (cookie + User-Agent) saved after the user passes Mozilla's
client challenge in a real browser. Stored with mode 0600; treat it as a secret."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from . import USER_AGENT
from .tokens import DEFAULT_PATH as DEFAULT_TOKEN_PATH

DEFAULT_PATH = DEFAULT_TOKEN_PATH.parent / "session.json"


@dataclass
class BrowserSession:
    cookie: str
    user_agent: str = USER_AGENT


def clean_cookie(raw: str) -> str:
    """Accept a bare 'a=b; c=d' string or a pasted 'Cookie: a=b; c=d' header line."""
    raw = raw.strip()
    if raw.lower().startswith("cookie:"):
        raw = raw[len("cookie:"):].strip()
    if "\n" in raw or "\r" in raw:
        raise ValueError("cookie must be a single line")
    if raw and "=" not in raw:
        raise ValueError("cookie must look like name=value; name2=value2")
    return raw


def load(path: Path = DEFAULT_PATH) -> Optional[BrowserSession]:
    try:
        return BrowserSession(**json.loads(Path(path).read_text()))
    except (FileNotFoundError, ValueError, TypeError):
        return None


def save(sess: BrowserSession, path: Path = DEFAULT_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".tmp-")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(asdict(sess), f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def delete(path: Path = DEFAULT_PATH) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
