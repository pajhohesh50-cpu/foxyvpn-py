"""Persistent storage of the OAuth tokens (file mode 0600)."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .fxa import TokenResponse

DEFAULT_PATH = Path.home() / ".foxyvpn-py" / "tokens.json"


@dataclass
class SavedTokens:
    access_token: str
    refresh_token: str
    scope: str
    obtained_at: float
    expires_in: int

    def access_token_valid(self, now: Optional[float] = None) -> bool:
        if not self.access_token:
            return False
        now = time.time() if now is None else now
        return now < self.obtained_at + self.expires_in - 60


def load(path: Path = DEFAULT_PATH) -> Optional[SavedTokens]:
    try:
        data = json.loads(Path(path).read_text())
        return SavedTokens(**data)
    except (FileNotFoundError, ValueError, TypeError):
        return None


def save(tok: TokenResponse, path: Path = DEFAULT_PATH, now: Optional[float] = None) -> SavedTokens:
    saved = SavedTokens(
        access_token=tok.access_token,
        refresh_token=tok.refresh_token,
        scope=tok.scope,
        obtained_at=time.time() if now is None else now,
        expires_in=tok.expires_in,
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".tmp-")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(asdict(saved), f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return saved


def delete(path: Path = DEFAULT_PATH) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
