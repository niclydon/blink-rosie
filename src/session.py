"""
Blink session reader + OAuth refresh. Reuses the session file produced by
blink-mcp's auth bootstrap (~/.blink-mcp/session.json), so this project never
re-does the OAuth + 2FA dance — it just consumes the token blink-mcp got and
refreshes it when it goes stale.

Refresh shape mirrors ~/projects/blink-mcp/src/blink/client.ts:155-225 exactly.
If the OAuth endpoint rejects the refresh_token, fall back to:
    cd ~/projects/blink-mcp && eval "$(~/projects/secrets-vault/bin/sv get blink-mcp)" && npm run auth
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import requests

DEFAULT_SESSION_PATH = Path.home() / ".blink-mcp" / "session.json"
OAUTH_TOKEN_URL = "https://api.oauth.blink.com/oauth/token"
OAUTH_TOKEN_UA = "Blink/2511191620 CFNetwork/3860.200.71 Darwin/25.1.0"
REFRESH_LEEWAY_S = 300
REQUIRED_FIELDS = ("access_token", "tier", "account_id", "client_id", "unique_id")


class BlinkAuthError(RuntimeError):
    """Raised when the stored session cannot be refreshed and re-auth is needed."""


@dataclass
class BlinkSession:
    email: str
    account_id: int
    client_id: str
    tier: str
    access_token: str
    unique_id: str
    user_id: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    expiration_date: Optional[float] = None
    host: Optional[str] = None
    saved_at: Optional[str] = None

    def is_stale(self, leeway_s: int = REFRESH_LEEWAY_S) -> bool:
        if self.expiration_date is None:
            return False
        return self.expiration_date - time.time() <= leeway_s


def session_path() -> Path:
    override = os.environ.get("BLINK_MCP_SESSION")
    return Path(override) if override else DEFAULT_SESSION_PATH


def load_session(path: Optional[Path] = None) -> BlinkSession:
    p = path or session_path()
    raw = json.loads(p.read_text())
    for field in REQUIRED_FIELDS:
        if not raw.get(field):
            raise BlinkAuthError(
                f"session file {p} is missing field '{field}'. "
                "Re-run `npm run auth` in ~/projects/blink-mcp to bootstrap."
            )
    known = {f for f in BlinkSession.__dataclass_fields__}
    return BlinkSession(**{k: v for k, v in raw.items() if k in known})


def save_session(s: BlinkSession, path: Optional[Path] = None) -> None:
    p = path or session_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(asdict(s), indent=2, sort_keys=True))
    tmp.chmod(0o600)
    tmp.replace(p)


def refresh(s: BlinkSession, persist: bool = True) -> BlinkSession:
    if not s.refresh_token:
        raise BlinkAuthError(
            "session has no refresh_token. Re-run `npm run auth` in ~/projects/blink-mcp."
        )
    res = requests.post(
        OAUTH_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": s.refresh_token,
            "client_id": "ios",
            "scope": "client",
            "hardware_id": s.unique_id,
        },
        headers={
            "User-Agent": OAUTH_TOKEN_UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
        },
        timeout=15,
    )
    if res.status_code != 200:
        raise BlinkAuthError(
            f"OAuth refresh failed (HTTP {res.status_code}): {res.text[:256]}. "
            "Re-run `npm run auth` in ~/projects/blink-mcp."
        )
    tokens = res.json()
    if not tokens.get("access_token"):
        raise BlinkAuthError(f"OAuth refresh returned no access_token: {tokens}")

    now = time.time()
    fresh = BlinkSession(
        **{**asdict(s),
           "access_token": tokens["access_token"],
           "refresh_token": tokens.get("refresh_token") or s.refresh_token,
           "expires_in": tokens.get("expires_in") or s.expires_in,
           "expiration_date": (now + tokens["expires_in"])
                              if tokens.get("expires_in")
                              else s.expiration_date,
           "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now)),
           })
    if persist:
        save_session(fresh)
    return fresh


def ensure_fresh(s: BlinkSession, persist: bool = True) -> BlinkSession:
    return refresh(s, persist=persist) if s.is_stale() else s
