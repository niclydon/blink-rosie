"""
Minimal Blink REST client.

Header set is deliberately Bearer + Content-Type only — blink-mcp proved that
sending User-Agent / APP-BUILD on REST traffic triggers HTTP 426. The
Blink-app UA is only used on the OAuth refresh path (see session.py).

The probe scripts under src/rosie_*.py drive this client; they should call
.request() with `raise_on_error=False` so 4xx responses are returned for diff
analysis rather than raising.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from dataclasses import dataclass
from typing import Any, Optional

import requests

from src.session import (
    BlinkAuthError,
    BlinkSession,
    ensure_fresh,
    load_session,
    refresh as refresh_session,
)

HTTP_TIMEOUT_S = 15


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: Any
    raw_text: str
    url: str
    method: str


class BlinkClient:
    def __init__(self, session: Optional[BlinkSession] = None):
        self.session = session or load_session()
        self.base = f"https://rest-{self.session.tier}.immedia-semi.com"
        self._refresh_lock = threading.Lock()

    def _auth_headers(self, has_body: bool = False) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self.session.access_token}",
            "Accept": "application/json",
        }
        if has_body:
            h["Content-Type"] = "application/json"
        return h

    def _refresh_locked(self) -> None:
        with self._refresh_lock:
            self.session = refresh_session(self.session)

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        raise_on_error: bool = True,
    ) -> Response:
        self.session = ensure_fresh(self.session)
        url = path if path.startswith("http") else f"{self.base}{path if path.startswith('/') else '/' + path}"
        res = self._do(method, url, body)
        if res.status_code in (401, 403):
            self._refresh_locked()
            res = self._do(method, url, body)
        text = res.text
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = None
        out = Response(
            status=res.status_code,
            headers=dict(res.headers),
            body=parsed,
            raw_text=text,
            url=url,
            method=method.upper(),
        )
        if raise_on_error and not (200 <= res.status_code < 300):
            if res.status_code in (401, 403):
                raise BlinkAuthError(
                    f"Blink rejected the token after refresh ({res.status_code}). "
                    "Re-run `npm run auth` in ~/projects/blink-mcp."
                )
            raise requests.HTTPError(f"{method.upper()} {url} → HTTP {res.status_code}: {text[:200]}")
        return out

    def _do(self, method: str, url: str, body: Any) -> requests.Response:
        has_body = body is not None
        return requests.request(
            method.upper(),
            url,
            headers=self._auth_headers(has_body=has_body),
            data=json.dumps(body) if has_body else None,
            timeout=HTTP_TIMEOUT_S,
        )

    def homescreen(self) -> dict:
        return self.request("GET", f"/api/v3/accounts/{self.session.account_id}/homescreen").body  # type: ignore[return-value]


def _cmd_ping(_args: argparse.Namespace) -> int:
    c = BlinkClient()
    home = c.homescreen()
    nets = home.get("networks", []) or []
    cams = home.get("cameras", []) or []
    owls = home.get("owls", []) or []
    rosies = (home.get("accessories", {}) or {}).get("rosie", []) or []
    print(
        f"ok tier={c.session.tier} account={c.session.account_id} "
        f"networks={len(nets)} cameras={len(cams)} owls={len(owls)} rosies={len(rosies)}"
    )
    return 0


def _cmd_rosies(_args: argparse.Namespace) -> int:
    c = BlinkClient()
    home = c.homescreen()
    rosies = (home.get("accessories", {}) or {}).get("rosie", []) or []
    if not rosies:
        print("no rosie accessories on this account")
        return 1
    for r in rosies:
        print(json.dumps(r, indent=2, sort_keys=True))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="src.api_client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ping", help="hit /homescreen and print a one-line summary")
    sub.add_parser("rosies", help="dump rosie accessory records from homescreen")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "ping":
            return _cmd_ping(args)
        if args.cmd == "rosies":
            return _cmd_rosies(args)
    except BlinkAuthError as e:
        print(f"auth error: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
