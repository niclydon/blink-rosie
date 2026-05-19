"""
IMMIS protocol client (observation layer).

Async TLS client that connects to a Blink IMMIS streaming server, sends the
122-byte auth header, runs the standard heartbeat cadence (LATENCY_STATS
every 1s, KEEPALIVE every 10s), and dispatches incoming frames by message
type. VIDEO frames are counted and discarded; everything else gets a hex-dump
JSONL log entry — this is the data we need to characterize what an idle
Rosie-attached session looks like at the wire level.

Auth header layout, packet framing, and heartbeat shape all come from
refs/blinkpy/blinkpy/livestream.py and refs/homebridge-blink-new/src/blink-api/immis-proxy.ts.
CLAUDE.md has the full byte-level spec.

Blink IMMIS uses a non-standard TLS cert chain, so we run with verify_mode
CERT_NONE. The connection is to a public AWS IP (we see 54.198.x.x), not to
the camera directly — the camera tunnels through Blink's relay infra.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from src.api_client import BlinkClient

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
SERIAL_LEN = 16
CONN_ID_LEN = 16
TOKEN_LEN = 64


class MsgType(IntEnum):
    VIDEO = 0x00
    KEEPALIVE = 0x0A
    LATENCY_STATS = 0x12
    INLINE_COMMAND = 0x14
    ACCESSORY_MESSAGE = 0x15
    SESSION_COMMAND = 0x17
    SESSION_MESSAGE = 0x18


@dataclass
class ImmisTarget:
    host: str
    port: int
    conn_id: str
    serial: str
    client_id: int
    auth_token: bytes = b""  # populates the 64-byte token slot in the auth header

    @classmethod
    def from_url(cls, url: str, auth_token: bytes = b"") -> "ImmisTarget":
        p = urlparse(url)
        if p.scheme != "immis":
            raise ValueError(f"expected immis://, got {p.scheme}://")
        path = p.path.lstrip("/")
        if "__IMDS_" not in path:
            raise ValueError(f"path missing __IMDS_ separator: {path!r}")
        conn_id, _, serial = path.partition("__IMDS_")
        client_id_q = parse_qs(p.query).get("client_id", [None])[0]
        if client_id_q is None:
            raise ValueError("immis URL missing client_id query param")
        if p.hostname is None or p.port is None:
            raise ValueError(f"immis URL missing host/port: {url!r}")
        return cls(
            host=p.hostname,
            port=p.port,
            conn_id=conn_id,
            serial=serial,
            client_id=int(client_id_q),
            auth_token=auth_token,
        )


def build_auth_header(target: ImmisTarget) -> bytes:
    """122-byte auth handshake. Byte layout matches CLAUDE.md exactly."""
    buf = bytearray()
    buf.extend(b"\x00\x00\x00\x28")  # magic
    buf.extend(SERIAL_LEN.to_bytes(4, "big"))
    buf.extend(target.serial.encode("utf-8")[:SERIAL_LEN].ljust(SERIAL_LEN, b"\x00"))
    buf.extend(target.client_id.to_bytes(4, "big"))
    buf.extend(b"\x01\x08")  # static
    buf.extend(TOKEN_LEN.to_bytes(4, "big"))
    token = target.auth_token[:TOKEN_LEN].ljust(TOKEN_LEN, b"\x00")
    buf.extend(token)
    buf.extend(CONN_ID_LEN.to_bytes(4, "big"))
    buf.extend(target.conn_id.encode("utf-8")[:CONN_ID_LEN].ljust(CONN_ID_LEN, b"\x00"))
    buf.extend(b"\x00\x00\x00\x01")  # trailer
    if len(buf) != 122:
        raise AssertionError(f"auth header length {len(buf)} != 122")
    return bytes(buf)


def frame(msgtype: int, sequence: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("payload too large for u32 length field")
    return (
        bytes([msgtype])
        + sequence.to_bytes(4, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


LATENCY_STATS_PAYLOAD = bytes(24)


class ImmisObserver:
    """Connect, hold the connection, log everything that isn't VIDEO."""

    def __init__(self, target: ImmisTarget, log_path: Path, duration_s: float):
        self.target = target
        self.log_path = log_path
        self.duration_s = duration_s
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.log_fh = None
        self.video_count = 0
        self.video_bytes = 0
        self.non_video_count = 0
        self.by_type: dict[int, int] = {}
        self.stop_event = asyncio.Event()

    def _log(self, record: dict) -> None:
        record["t"] = round(time.time() - self.t0, 3)
        if self.log_fh:
            self.log_fh.write(json.dumps(record) + "\n")
            self.log_fh.flush()

    async def _connect(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        print(f"connecting to {self.target.host}:{self.target.port} (TLS, no verify)")
        self.reader, self.writer = await asyncio.open_connection(
            self.target.host, self.target.port, ssl=ctx,
        )
        header = build_auth_header(self.target)
        self.writer.write(header)
        await self.writer.drain()
        print(f"  sent 122-byte auth header (serial={self.target.serial!r} client_id={self.target.client_id} conn={self.target.conn_id!r})")
        self._log({"event": "auth_sent", "header_hex": header.hex()})

    async def _recv_loop(self) -> None:
        assert self.reader is not None
        try:
            while not self.reader.at_eof():
                hdr = await self.reader.readexactly(9)
                msgtype = hdr[0]
                seq = int.from_bytes(hdr[1:5], "big")
                length = int.from_bytes(hdr[5:9], "big")
                payload = await self.reader.readexactly(length) if length > 0 else b""
                self.by_type[msgtype] = self.by_type.get(msgtype, 0) + 1

                if msgtype == MsgType.VIDEO:
                    self.video_count += 1
                    self.video_bytes += length
                    if self.video_count == 1:
                        sync_ok = bool(payload) and payload[0] == 0x47
                        self._log({"event": "first_video", "len": length, "mpegts_sync": sync_ok})
                else:
                    self.non_video_count += 1
                    name = _name_for(msgtype)
                    self._log({
                        "event": "rx",
                        "type_hex": f"0x{msgtype:02x}",
                        "type_name": name,
                        "seq": seq,
                        "len": length,
                        "hex": payload.hex(),
                    })
                    print(f"  RX  0x{msgtype:02x} {name:<18} seq={seq} len={length}")
                    if 0 < length <= 64:
                        print(f"      payload: {payload.hex()}")
        except asyncio.IncompleteReadError:
            print("  recv: server closed connection (EOF)")
            self._log({"event": "eof"})
        except ssl.SSLError as e:
            if e.reason != "APPLICATION_DATA_AFTER_CLOSE_NOTIFY":
                print(f"  recv: SSL error: {e}")
                self._log({"event": "ssl_error", "reason": str(e)})
        except Exception as e:
            print(f"  recv: error: {e}")
            self._log({"event": "recv_error", "error": repr(e)})
        finally:
            self.stop_event.set()

    async def _heartbeat_loop(self) -> None:
        assert self.writer is not None
        keepalive_seq = 0
        try:
            tick = 0
            while not self.stop_event.is_set() and not self.writer.is_closing():
                if tick % 10 == 0:
                    keepalive_seq += 1
                    ka = frame(MsgType.KEEPALIVE, keepalive_seq, b"")
                    self.writer.write(ka)
                    await self.writer.drain()
                    self._log({"event": "tx", "type_hex": "0x0a", "type_name": "KEEPALIVE", "seq": keepalive_seq})

                ls = frame(MsgType.LATENCY_STATS, 1000, LATENCY_STATS_PAYLOAD)
                self.writer.write(ls)
                await self.writer.drain()
                tick += 1
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=1.0)
                    return
                except asyncio.TimeoutError:
                    pass
        except Exception as e:
            print(f"  heartbeat: error: {e}")
            self._log({"event": "tx_error", "error": repr(e)})

    async def _timer(self) -> None:
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=self.duration_s)
        except asyncio.TimeoutError:
            print(f"  duration {self.duration_s}s elapsed — closing")
            self.stop_event.set()

    async def run(self) -> None:
        self.t0 = time.time()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_fh = self.log_path.open("w")
        try:
            self._log({"event": "session_start", "target": {
                "host": self.target.host, "port": self.target.port,
                "conn_id": self.target.conn_id, "serial": self.target.serial,
                "client_id": self.target.client_id,
            }, "duration_s": self.duration_s})
            await self._connect()
            tasks = [
                asyncio.create_task(self._recv_loop(), name="recv"),
                asyncio.create_task(self._heartbeat_loop(), name="hb"),
                asyncio.create_task(self._timer(), name="timer"),
            ]
            await self.stop_event.wait()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            if self.writer and not self.writer.is_closing():
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass
            summary = {
                "event": "session_end",
                "elapsed_s": round(time.time() - self.t0, 2),
                "video_packets": self.video_count,
                "video_bytes": self.video_bytes,
                "non_video_packets": self.non_video_count,
                "by_type": {f"0x{k:02x}": v for k, v in sorted(self.by_type.items())},
            }
            self._log(summary)
            if self.log_fh:
                self.log_fh.close()
            print()
            print("=== summary ===")
            print(f"  elapsed: {summary['elapsed_s']}s")
            print(f"  video packets: {summary['video_packets']} ({summary['video_bytes']} bytes)")
            print(f"  non-video packets: {summary['non_video_packets']}")
            print("  by type:")
            for k, v in sorted(self.by_type.items()):
                print(f"    0x{k:02x} {_name_for(k):<18} {v}")
            print()
            print(f"  full log: {self.log_path}")


def _name_for(msgtype: int) -> str:
    try:
        return MsgType(msgtype).name
    except ValueError:
        return f"UNKNOWN_0x{msgtype:02x}"


def _start_liveview(camera_id: int, network_id: int) -> tuple[str, int, dict]:
    """POST /liveview, return (immis_url, command_id, full_response)."""
    c = BlinkClient()
    path = f"/api/v2/accounts/{c.session.account_id}/networks/{network_id}/owls/{camera_id}/liveview"
    res = c.request("POST", path, body={"intent": "liveview"})
    if not res.body or "server" not in res.body:
        raise RuntimeError(f"liveview response missing 'server': {res.body!r}")
    return res.body["server"], res.body.get("command_id", 0), res.body


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="src.immis_client")
    sub = ap.add_subparsers(dest="cmd", required=True)

    obs = sub.add_parser("observe", help="connect to a live IMMIS server, log all non-video traffic")
    obs.add_argument("--camera-id", type=int, required=True, help="owl id (e.g. 1234567 for LivingRoom)")
    obs.add_argument("--network-id", type=int, default=12345)
    obs.add_argument("--duration", type=float, default=30.0, help="how long to hold the connection (s)")
    obs.add_argument("--token-source", choices=("null", "player_transaction", "liveview_token", "both"), default="null",
                     help="what to put in the 64-byte auth-header token slot")

    parse_url = sub.add_parser("parse-url", help="parse and dump an immis:// URL without connecting")
    parse_url.add_argument("url")

    args = ap.parse_args(argv)

    if args.cmd == "parse-url":
        t = ImmisTarget.from_url(args.url)
        print(json.dumps({
            "host": t.host, "port": t.port,
            "conn_id": t.conn_id, "serial": t.serial,
            "client_id": t.client_id,
        }, indent=2))
        return 0

    if args.cmd == "observe":
        print(f"requesting liveview: owl={args.camera_id} network={args.network_id}")
        url, command_id, body = _start_liveview(args.camera_id, args.network_id)
        print(f"  immis url: {url}")
        print(f"  command_id: {command_id}")
        player_tx = (body.get("player_transaction") or "").encode("utf-8")
        lv_token = (body.get("liveview_token") or "").encode("utf-8")
        if args.token_source == "null":
            auth_token = b""
        elif args.token_source == "player_transaction":
            auth_token = player_tx
        elif args.token_source == "liveview_token":
            auth_token = lv_token
        elif args.token_source == "both":
            auth_token = player_tx + b"\x00" + lv_token
        else:
            auth_token = b""
        print(f"  token-source: {args.token_source} ({len(auth_token)} bytes into 64-byte slot)")
        target = ImmisTarget.from_url(url, auth_token=auth_token)
        ts = time.strftime("%Y%m%d-%H%M%S")
        log_path = LOG_DIR / f"immis_observe-{args.camera_id}-{ts}.jsonl"
        obs = ImmisObserver(target, log_path, args.duration)
        try:
            asyncio.run(obs.run())
        except KeyboardInterrupt:
            print("interrupted")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
