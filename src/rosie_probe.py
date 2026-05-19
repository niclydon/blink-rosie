"""
Phase 1: REST endpoint discovery for the Rosie pan/tilt accessory.

Discovery strategy: blink-mcp already proved /rosie, /rosies/{id}, and the
generic /accessories/* shapes return 404. We focus on camera-scoped paths
(the shape that works for Storm floodlights, documented in
refs/homebridge-blink-original/src/blink-api.js:67-68), trying both
/cameras/{id}/ and /owls/{id}/ segments since the Rosie is on a Mini (owl).

Phase 1a is GET-only — no movement risk. Status semantics:

  404 = path doesn't exist (most probes will land here)
  403 = path exists but unauthorized (interesting)
  405 = path exists, wrong verb (interesting — check Allow: header)
  400 = path exists, missing/bad query params (interesting)
  410 = path was a thing once, now gone (interesting)
  426 = our headers tripped the upgrade check (shouldn't happen — bug if so)
  429 = rate limited → ABORT THE RUN
  2xx = jackpot

Outputs a JSONL log per request to logs/rosie_probe-{ts}.jsonl plus a stdout
summary grouped by status. logs/ is gitignored — captures may contain account
IDs, serials, and IP addresses.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from src.api_client import BlinkClient
from src.session import BlinkAuthError

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
DEFAULT_DELAY_S = 0.8
DEFAULT_JITTER_S = 0.4


PATH_SUFFIXES = [
    "",
    "/status",
    "/info",
    "/state",
    "/config",
    "/command",
    "/move",
    "/position",
    "/ptz",
    "/pan",
    "/tilt",
    "/home",
    "/default_position",
    "/sweep",
    "/calibrate",
    "/calibration",
]

INTERESTING_STATUSES = {200, 201, 202, 204, 400, 403, 405, 409, 410, 422}


@dataclass
class ProbeResult:
    method: str
    path: str
    status: int
    body_excerpt: str
    allow_header: Optional[str]
    server_header: Optional[str]
    content_type: Optional[str]
    elapsed_ms: int


def candidate_paths(account_id: int, network_id: int, owl_id: int, rosie_id: int) -> list[str]:
    base_acct_net = f"/api/v1/accounts/{account_id}/networks/{network_id}"
    paths: list[str] = []

    for segment in ("cameras", "owls"):
        prefix = f"{base_acct_net}/{segment}/{owl_id}/accessories/rosie/{rosie_id}"
        for suffix in PATH_SUFFIXES:
            paths.append(prefix + suffix)

    paths.extend([
        f"{base_acct_net}/accessories/rosie/{rosie_id}",
        f"{base_acct_net}/accessories/rosie/{rosie_id}/status",
        f"{base_acct_net}/accessories/rosie/{rosie_id}/move",
        f"/api/v1/accounts/{account_id}/accessories/rosie/{rosie_id}",
        f"/api/v1/accessories/rosie/{rosie_id}",
        f"/network/{network_id}/owl/{owl_id}/accessories/rosie/{rosie_id}",
        f"/network/{network_id}/camera/{owl_id}/accessories/rosie/{rosie_id}",
    ])
    return paths


def probe_one(client: BlinkClient, method: str, path: str, body: Any = None) -> ProbeResult:
    t0 = time.perf_counter()
    res = client.request(method, path, body=body, raise_on_error=False)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    excerpt = (res.raw_text or "")[:200].replace("\n", " ")
    return ProbeResult(
        method=res.method,
        path=path,
        status=res.status,
        body_excerpt=excerpt,
        allow_header=res.headers.get("Allow") or res.headers.get("allow"),
        server_header=res.headers.get("Server") or res.headers.get("server"),
        content_type=res.headers.get("Content-Type") or res.headers.get("content-type"),
        elapsed_ms=elapsed_ms,
    )


def run(
    method: str,
    paths: Iterable[str],
    delay_s: float,
    jitter_s: float,
    log_path: Path,
    body: Any = None,
    abort_on_rate_limit: bool = True,
) -> list[ProbeResult]:
    client = BlinkClient()
    results: list[ProbeResult] = []
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as fh:
        for i, path in enumerate(paths):
            try:
                r = probe_one(client, method, path, body=body)
            except BlinkAuthError as e:
                print(f"AUTH ERROR after {i} probes: {e}", file=sys.stderr)
                break
            results.append(r)
            fh.write(json.dumps(asdict(r)) + "\n")
            fh.flush()
            marker = "*" if r.status in INTERESTING_STATUSES else " "
            print(f"  {marker} {r.method:5} {r.status:>3}  {r.path}  ({r.elapsed_ms}ms)")
            if r.allow_header:
                print(f"      Allow: {r.allow_header}")
            if r.status == 429:
                print("RATE LIMITED — aborting", file=sys.stderr)
                if abort_on_rate_limit:
                    break
            time.sleep(delay_s + random.uniform(0, jitter_s))
    return results


def summarize(results: list[ProbeResult]) -> None:
    by_status: dict[int, list[ProbeResult]] = defaultdict(list)
    for r in results:
        by_status[r.status].append(r)
    print()
    print("=== summary ===")
    for status in sorted(by_status):
        n = len(by_status[status])
        flag = " <-- INTERESTING" if status in INTERESTING_STATUSES else ""
        print(f"  {status}: {n}{flag}")
    print()
    interesting = [r for r in results if r.status in INTERESTING_STATUSES]
    if interesting:
        print("=== interesting responses ===")
        for r in interesting:
            print(f"  {r.method} {r.status} {r.path}")
            if r.allow_header:
                print(f"      Allow: {r.allow_header}")
            if r.body_excerpt:
                print(f"      body: {r.body_excerpt}")


def discover_targets() -> tuple[int, int, int, int]:
    client = BlinkClient()
    home = client.homescreen()
    networks = home.get("networks") or []
    if not networks:
        raise SystemExit("no networks on this account")
    network_id = networks[0]["id"]

    rosies = (home.get("accessories", {}) or {}).get("rosie") or []
    if not rosies:
        raise SystemExit("no rosie accessories on this account")
    rosie = rosies[0]
    rosie_id = rosie["id"]
    owl_id = rosie["target_id"]
    return client.session.account_id, network_id, owl_id, rosie_id


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="src.rosie_probe")
    ap.add_argument("--method", default="GET", choices=("GET", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"),
                    help="HTTP method to sweep (default: GET — safe)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY_S,
                    help=f"base delay between probes (default: {DEFAULT_DELAY_S}s)")
    ap.add_argument("--jitter", type=float, default=DEFAULT_JITTER_S,
                    help=f"extra random jitter (default: {DEFAULT_JITTER_S}s)")
    ap.add_argument("--dry-run", action="store_true", help="print candidate paths and exit")
    args = ap.parse_args(argv)

    acct, net, owl, rosie = discover_targets()
    paths = candidate_paths(acct, net, owl, rosie)
    print(f"target: account={acct} network={net} owl={owl} rosie={rosie}")
    print(f"candidates: {len(paths)} paths via {args.method}")

    if args.dry_run:
        for p in paths:
            print(f"  {args.method} {p}")
        return 0

    ts = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"rosie_probe-{args.method.lower()}-{ts}.jsonl"
    body: Any = {} if args.method in ("POST", "PUT", "PATCH") else None
    print(f"logging to: {log_path}")
    if body is not None:
        print(f"body: {json.dumps(body)}")
    print()
    results = run(args.method, paths, args.delay, args.jitter, log_path, body=body)
    summarize(results)
    print()
    print(f"full log: {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
