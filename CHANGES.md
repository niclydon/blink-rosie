# CHANGES

Chronological per-phase log for `blink-rosie`. Each entry references the
full story in `docs/narrative/`. Newest entry on top.

---

## 2026-05-19 — Phase 1 + Phase 2: REST eliminated, server-push wire format decoded, command channel identified

Single-session arc from empty directory to fully decoded Rosie position
state. ~5.5 hours of work, 12 git commits, 12 live IMMIS sessions.

**Decisions made:**

- Reuse `~/.blink-mcp/session.json` as the auth boundary rather than
  re-doing OAuth in this repo. blink-mcp owns the Python bootstrap; this
  project consumes the token and refreshes via the same OAuth endpoint.
  Mirrors `blink-mcp/src/blink/client.ts:155-225`.
- Corrected the User-Agent guidance inherited from the original brief —
  REST traffic must NOT carry UA/APP-BUILD headers (triggers HTTP 426).
  The Blink-app UA is *only* used on the OAuth refresh path.
- Built our own async IMMIS client rather than vendoring one. Reference
  port target was `refs/blinkpy/blinkpy/livestream.py` with cross-checks
  against `refs/homebridge-blink-new/src/blink-api/immis-proxy.ts`. One
  divergence from blinkpy: use `StreamReader.readexactly()` for frame
  reassembly instead of `read(N)`, which warns-and-breaks on partial reads.

**What got proven (or ruled out):**

- **REST is conclusively dead for rosie movement.** ~85 distinct
  path/method probes across camera-scoped, owl-scoped, account-scoped, and
  legacy `/network/...` shapes. All returned the generic Phusion Passenger
  HTML 404. A verb-discriminator diagnostic confirmed this means "no Rails
  route matches" rather than "controller exists but rejected request" —
  contrast with `POST /state/nonsense` which returns structured JSON 400.
- **The IMMIS ACCESSORY_MESSAGE wire format is decoded.** The
  server-push 7-byte payload is `[counter? 3-byte-hash PAN TILT 0x00]`.
  Both axes are unsigned bytes increasing with leftward pan / upward tilt,
  symmetric around their mechanical centers:

| Axis | Center | Min byte | Max byte | Range | °/byte |
|---|---|---|---|---|---|
| Pan  | `0x5a` (90)  | `0x06` (right) | `0xae` (left) | 168 | ~2.08° |
| Tilt | `0xb4` (180) | `0x77` (down)  | `0xf1` (up)   | 122 | ~1.025° |

- **Three new IMMIS message types observed** that no public reference
  documents: `0x06` (auth ACK), `0x0c` (flag-shaped seq `0xA0000001`),
  `0x13` (26-byte session config with the timing constants
  `1388 03e8 03e8 0064`).
- **KEEPALIVE is bidirectional** with sequence echo (30-50ms RTT). Refs
  said client-only.
- **Per-msgtype sequence spaces** — each message type maintains its own
  independent seq counter; refs implicitly assumed connection-wide.
- **`0x17` SESSION_COMMAND is the client→server command channel.**
  Only msgtype that produces any server response. Empty 0x18 ACK fires
  within 37ms for every 0x17, regardless of cmd_id validity. `0x14`
  INLINE_COMMAND and `0x15` ACCESSORY_MESSAGE in client→server direction
  are silently ignored.

**What's still unknown:**

- Valid Rosie command IDs (audio cmd_ids 3 and 4 are documented; movement
  cmd_ids are not).
- Expected payload shape for movement (`cmd_id + pan + tilt`?
  `cmd_id + accessory_id + struct`?).
- Whether the empty 0x18 ACK is content-blind acknowledgment or
  "received-but-denied" with the same on-wire shape.

The empty ACK can't be used as a success signal. Brute-forcing
(cmd_id × payload-shape) without that signal is impractical (~100+ probes
each requiring eyes-on-mount).

**Commits:**

| SHA | Description |
|---|---|
| `62bca04` | Bootstrap project (CLAUDE.md, refs/, .gitignore, scaffolding) |
| `1a043e6` | Add session + REST client; correct CLAUDE.md auth headers |
| `38cd3ec` | Phase 1: rule out REST for rosie pan/tilt control |
| `91f30b7` | Phase 2.2: decode ACCESSORY_MESSAGE wire format (pan + tilt position bytes) |
| `173aaa6` | Phase 2.2: factory home capture invalidates earlier home assumption |
| `5794f65` | findings: correct "Default View" framing — it's user-set, not factory home |
| `864a272` | Phase 2.2: pan encoding anchored — full-right at 0x06, full-left at 0xae |
| `3b12d7b` | Phase 2.2: tilt encoding fully characterized — symmetric ~1°/byte around 0xb4 |
| `b4e170d` | Phase 2.2 COMPLETE: 0x5a 0xb4 is the Rosie's mechanical home |
| `71a785d` | Phase 2.3: 0x17 is the command channel; payload format still unknown |

**What's unblocked:**

- Future cold Claude sessions inherit the protocol surface via CLAUDE.md
  (no need to re-derive the auth header layout or the position byte
  encoding).
- Any future investigation of similar Blink accessories (Storm floodlight,
  Sync Module audio) can reuse `src/immis_client.py` as the connection
  layer.

**What's pending:**

- Phase 3 — find the movement cmd_id. Three paths:
  1. iOS Blink app class-dump / Hopper analysis of the `WalnutPlayer`
     framework (Option 3, next session).
  2. Android Frida MITM via `refs/blink-immis-proxy/` (Option 2, fallback
     if iOS dump hits obfuscation).
  3. Brute-force sweep of cmd_id × payload space (impractical without
     success signal).

**Full story:** `docs/narrative/2026-05-19-rosie-wire-format-decode.md`
