# blink-rosie

Reverse-engineering the Blink Rosie pan-tilt mount protocol — and **the first
publicly documented programmatic control** of one.

## What this is

The Blink Rosie is a motorized base that attaches to the Blink Mini Gen 1
camera. It pans ~350° horizontally and ~125° vertically. Blink ships no
official API for moving it; the mount is controllable only through the Blink
Home Monitor app during a live-view session. As of mid-2026 no community
project — homebridge plugins, Home Assistant integrations, Hubitat drivers,
or the various IMMIS MITM kits — had publicly figured out how to send
movement commands to it.

This repo is the investigation log of doing that in one evening
(2026-05-19): five phases of reverse engineering from REST endpoint probing
through static analysis of the Blink Android app's native library to
empirically verified physical mount motion.

**Headline result:** the camera physically moved on a programmatic command,
and the wire format is fully decoded.

## TL;DR — the protocol

Rosie movement rides on the Blink-proprietary **IMMIS streaming protocol**
(TLS over TCP, ~25 MB Android native lib at `lib/arm64-v8a/libwalnut.so`).
The full 9-byte IMMIS header carries the cmd_id in what is normally the
"sequence number" position:

```
[byte 0]      msgtype = 0x14 (INLINE_COMMAND)
[bytes 1-4]   command (uint32 BE)   ← cmd_id rides here
[bytes 5-8]   length  (uint32 BE)   ← payload size
[bytes 9+]    payload (variable)
```

The Rosie command IDs (extracted from the Blink Android app's Kotlin code
via `jadx`):

| cmd_id | Name | Payload |
|---|---|---|
| 3 | RosieMove | 7 bytes: `00 00 00 00 PAN_byte TILT_byte 00` |
| 4 | RosieStop | none |
| 5 | RosieGoHome | none |
| 6 | RosieSetHome | none |
| 7 | Rosie360 | none |

The PAN and TILT bytes are unsigned, symmetric around mechanical center:

| Axis | Mechanical center | Min | Max | °/byte |
|---|---|---|---|---|
| Pan  | `0x5a` (90)  | `0x06` (right, 6)   | `0xae` (left, 174) | ~2.08 |
| Tilt | `0xb4` (180) | `0x77` (down, 119)  | `0xf1` (up, 241)   | ~1.025 |

So an on-wire `RosieMove` packet that sends the mount to mechanical home
(pan=`0x5a`, tilt=`0xb4`) is exactly **16 bytes**:

```
14  00 00 00 03  00 00 00 07  00 00 00 00 5a b4 00
```

During motion the server streams ACCESSORY_MESSAGE (msgtype `0x15`) packets
back every ~140ms with the current position plus a motion-in-progress flag
in byte 6 (0x01 while moving, 0x00 when stationary).

Full byte-level analysis, the disassembly chain that got us here, and the
complete `LiveViewCommand` enum (which includes Storm floodlight + Sync
Module audio commands beyond Rosie) are in
[`docs/findings.md`](docs/findings.md).

## The story

The full investigation, in Netflix-documentary prose, is in
[`docs/narrative/2026-05-19-rosie-wire-format-decode.md`](docs/narrative/2026-05-19-rosie-wire-format-decode.md):
~700 lines, covering the REST elimination (85+ probes), the bidirectional
KEEPALIVE finding (community refs all said client-only), the wire-format
decode by panning the real mount and diffing captures, three previously
undocumented IMMIS message types (0x06, 0x0c, 0x13, plus the now-decoded
0x08 = STOP), `libwalnut.so` static analysis via `radare2`, and the final
empirical verification when the mount physically moved on the first
correctly-framed `RosieMove` packet.

`CLAUDE.md` is the protocol reference — auth header layout, message types,
wire formats, byte-to-degree mappings.

## What's in `src/`

A working Python implementation that authenticates against Blink, opens a
live-view session, holds the IMMIS connection, and sends rosie commands.
This is *exploratory* code — clear, single-file, no abstractions. The
production version lives in [`blink-mcp`](#related-project).

```
src/
├── session.py         # Loads ~/.blink-mcp/session.json; OAuth refresh
├── api_client.py      # Blink REST client (BlinkClient)
├── rosie_probe.py     # Phase 1: REST endpoint sweep (proves REST doesn't carry rosie commands)
└── immis_client.py    # Phase 2-4: async TLS IMMIS client; observe + send experiment + send-rosie modes
```

### Try it yourself

You'll need an existing Blink session file at `~/.blink-mcp/session.json`
in the format produced by [blink-mcp's auth bootstrap](https://github.com/niclydon/blink-mcp).
(`blinkpy` will produce a compatible session file if you don't want to use
blink-mcp; the required fields are
`access_token`, `refresh_token`, `tier`, `account_id`, `client_id`,
`unique_id`, `expiration_date`.)

```bash
# Observe a live-view session: connect, log all non-VIDEO packets, disconnect after N seconds.
python3 -m src.immis_client observe --camera-id <owl_id> --duration 30

# Confirm a rosie is attached to a camera.
python3 -m src.api_client rosies

# Send the mount to its mechanical center (pan=0x5a, tilt=0xb4).
python3 -m src.immis_client send-rosie --camera-id <owl_id> --rosie-cmd move --pan 0x5a --tilt 0xb4

# Send to the user-saved Default View.
python3 -m src.immis_client send-rosie --camera-id <owl_id> --rosie-cmd home

# Auto pan-overview sweep.
python3 -m src.immis_client send-rosie --camera-id <owl_id> --rosie-cmd rosie360
```

## Related project

[**blink-mcp**](https://github.com/niclydon/blink-mcp) ships the productionized
version as Model Context Protocol tools: `blink_rosie_status`, `blink_rosie_move`,
`blink_rosie_home`, `blink_rosie_set_home`, `blink_rosie_stop`, `blink_rosie_sweep_360`.
The protocol work in this repo is what enabled those tools.

## References

The reverse engineering stood on the shoulders of these community projects;
the IMMIS framing was already documented even if the rosie command was not:

- [`fronzbot/blinkpy`](https://github.com/fronzbot/blinkpy) — cleanest Python IMMIS implementation
- [`sealad886/homebridge-blink-cameras-new-api`](https://github.com/sealad886/homebridge-blink-cameras-new-api) — most complete TypeScript IMMIS impl, full message-type enum
- [`MattTW/BlinkMonitorProtocol`](https://github.com/MattTW/BlinkMonitorProtocol) — protocol docs
- [`jakecrowley/blink-immis-proxy`](https://github.com/jakecrowley/blink-immis-proxy) — Frida + socat MITM kit
- [`amattu2/blink-liveview-middleware`](https://github.com/amattu2/blink-liveview-middleware) — Go IMMIS proxy with explicit "PTZ TODO"

The decisive step was static analysis of `libwalnut.so` from the Blink
Android app — the unstripped binary with debug info exposed function names
that pointed directly at the protocol layer. `jadx` decompilation of
`classes.dex` then surfaced the entire `LiveViewCommand` Kotlin enum in
`com.immediasemi.blink.utils.liveview` with every cmd_id inline.

## Notes / caveats

- This is reverse-engineering of an undocumented protocol. Blink can change
  anything at any time. The wire format here is verified against the
  Android app version `54.1` and `55.1` released in early 2026.
- Don't hammer Blink with repeated liveview opens. Reasonable rate limit:
  one liveview per camera per 30s while iterating; longer pauses for
  extended work. After a series of failed sessions the camera-side relay
  may enter a 5–15 minute "recovery window" where setup bursts don't
  complete — wait it out rather than retrying immediately.
- Liveview sessions consume battery on battery-powered Blink cameras.
  Mini Gen 1 (which the Rosie attaches to) is wall-powered, so this isn't
  a concern there, but be considerate of any battery-powered cameras on
  the same account.
- This work is for **interoperability with hardware you own**. Don't use
  it to control devices you don't have authorization to control.

## Acknowledgments

The reverse engineering session that produced this repo was driven jointly
with Claude Code (Anthropic). The investigation logs in `docs/findings.md`
and the narrative in `docs/narrative/` are the durable record of the
collaboration.

## License

MIT.
