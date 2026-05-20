# Findings — Blink Rosie Pan/Tilt Reverse Engineering

Running log of what we discover, what we ruled out, and what we still need to test.
Newest at the top. Cite source files / packet captures where applicable.

---

## 2026-05-19 — Project bootstrap

- Scaffolded blink-rosie project on Furnace.
- CLAUDE.md captures full prior-art summary, IMMIS packet format, and phased plan.
- blink-mcp confirmed available on the network for authenticated REST access.
- Reference repos cloned into `refs/` (not vendored — see `.gitignore`).

## 2026-05-19 — Phase 4 continued: 4 send-format attempts, identified 0x08 as STOP

After the first two silent send attempts (5-byte and 4-byte body formats),
disassembled the `processMessage` dispatcher to disambiguate the body
layout. The comparisons in the dispatch table:

```
cmp w21, 0x06   cmp w21, 0x0a   cmp w21, 0x0c
cmp w21, 0x12   cmp w21, 0x13   cmp w21, 0x15
cmp w21, 0x18   cmp w21, 0x08   ...
```

**Every comparison value matches an IMMIS msgtype we've observed** (0x06,
0x0a, 0x0c, 0x12, 0x13, 0x15, 0x18). That definitively proves the byte at
`this[0x310]` is the outer IMMIS msgtype set by the framing parser — NOT
a separate inner byte in the body. So the 4-byte body format (no inner
type prefix) was the correctly-framed one.

### Two more wire-format attempts

| Attempt | Body | Outer msgtype | Server response |
|---|---|---|---|
| 3: cmd + payload_size | `00000005 00000000` (8 bytes) for RosieGoHome | 0x14 | None visible — still silent |
| 4: RosieMove home (v2 format, 11-byte body) | `00000003 00000000 5a b4 00` | 0x14 | **SERVER SENT 0x08 STOP** at t+15s, then closed connection at t+15.8s |

The session for attempt 4 was already abnormal — video never started (no
first_video event, no ACCESSORY_MESSAGE seq=2 position snapshot). Setup
burst stopped at 0x13. After our 0x14 send fired (because the wait-for-
first-video timer expired), the server sent a 0x08 message ~15s later and
closed the connection 0.8s after that.

### What 0x08 means

`walnut::IMMIStreamSource::sendStop(unsigned int)` exists at virtual address
`0x16f8e4` (128 bytes) — the client-side function to send a stop. Strings
in the binary confirm:

- `"StreamSource is stopped - %s"`
- `"StreamSource has unexpectedly stopped. Stopping the player."`

And the dispatcher branch is `cmp w21, 8; b.eq 0x16fc5c` — msgtype `0x08`
routes to a stop-handling branch.

**Conclusion: msgtype `0x08` is STOP, sent by either direction to signal
session teardown.** This is the first time we've seen the server emit 0x08
in any session.

### What this leaves unresolved

Whether 0x08 was a direct response to our 0x14 send (server detected
protocol violation → STOP) or an independent decision to tear down an
already-malformed session (no video had started). The 15-second gap
between our send and the 0x08 is unusual — too long to be a synchronous
NACK, but well-correlated enough to be suspicious.

Either way: **4 distinct body formats have been tried for InlineLVCommand
send. None have produced mount motion.** Static analysis has gone as deep
as it can without disassembling the queue-consumer in `sendMediaInfo` that
actually emits bytes to the TLS socket — and even that may not resolve the
question if the issue is auth/permission/session-state rather than bytes.

### What's left to try (whenever Phase 4 is resumed)

1. **Frida MITM on an Android emulator** — install the Blink APK on Bliss
   OS or Android Studio AVD with Frida, hook
   `Java_com_immediasemi_walnut_Player_submitInlineLVCommand`, pan the
   mount via the real app, dump the exact bytes that hit the TLS socket.
   Definitive resolution.
2. **Disassemble the queue-consumer** downstream of `sendMediaInfo`. The
   queue is keyed by msgtype at `this+0x430` (and 0x438, 0x440). Find the
   function that reads from those addresses and writes to the socket.
3. **Investigate the multi-client live view (MCLV) state machine.** The
   `is_mclv: true` field in `/liveview` responses suggests an MCLV protocol
   that may require explicit controller-role assertion before commands
   are accepted. Look for "controller" / "primary" / "join" string
   constants in libwalnut.

The night's static analysis produced an exceptionally thorough decode of
the Blink IMMIS protocol — wire formats for the read direction, message
type table including four previously-undocumented types (0x06, 0x08, 0x0c,
0x13), full command-id enumeration from Kotlin classes.dex, the
ROSIE_LIMITS interpretation, and the `walnut::*` C++ symbol map. The
final mile to making the mount physically move requires capturing one real
client→server pan/tilt packet from a running Blink app, which static
analysis alone cannot deliver.

Logs:
- `logs/immis_rosie-home-1234567-20260519-194811.jsonl` — attempt 1 (5B body)
- `logs/immis_rosie-home-1234567-20260519-195217.jsonl` — attempt 2 (4B body)
- `logs/immis_rosie-home-1234567-20260519-200318.jsonl` — attempt 3 (8B body)
- `logs/immis_rosie-move-1234567-20260519-201327.jsonl` — attempt 4 (RosieMove + 0x08 STOP)

## 2026-05-19 — Phase 4 (first send attempts): silent failures, send path needs more analysis

Built `send-rosie` mode in `immis_client.py` — wraps high-level commands
(`move`, `stop`, `home`, `set-home`, `rosie360`) into the InlineLVCommand
on-wire format. Fixed an early argparse bug (subparsers `dest="cmd"`
collided with a new `--cmd` argument in `send-rosie`; renamed to `--rosie-cmd`).

**Two live attempts at `RosieGoHome`, both with the mount silently still:**

| Attempt | Wire body sent (after 9-byte IMMIS header) | Result |
|---|---|---|
| 1 | `14 00 00 00 05` (5 bytes: inner type + cmd_id BE) | Server returned the usual position-update ACCESSORY_MESSAGE 196ms later but the position bytes were unchanged (`5a 77`). Mount didn't move. |
| 2 | `00 00 00 05` (4 bytes: just cmd_id BE, no inner type) | Same — position-update arrived shortly after our TX but bytes unchanged. Mount didn't move. |

**Why both interpretations are plausible from static analysis:**

The receive-side disassembly (`processInlineLVCommandPayload`) reads:
- type byte from `this[0x310]`
- command (uint32 BE) from `this[0x311]`
- payload from `this[0x315]+`

These are offsets in the IMMIStreamSource instance, not bytes on the wire.
Could be either:
- The framing layer copies outer msgtype to 0x310, then body bytes 0..3
  as command, body bytes 4+ as payload → wire body is `[command 4B BE][payload]`
- Or it copies body byte 0 as type, body bytes 1..4 as command, body 5+ as
  payload → wire body is `[type 1B][command 4B BE][payload]`

Without disassembling the IMMIS framing parser fully (specifically the
function that fills offsets 0x310, 0x311, 0x315 of `this`), I can't
distinguish. Both empirical tests failed identically.

### What disassembling the send-side revealed

The wire-write is NOT a single function. The call chain is:

1. `Java_com_immediasemi_walnut_Player_submitInlineLVCommand` (JNI)
2. `walnut::PlayerImplementation::submitInlineLVCommand` (forwards args)
3. `walnut::IMMIStreamSource::submitInlineLVCommand` (validates type, tail-calls)
4. `walnut::IMMIStreamSource::sendMediaInfo` — found at virtual address
   `0x170b38`, **632 bytes**, same `(uint8_t, uint32_t, vector<uint8_t>)`
   signature

`sendMediaInfo` early-on does:

```asm
0x170b54   ldr  w9, [x3, 8]       ; vector::end_
0x170b58   ldr  w10, [x3]          ; vector::begin_
0x170b6c   sub  w9, w9, w10        ; payload size = end - begin
0x170b68   and  w24, w1, 0xff      ; save type (low byte)
0x170b70   rev  w23, w2            ; BYTESWAP command (host → BE)
0x170b74   rev  w22, w9            ; BYTESWAP payload size (host → BE)
```

Then it does tree-map manipulation (`__tree:1683` source comments) and
calls `operator new`. **This is queue insertion, not socket write.** The
function builds a "media info entry" with `[type, command_BE, payload_size_BE,
payload]` and adds it to a per-stream map keyed by type. Some other thread
or function later reads from that map and constructs the actual wire bytes.

This means the wire format may include the byteswapped payload_size as a
separate field — something my earlier "type + command + payload" hypothesis
missed. A third candidate format:

```
[outer msgtype = type]                          ; in IMMIS header
[seq 4B BE]
[length 4B BE]
[command 4B BE]
[payload_size 4B BE]     ← NEW: separate length field for payload
[payload bytes]
```

That hasn't been tested yet — would be a logical next experiment when
resuming Phase 4.

### Why this is the right place to pause

Phase 3 produced a near-complete protocol decode in a single evening: the
ACCESSORY_MESSAGE wire format, the command channel (0x14), the cmd_id
enumeration, the receive-side body layout, even the bonus interpretation
of the 4-byte `06 ae 77 f1` packet as ROSIE_LIMITS. The remaining work to
move the mount is "find the exact byte-by-byte send framing" — a smaller
problem that needs another hour of disassembly tracing through
`sendMediaInfo` and its writer thread to identify exactly what bytes the
queue's consumer emits to the socket.

Alternative paths that would also close out Phase 4:

1. **Disassemble the queue-consumer/writer function** that actually emits
   bytes to the TLS socket. That's downstream of `sendMediaInfo` — probably
   reads the map-of-pending-media-info entries and assembles packets.
2. **Frida hook the running app**. Once Phase 4-blocking gets re-engaged,
   we could attach Frida to the Blink Android app on the user's phone (NOT
   the user's iPhone, just any rooted/emulator Android with the APK) and
   hook `Java_com_immediasemi_walnut_Player_submitInlineLVCommand`, then
   pan the mount via the app and dump the exact bytes the JNI passes
   downstream. Gives ground truth in one capture.
3. **Try the 8-byte `cmd + payload_size` format** as the next empirical
   probe.

Logs from tonight's attempts:
- `logs/immis_rosie-home-1234567-20260519-194811.jsonl` (attempt 1, 5-byte body)
- `logs/immis_rosie-home-1234567-20260519-195217.jsonl` (attempt 2, 4-byte body)

## 2026-05-19 — Phase 3 COMPLETE: full cmd_id table + payload formats from classes.dex

After the wire format was extracted from `libwalnut.so`, installed `jadx`
1.5.5 (needed `default-jre-headless`) and decompiled `base.apk` (~366 MB
of Java sources from 27,371 classes). One `grep` against
`submitInlineLVCommand` and the entire protocol was visible.

**Call site** at
`com/immediasemi/blink/video/live/sessionmanager/walnut/BlinkWalnutLiveViewSessionManager.java:455`:

```java
player.submitInlineLVCommand(command.getCommandTypeId(), command.getCommandId(), payload);
```

The `command` arg is a `LiveViewCommand` instance. That class is a sealed
Kotlin hierarchy at
`com/immediasemi/blink/utils/liveview/LiveViewCommand.java`. Two
subclasses — `InlineCommand(type=INLINE_COMMAND=0x14)` and
`SessionCommand(type=SESSION_COMMAND=0x17)` — and each concrete command
calls `super(<cmd_id>)` to set the integer cmd_id.

**Complete LiveViewCommand enum (type, cmd_id, name):**

| type | cmd_id | Name | Payload format |
|---|---|---|---|
| **0x14** | **1** | LightsOn (Storm floodlight) | _unknown_ |
| **0x14** | **2** | LightsOff | _unknown_ |
| **0x14** | **3** | **RosieMove** | **`00 00 00 00 PAN TILT 00`** (7 bytes) |
| **0x14** | **4** | **RosieStop** | empty |
| **0x14** | **5** | **RosieGoHome** | empty |
| **0x14** | **6** | **RosieSetHome** | empty |
| **0x14** | **7** | **Rosie360** (full pan overview) | empty |
| 0x14 | 8 | SirenOn | _unknown_ |
| 0x14 | 9 | SirenOff | _unknown_ |
| 0x17 | 1 | SaveClip | _unknown_ |
| 0x17 | 2 | DiscardClip | _unknown_ |
| 0x17 | 3 | StartAudio | empty (matches sealad886) |
| 0x17 | 4 | StopAudio | empty (matches sealad886) |
| 0x17 | 5 | ToggleExtended | _unknown_ |

**RosieMove payload format** at
`WalnutRosieNavigator.java:moveTo()`:

```java
@Override
public void moveTo(int panAngle, int tiltAngle) {
    this.commandSubmitter.submitCommand(
        LiveViewCommand.RosieMove.INSTANCE,
        new byte[]{0, 0, 0, 0, (byte) panAngle, (byte) tiltAngle, 0}
    );
}
```

So the on-wire `RosieMove` packet, panning to home and tilting to center,
looks like:

```
14  XX XX XX XX  00 00 00 0c   14  00 00 00 03   00 00 00 00 5a b4 00
└──── msgtype                ─┘└── inner type ─┘└─ cmd_id=3 ─┘└── 7-byte payload ──┘
                              length=12=0x0c                    pan=0x5a tilt=0xb4
```

**Receive-side parser** (also in `WalnutRosieNavigator.java`) **confirms
our Phase 2 wire-format decode byte-for-byte**:

```java
private final RosieNavigator.Position payloadToRosiePosition(byte[] payload, boolean isHomePosition) {
    return new RosieNavigator.Position(isHomePosition,
        UByte.m14243constructorimpl(payload[4]) & 255,  // ← PAN at byte 4
        UByte.m14243constructorimpl(payload[5]) & 255,  // ← TILT at byte 5
        payload[6]);                                     // byte 6
}
```

The same 7-byte format is used in both directions:

- **Client → server** (RosieMove): `00 00 00 00 PAN TILT 00`. Bytes 0-3
  are always zero on send.
- **Server → client** (POSITION update via ACCESSORY_MESSAGE 0x15):
  `<state-counter> <3-byte-hash> PAN TILT <flag>`. Bytes 0-3 carry
  state-version metadata; bytes 4-5 are the position; byte 6 may indicate
  isHome (we always saw 0x00 in captures, presumably meaning "not at
  home").

**Receive-side accessory message types** (from `handleAccessoryMessage`):

| `LiveViewAccessoryMessage.<NAME>` | What it carries |
|---|---|
| `POSITION` | 7-byte position snapshot (we observed this in every session at seq=2) |
| `HOME_POSITION` | 7-byte snapshot but flagged as the home position |
| `ROSIE_LIMITS` | 4-byte payload: `[pan_min, pan_max, tilt_min, tilt_max]` |
| `ROSIE_PAN_360_COMPLETE` | Empty — signals Rosie360 sweep finished |

**The 4-byte `06ae77f1` ACCESSORY_MESSAGE (seq=4) we observed in every
session is almost certainly `ROSIE_LIMITS`** — the structure matches
exactly: `06 ae 77 f1` = `pan_min=0x06, pan_max=0xae, tilt_min=0x77,
tilt_max=0xf1`. Those are the exact mechanical limit values we
triangulated by panning/tilting the camera. **The server was telling us
the limits the entire time — we just didn't know that's what the bytes
meant.** Confirmation of our pan/tilt range bounds without needing
physical experimentation, but we got there independently first.

### Phase 3 wrap

Every protocol detail we need for programmatic Rosie control is now in
hand:

- Outer IMMIS msgtype: `0x14` (INLINE_COMMAND)
- Inner type byte: `0x14`
- cmd_id: 3 for move, 4 for stop, 5 for goHome, 6 for setHome, 7 for 360
- Payload: 7 bytes `00 00 00 00 PAN TILT 00` for move; empty for the rest
- Pan range: `0x06` (right) to `0xae` (left), center `0x5a`
- Tilt range: `0x77` (down) to `0xf1` (up), center `0xb4`

Next step: build the send path in `immis_client.py` (`--send-rosie-cmd`
mode) and try `RosieGoHome` first as the lowest-risk test of the format
(empty payload, sends mount to user's saved home position — known
movement, predictable target).

## 2026-05-19 — Phase 3 (libwalnut.so analysis): wire format decoded from disassembly

Pivoted from iOS class-dump (user has no IPA, no jailbroken phone) to
Android APK static analysis on Furnace.

**APK source:** Blink 55.1 (`com.immediasemi.android.blink_55.1-29635039`)
pulled from APKMirror via the user's MacBook (also kept 54.1 alongside for
potential diff). Unpacked the `.apkm` bundle and extracted
`lib/arm64-v8a/libwalnut.so` (~25 MB, ELF aarch64).

**The binary is unstripped with debug info.** GNU build ID
`ef4234b958fe83bb`. 3260 exported symbols, 11776 total. JNI exports are
under `Java_com_immediasemi_walnut_*` (the Android name for what the iOS
brief called the "WalnutPlayer" framework).

**Source paths leaked via debug info:**
```
/walnut/android/externals/MbedTLS/third-party-src/library/...
/walnut/android/src/.../IMMIStreamSource.cc:399  ← submitInlineLVCommand
/walnut/android/src/.../IMMIStreamSource.cc:510  ← processInlineLVCommandPayload
```

**Critical log-string finds (from `strings -n 6`):**

| String | Tells us |
|---|---|
| `"Attempted to send inline LV command of incorrect type: type = %d"` | The `type` arg is whitelisted; wrong values silently fail with this log |
| `"submitInlineLVCommand called before StreamSource has been initialized"` | StreamSource must be initialized before commands accepted |
| `"Inline LV command received while not in a Streaming state"` | Bidirectional — server sends 0x14 too, but only during streaming |
| `"Received inline LV command from stream - command = '%zu', payload size = %u"` | Receive log shows the format: `command` is a size_t, payload has its own size |
| `"IMMI_DATA_FLAG_INLINE_LV_CMD"` | The data-flag name, confirms 0x14 = InlineLVCommand |

**No "rosie", "accessory", "pan", or "tilt" strings appear in
`libwalnut.so`.** The Rosie pan-tilt is NOT a named abstraction in the
walnut protocol library — it's just a specific (type, command) tuple in
the generic InlineLVCommand framework.

**Function signature (demangled from C++ mangled symbol):**

```cpp
walnut::IMMIStreamSource::submitInlineLVCommand(
    unsigned char type,
    unsigned int  command,
    const std::vector<unsigned char>& payload
)
```

### Send-side: type validation

Disassembled `walnut::IMMIStreamSource::submitInlineLVCommand` at virtual
address `0x17084c` (size 412 bytes). The prologue does:

```asm
; load state byte from `this`
0x17085c   ldr  w8, [x0, 0xc7]
0x170860   and  w8, w8, 0xfffffffe   ; mask low bit
0x170864   cmp  w8, 4                 ; state == initialized?
0x170868   b.ne 0x170890              ; → "called before initialized" log

; validate `type` arg
0x17086c   and  w8, w1, 0xff          ; w1 = type
0x170870   cmp  w8, 0x14              ; type == INLINE_COMMAND?
0x170874   b.eq 0x170880              ; yes → continue
0x170878   cmp  w8, 0x17              ; type == SESSION_COMMAND?
0x17087c   b.ne 0x170904              ; no → "incorrect type" log

; success path: tail-call to wire-write
0x170880-88   (restore regs)
0x17088c   b   0x1d2380               ; PLT trampoline to wire-send fn
```

**Only `type == 0x14` (INLINE_COMMAND) or `type == 0x17` (SESSION_COMMAND)
are accepted as the first argument.** Other values silently fail with the
"incorrect type" log message. This explains why our 0x14 and 0x17 send
experiments earlier produced varying server reactions — but neither
properly framed the body.

### Receive-side: body layout

Disassembled `processInlineLVCommandPayload()` at `0x170ae4`. The packet
body is parsed as:

```asm
0x170afc   add  x9, x8, 0x311           ; ptr to offset 0x311 in `this`
0x170b00   ldrb w10, [x8, 0x310]        ; load type byte (offset 0x310)
0x170b08   ldr  w9, [x9]                 ; load uint32 at offset 0x311
0x170b1c   add  x3, x8, 0x315            ; payload starts at offset 0x315
0x170b20   rev  w9, w9                   ; **big-endian byte-swap the command!**
0x170b28   blr  x10                      ; invoke callback(type, command, payload)
```

**This nails down the on-wire body layout of every 0x14/0x17 packet:**

```
9-byte IMMIS header:
  [byte 0]      msgtype: 0x14 (INLINE_COMMAND) or 0x17 (SESSION_COMMAND)
  [bytes 1-4]   seq (uint32, big-endian)
  [bytes 5-8]   length (uint32, big-endian) — counts bytes from this point

Packet body (length bytes):
  [byte 0]      type      — 0x14 or 0x17, matches outer msgtype
  [bytes 1-4]   command   — uint32 BIG-ENDIAN (CONFIRMED by `rev w9, w9`)
  [bytes 5...]  payload   — variable-length payload bytes
```

So a proper INLINE_COMMAND that calls `submitInlineLVCommand(type=0x14, command=N, payload=[...])` produces on the wire:

```
14  <seq:4 BE>  <length:4 BE>  14  <N:4 BE>  <payload bytes>
```

Total IMMIS packet size = 9 + 5 + payload.size() bytes.

### Why our earlier Phase 2.3 probes silently failed

| Probe | Outer msgtype | Body bytes | Body parsed as |
|---|---|---|---|
| A: empty | 0x14 | (none) | length=0, but parser expects ≥5; underrun → silent discard |
| B: `00000000 70 77 00` | 0x14 | 7 bytes | type=0x00 ← invalid (≠0x14/0x17) → "incorrect type" log |
| C: `01 5a b4` | 0x14 | 3 bytes | type=0x01 invalid + underrun for command |
| D: `05 5a b4` | 0x17 | 3 bytes | type=0x05 invalid + underrun for command |
| E: `00000000 70 b4 00` | 0x15 | 7 bytes | wrong outer msgtype — 0x15 isn't routed to this handler at all |
| F: `ff` | 0x17 | 1 byte | type=0xff invalid + underrun |

The "empty 0x18 ACK within 37ms" we saw for probes D and F is therefore
**not a content-level ACK from the InlineLVCommand layer** — it's
something else in the IMMIS framing layer (possibly a connection-level
keepalive nudge triggered by any received 0x17 packet, before the body
parser even runs).

### What's still needed

The wire format is fully known. What remains unknown is the **valid
`command` (uint32) values for Rosie movement**. The walnut.so binary
itself contains no string constants like "rosie_pan" or "tilt_set" — the
cmd_id integers come from the Kotlin/Java app layer, which lives in
`base.apk`'s `classes.dex` and would need `jadx` or `apktool` to decompile.

Two next-step options:

1. **Decompile `classes.dex`** with `jadx` (no Java needed for jadx-cli;
   ~80MB download). Find call sites of `Player.submitInlineLVCommand(...)`
   in the Kotlin code. Those calls pass concrete `type` and `command`
   values — the rosie/pan-tilt ones will be in business-logic classes
   adjacent to live-view UI code.
2. **Brute-force `command` with the correct body shape now**. Since we
   know the wire format, we can iterate cmd_ids 0..0x40 with body=`[type,
   cmd_BE_uint32, pan, tilt]` and watch for movement or for the
   server-pushed ACCESSORY_MESSAGE position update. Each probe is well-
   formed instead of silently discarded.

Recommended: try a small handful of likely cmd_ids first with the correct
body shape (4-5 probes), then if no movement, pivot to jadx for definitive
identification.

## 2026-05-19 — Phase 2.3: identified the command channel (0x17), but format still unknown

Added a `send` subcommand to `immis_client.py` (opens session, waits for
setup burst, sends one configured packet, holds connection to observe
reactions). Used it to probe three candidate client→server message types.

**Probe results:**

| Probe | TX | TX payload | Server reaction | Camera moved? |
|---|---|---|---|---|
| A | 0x14 INLINE_COMMAND | (empty) | none | no |
| B | 0x14 INLINE_COMMAND | `00000000 70 77 00` (7-byte echo of server format, target pan 0x70) | none | no |
| C | 0x14 INLINE_COMMAND | `01 5a b4` (cmd-id-prefix style) | none | no |
| D | 0x17 SESSION_COMMAND | `05 5a b4` (cmd_id=5, pan, tilt) | **empty 0x18 SESSION_MESSAGE @ t+37ms** | no |
| E | 0x15 ACCESSORY_MESSAGE | `00000000 70 b4 00` (7-byte echo with target) | none | no |
| F | 0x17 SESSION_COMMAND | `ff` (invalid cmd_id only) | **empty 0x18 SESSION_MESSAGE @ t+~30ms** | no |

**Key findings:**

1. **0x17 SESSION_COMMAND is the command channel.** Only message type that
   produces any server reaction. 37ms response time matches network RTT —
   the server is reading and processing our 0x17 packets immediately.
2. **0x14 INLINE_COMMAND (sent direction) is dead silent.** Despite Blink
   app's `IMMI_DATA_FLAG_INLINE_LV_CMD` (sent counter) hint suggesting
   otherwise, our 0x14 sends produce zero server reaction. Either the
   message type was renamed/deprecated, or we're missing something the
   app populates that gates 0x14 processing.
3. **0x15 ACCESSORY_MESSAGE in client→server direction is also ignored.**
   Despite being marked "bidirectional" in community refs, our 0x15 sends
   get no response. The server-push direction works; client→server seems
   to be inert.
4. **The empty 0x18 ACK is universal, not content-dependent.** Sending
   cmd_id=`0xff` (clearly bogus) produced the same empty ACK as cmd_id=
   `0x05`. The server ACKs every 0x17 it receives at the protocol layer,
   then silently discards unrecognized cmd_ids/payloads. So **we can't use
   ACK content to determine if a command was understood** — only physical
   movement or a follow-up ACCESSORY_MESSAGE will tell us.

**What we can't determine via local experimentation:**

- The valid Rosie cmd_id values (audio cmd_ids 3, 4 are known; movement
  cmd_id is unknown — could be 5, 6, 7, 8, 0x10, anything)
- The expected payload format (just `cmd_id`? `cmd_id + pan + tilt`?
  `cmd_id + 7-byte ACCESSORY_MESSAGE shape`? `cmd_id + accessory_id + …`?)
- Whether there are additional auth/permission requirements that gate
  command execution

**Why brute-force is impractical:** without command-success signal, we'd
need to test every (cmd_id × payload-shape) combination AND watch the
camera physically for each one. Even narrowing cmd_ids to 0x00-0x1f and 3
payload shapes = ~96 probes, each ~20s, each requiring eyes-on-mount.

**Next step: Phase 3 — Android MITM.** Captures one real pan/tilt command
from the actual Blink app. Setup is documented in
`refs/blink-immis-proxy/proxy.py` (mitmproxy + socat) and
`refs/blink-immis-proxy/inject-tls-verify-hook.py` (Frida hook to bypass
libwalnut TLS cert pinning). Needs a rooted Android device or Bliss OS in
QEMU. Multi-hour setup, but yields ground truth in one capture.

## 2026-05-19 — Phase 2.2 BREAKTHROUGH: wire-format candidate for Rosie position state

**Built `src/immis_client.py`** — async TLS client that connects to a live
IMMIS server, sends the 122-byte auth header, runs the latency_stats (1s) +
keepalive (10s) heartbeat cadence, and logs every non-VIDEO frame with full
hex dumps. Auth header construction validated byte-by-byte against
CLAUDE.md's spec (all 9 offset checks pass).

**Three live sessions captured** against LivingRoom (owl 1234567, rosie
54321). Camera was at home position for sessions 1 & 2, then user panned the
mount **fully to the left** via the Blink app before session 3.

### Three undocumented message types observed

Community references (CLAUDE.md, sealad886's enum, blinkpy) only documented
0x00, 0x0a, 0x12, 0x14, 0x15, 0x17, 0x18. We additionally observed:

| Type | Length | Sequence field | Notes |
|---|---|---|---|
| `0x06` | 0 | 0 | First packet from server post-auth (~0.5s after we send the auth header). **Almost certainly the auth ACK.** |
| `0x0c` | 0 | `0xA0000001` (= 2684354561) | Identical across all 3 sessions. The sequence field looks like a packed bitmask (top bit + bottom bit set), not a counter — high bits probably encode a state flag. |
| `0x13` | 26 | 0 | Structured payload: `00000000 0000000000 00 1388 03e8 03e8 0064 0000000000000000`. Numeric fields: 0x1388=5000, 0x03e8=1000 (x2), 0x0064=100. Looks like a **session-config block** with timing parameters (5000ms, 1000ms, 1000ms, 100ms). Identical across all 3 sessions. |

### Setup-burst pattern (every session, t < 1.6s)

Captured timeline against wall clock from session 1:

```
t=0.079s → client: 122-byte auth header
t=0.538s ← server: 0x06 (auth ACK, len=0)
t=0.674s ← server: KEEPALIVE seq=1 (echoes our seq=1 keepalive)
t=1.405s ← server: SESSION_MESSAGE seq=1 len=0
t=1.407s ← server: SESSION_MESSAGE seq=4 len=0
t=1.437s ← server: 0x0c seq=0xA0000001 len=0
t=1.440s ← server: 0x13 len=26 (session config)
t=1.518s ← server: ACCESSORY_MESSAGE seq=4 len=4   payload=06ae77f1
t=1.527s ← server: ACCESSORY_MESSAGE seq=2 len=7   payload=006a5e425ab400
t=1.578s ← server: first VIDEO frame (MPEG-TS, 0x47 sync confirmed)
```

After t≈1.6s, only VIDEO (~4300 packets / 30s, ~5MB) and 10-second keepalive
ping-pong. **No further ACCESSORY_MESSAGE traffic on an idle connection** —
the server pushes 0x15 only at session start (state snapshot) and presumably
on state-change events.

### Bidirectional KEEPALIVE with sequence echo (NEW)

CLAUDE.md described KEEPALIVE (0x0a) as client→server only. Live capture
shows it's **bidirectional with sequence-number echo**:

```
t= 0.079s tx KEEPALIVE seq=1
t= 0.674s rx KEEPALIVE seq=1  (33-50ms after we sent)
t=10.086s tx KEEPALIVE seq=2
t=10.120s rx KEEPALIVE seq=2
t=20.091s tx KEEPALIVE seq=3
t=20.140s rx KEEPALIVE seq=3
```

The server echoes our sequence numbers back. This is an actual ping-pong
RTT mechanism, not just "keep the socket warm".

### Per-type sequence spaces (NEW)

In session 1, ACCESSORY_MESSAGE seq numbers were 2 and 4 — but
SESSION_MESSAGE seq numbers were ALSO 1 and 4 with no overlap. The 9-byte
header's sequence field isn't a single connection-wide counter; **each
message type maintains its own independent sequence space**. This matters
for any code that wants to track or replay packets.

### The Rosie state-snapshot finding

Two ACCESSORY_MESSAGE payloads arrived in every session. The 4-byte one is
stable across all sessions; the 7-byte one has a stable 3-byte trailer and a
variable 4-byte prefix.

**4-byte ACCESSORY_MESSAGE (seq=4)** — `06ae77f1`. Identical in all 3
sessions. Hypothesis: per-rosie identity / type code / config hash. Byte 0
`0x06` could be an accessory-class identifier; bytes 1-3 `ae 77 f1` could be
a Rosie-model parameter, calibration hash, or fixed device constant.

**7-byte ACCESSORY_MESSAGE (seq=2)** — variable across sessions:

| Session | Camera state | Raw payload |
|---|---|---|
| 1 | home position | `00` `6a 5e 42` `5a` `b4` `00` |
| 2 | home (5 min later) | `01` `2d 63 a7` `5a` `b4` `00` |
| 3 | **panned full LEFT** | `02` `3c 03 37` `ae` `b4` `00` |

**Byte 4 changed `0x5a` → `0xae` when the Rosie was panned.** Byte 5
unchanged (`0xb4`). Byte 0 increments every session (`00 → 01 → 02`).
Bytes 1-3 look like a per-state hash or timestamp. Byte 6 is always `0x00`.

### Working format hypothesis for the 7-byte payload

```
[0]    state-version counter — increments every state update, 0-255 wrap
[1-3]  state-change hash or timestamp (variable, no clear structure yet)
[4]    PAN position  (0x5a = 90 at home; 0xae = 174 at full-left)
[5]    TILT position (0xb4 = 180 at home; stable when only pan moves)
[6]    0x00 trailer (probably null terminator)
```

If bytes 4-5 are unsigned 0-255 representing the full pan/tilt range:
- Pan range 350° / 256 = ~1.367°/unit; full-left swing from 0x5a to 0xae is
  +84 units ≈ 115°. Full-left from center in a 350° range is ~175° — so
  either the encoding is signed, or the convention is different from
  "0=center, 128=full-left".
- Plausible alternative: signed int8 where 0x5a = +90 (right of center) and
  0xae = -82 (left of center), making the move a 172° swing. **Consistent
  with "full left from center".**

### Session 11: tilt-DOWN anchors tilt encoding (and is symmetric)

User power-cycled the camera (second restart), then tilted the mount fully
down via the app. Capture worked first try — no recovery delay this time
(camera had been off for several minutes during user-driven app
troubleshooting before being plugged back in).

| Session | State | Raw payload |
|---|---|---|
| 11 | tilt fully DOWN | `00` `79 92 d1` `5a` `77` `00` |

**Byte 5 (TILT) = `0x77` (119)** — anchors the LOW end of the tilt range.

**Tilt encoding now characterized — and it's symmetric around `0xb4`:**

| Position | Tilt byte | Delta from rest |
|---|---|---|
| fully DOWN (session 11) | `0x77` (119) | -61 |
| at rest (sessions 1, 2, 5, 10) | `0xb4` (180) | 0 |
| fully UP (session 4) | `0xf1` (241) | +61 |

The deltas are equal in both directions. **0xb4 is the mechanical center**
of tilt. Full range = 0x77 to 0xf1 = 122 byte values mapped to the
documented 125° tilt range → **~1.025°/byte (essentially 1°/byte)**.

This contrasts with pan, which spans ~168 byte values for a documented 350°
range (~2.08°/byte). Tilt has noticeably higher byte-resolution.

**Pan byte surprise in this session: `0x5a` (90)** — and the user later
confirmed visually that the camera "did seem to reset to a middle spot when
it power cycled." That matches sessions 1, 2, and 11 all reading `0x5a`,
and it lets us close the encoding math:

**Pan is symmetric around `0x5a`:**
- Right limit at `0x06` (delta -84)
- Mechanical center / power-on default at `0x5a`
- Left limit at `0xae` (delta +84)
- Range = 168 byte values → 350° / 168 = **2.08°/byte**

**Tilt is symmetric around `0xb4`** (already characterized):
- Down limit `0x77` (delta -61), center `0xb4`, up limit `0xf1` (delta +61)
- Range = 122 byte values → 125° / 122 = **1.025°/byte**

The **canonical home position** (mechanical centers, post-boot default) is
**pan=`0x5a` tilt=`0xb4`**. The user's "Default View" preset at `0x3e b4`
is slightly left of mechanical center, set by user preference.

**Byte 0 ("counter") theory definitively dead.** Across all 6 successful
captures, byte 0 values were: `00, 01, 02, 03, 01, 01, 00` (in session
order 1, 2, 3, 4, 5, 10, 11). Not a counter. Not monotonic. Could be:
- A state-change-type code that takes a small set of discrete values
- A flag bitmask we're not interpreting correctly
- A randomly-set field that happens to use low values

### Sessions 6-9: post-reboot recovery period (false-alarm investigation)

After session 5, the user unplugged and restarted the LivingRoom camera. The
next three liveview attempts (sessions 6-8) and one more after extended wait
(session 9) all failed identically:

- TLS connect succeeded
- Auth header sent (122 bytes, same as working sessions)
- 0x06 auth-ACK received from server
- Keepalive ping/pong worked (server echoed our seq=1, seq=2)
- **No setup burst, no SESSION_MESSAGE, no 0x0c, no 0x13, no ACCESSORY_MESSAGE, no VIDEO**
- by_type summary on those sessions: `{"0x06": 1, "0x0a": 2}` — only auth ACK + keepalives

Camera homescreen and `/owls/{id}/config` both showed healthy state during
these failures (`status: online`, `rosie.connected: true`,
`rosie.calibrated: true`). The camera's own firmware: `9.96`; the Rosie's
own firmware (newly visible in config): `1.11.0.2`.

Investigated two hypotheses:
1. **Auth-header token theory** — Blink might have started requiring the
   /liveview response's `player_transaction` (16 chars) in the 64-byte token
   slot of the auth header, where we send all-nulls. Modified
   `immis_client.py` to support `--token-source player_transaction`.
2. **Camera-side post-reboot settling time** — camera needed longer to
   fully reattach the Rosie and resume normal session handling.

**Session 10 resolved it: hypothesis 2 was correct.** When session 10 ran
with `--token-source player_transaction`, the `/liveview` response that turn
happened to OMIT `player_transaction` entirely, so we ended up sending the
same all-null token we'd been sending all along — and the session worked
fully. The auth header was never the blocker. It was just camera-side state
needing time. The recovery feature in immis_client.py is left in place for
future experimentation, but the all-null token continues to work today.

Useful incidental finding: the `player_transaction` field is NOT always
present in `/liveview` responses — it appeared in our earlier diagnostic
call but was missing in session 10's response. So we can't rely on it as a
mandatory authentication factor.

### Session 10: full-RIGHT pan anchors the encoding

Camera at full pan-right (via the Blink app), tilt unchanged:

| Session | State | Raw payload |
|---|---|---|
| 10 | **full RIGHT** | `01` `b1 5f 21` `06` `b4` `00` |

**Byte 4 (PAN) = `0x06` (6)** — anchors the LOW end of the pan-byte range.
**Byte 5 (TILT) = `0xb4` (180)** — matches Default View tilt, consistent.

**Pan encoding now characterized:**

```
full RIGHT ← 0x06 (6) ── 0x3e (62) ── 0x5a (90) ── 0xae (174) → full LEFT
                       Default View   earlier      "full left"
                                       user pos    via app
```

- Convention: **unsigned, increasing value = leftward pan**
- Observed range: `0x06` to `0xae` ≈ 168 byte values
- If Rosie's mechanical pan range is the documented 350°, that's
  ~2.08°/unit resolution
- "Default View" at 0x3e sits ~33% of the way from right limit to left
  limit — consistent with a user-chosen "look slightly left of center"
  preset, not the mathematical center

Tilt encoding is still under-constrained — we only have two values: `0xb4`
(at rest, both user-default and pre-experiments) and `0xf1` (~30° up from
default). Need a full-down capture (and ideally a full-up that's actually
at the mechanical limit) to pin tilt.

Byte 0 came back as `0x01` again — earlier I'd theorized it was a session
counter, but it's now appeared as 00, 01, 01, 02, 03 across sessions
1, 2, 5, 3, 4 in time order. Definitely not a simple counter. Possibly a
"state-change category" code (e.g., 00 = initial, 01 = single-axis,
02 = multi-axis?). Insufficient data to determine.

### Session 5: user-configured "Default View" position

User pressed the Blink app's "Default View" button. **Critical caveat from
the user (recorded after the original capture write-up):** "Default View" is
a **user-configured** preset that the user themselves chose during app
setup, not a factory-set reference. So this position is not canonical —
it's just where the user pointed the mount and saved as their preferred
default. We do NOT yet have a known mechanical-center or factory-home
reference in our captured data. Treat ALL position byte values seen so far
as samples from arbitrary user-chosen positions.

Capture:

| Session | State | Raw payload |
|---|---|---|
| 5 | user "Default View" preset | `01` `08 7a 66` `3e` `b4` `00` |

**What we still know:** byte 4 = `0x3e` (62), byte 5 = `0xb4` (180) in this
sample. Byte 5 matches the no-tilt readings in sessions 1, 2, and 4, so
**`0xb4` reliably means "tilt-axis at the position the user calls home"**
— that's plausibly mechanical center but not yet proven.

**Byte 0 anomaly:** sessions 1-4 had byte 0 monotonically incrementing
00 → 01 → 02 → 03. Session 5 has byte 0 = `0x01`, breaking the
"session-counter" theory. It's something else — possibly:
- a change-class code (e.g., 01 = "single-axis change"?)
- a counter scoped to physical state changes, reset by the "Default Home"
  command
- a flag that distinguishes "factory-set" vs "user-set" state
- noise / not really a counter at all (just looked like one across 4 samples)

**ACCESSORY_MESSAGE seq jumped to `seq=3`** for this 7-byte payload (was
seq=2 in every prior session). The seq field on accessory state-update
messages might increment per state change rather than per session.

**Pan-range constraint from two arbitrary user positions:**
- `0x3e` (62) = the user's chosen "Default View" preset
- `0xae` (174) = app's "full left" gesture from there
- Delta = +112 units

Neither point is anchored to a mechanical or factory reference, so this
delta only tells us that the byte moved by +112 when the mount swung
from "user default" to "as far left as the app gesture went." Whether
`0xae` is at the mechanical pan-left stop, or only partway, is unknown.
**Full-right capture is the next needed data point** — it tells us
whether the byte decreases below `0x3e` (signed/bidirectional encoding)
or wraps high past `0xae` (unsigned increasing-with-left convention).

### Session 4: tilt-up confirmation

User left the pan at full-left and tilted the mount fully up via the app.
Capture:

| Session | State | Raw payload |
|---|---|---|
| 4 | full-left, **tilted up** | `03` `4c 0e 7b` `ae` `f1` `00` |

**Byte 5 changed `0xb4` → `0xf1` (180 → 241)** while byte 4 held at `0xae`.
This confirms byte 5 is the tilt axis. Pan-vs-tilt assignment is now locked.

Tilt range 125° total / 256 byte values = 0.488°/unit. The b4→f1 swing of
+61 units ≈ 30° of tilt, which is less than a "fully up" command should
produce. Either (a) the byte encoding isn't a linear 0-255 over the full
range, (b) the encoding is signed and 0xb4 maps to a value far from center,
or (c) the user's "tilt up" didn't reach the mechanical limit. More
positions needed to pin the encoding.

### Next steps

1. **Home-reset capture**: user sends Rosie back to home (or uses the app's
   "Set Home" / "Reset" button if available). Confirms bytes 4-5 return to
   `0x5a 0xb4` and gives a stable origin for the byte-to-degree mapping.
2. **Multi-position sweep**: 4-5 captures at different known positions
   (e.g., full-right + center-tilt, center + tilt-down, etc.) to fit a
   byte-to-degree curve and resolve signed-vs-unsigned encoding.
2. **Home-reset confirmation** (single capture): user uses app to send
   Rosie back to home. Confirm bytes 4-5 return to `0x5a 0xb4`.
3. **Sample several positions** (3-4 captures at known approximate
   positions) to figure out the byte-to-degree mapping and signed/unsigned
   question.
4. **Then** plan a send-command experiment: build a candidate
   ACCESSORY_MESSAGE payload (probably mirroring the 7-byte server-push
   format) and send it via our TLS connection. Confirm with user before
   doing anything that could trigger physical motion.

Logs (gitignored, kept locally for verification):
- `logs/immis_observe-1234567-20260519-174446.jsonl` (session 1, home)
- `logs/immis_observe-1234567-20260519-174558.jsonl` (session 2, home)
- `logs/immis_observe-1234567-20260519-174717.jsonl` (session 3, full-left)

## 2026-05-19 — Phase 1 CONCLUDED: REST has no rosie movement controls

After ~85 distinct path/method probes against Blink's REST API, **no
controller exists for rosie pan/tilt control**. Every probe outside the known
homescreen/config/liveview routes returned the generic nginx + Phusion
Passenger `<h1>Not Found</h1>` HTML — meaning Blink's Rails router has no
entry for any of these paths.

**Probes performed (all HTML 404):**

| Group | Method | Count |
|---|---|---|
| `/networks/{n}/cameras/{c}/accessories/rosie/{r}{suffix}` (16 suffixes) | GET | 16 |
| `/networks/{n}/owls/{c}/accessories/rosie/{r}{suffix}` (16 suffixes) | GET | 16 |
| Account-/network-scoped /accessories variants | GET | 5 |
| Legacy `/network/{n}/(owl\|camera)/{c}/...` shape | GET | 2 |
| Same 39 paths via POST `{}` | POST | 39 |
| Rosie-as-direct-subresource (`/owls/{c}/rosie/...`) | GET/POST | 5 |
| Alternate API versions (`/api/v2`, `/api/v4`) | GET | 2 |

**Liveview response inspection** (`POST /api/v2/accounts/{a}/networks/{n}/owls/{c}/liveview`):

```json
{
  "command_id": 2214879929,
  "duration": 300,
  "extended_duration": 5400,
  "polling_interval": 15,
  "is_mclv": true,
  "server": "immis://<aws-relay-ip>:443/{ConnectionID}__IMDS_{DeviceSerial}?client_id={ClientID}",
  ...
}
```

No rosie-specific fields. The mobile app must be discovering pan/tilt
capability from the homescreen `accessories.rosie[]` array (where `calibrated:
true` and `connected: true` enable the UI), then sending movement commands
in-band on the IMMIS connection — exactly as CLAUDE.md hypothesized.

**Other facts captured during Phase 1:**

- `POST /network/{n}/command/{cmd_id}/done` is deprecated:
  `{"message":"Endpoint no longer supported.","code":900}`. Liveview commands
  auto-expire on Blink's side when no IMMIS client connects (we saw
  `status_code: 523, status_msg: "Live view failed"` after our test session
  was abandoned). Phase 2 doesn't need to manage this lifecycle.
- IMMIS URL is a real string from production: `immis://{IP}:443/{ConnID}__IMDS_{DeviceSerial}?client_id={CameraID}`.
  ClientID parameter == camera ID (the owl_id, `1234567`), which fits as uint32
  in the 122-byte auth header at offset 24.
- DeviceSerial in the URL (`GNTXXXXXXXXXXXXX`) is 16 chars and gets dropped
  into the auth header's serial field at offset 8.

**Verdict:** Phase 1 done. REST is conclusively dead for rosie control.
Pivot to Phase 2 (build IMMIS client, fuzz ACCESSORY_MESSAGE 0x15 and
INLINE_COMMAND 0x14 payloads).

Logs:
- `logs/rosie_probe-get-20260519-171113.jsonl` (39 GET probes)
- `logs/rosie_probe-post-20260519-171729.jsonl` (39 POST probes)

## 2026-05-19 — Phase 1a GET sweep + verb-discriminator diagnostic

**Result:** 39/39 candidate GETs returned `404 <h1>Not Found</h1>` (generic
nginx + Phusion Passenger HTML). No rate limiting, ~120-150ms per request.

**Diagnostic followup** revealed that the GET sweep is less conclusive than it
looks. Blink returns the same generic HTML 404 for "no route matches" AND for
"route exists for a different verb." The differentiator is what the response
looks like when the *controller* fires:

| Probe | Response | What it tells us |
|---|---|---|
| `GET /api/v3/accounts/{acct}/homescreen` | `200 application/json` | route + controller live |
| `GET /api/v3/accounts/{wrong}/homescreen` | `400 {"code":1620,"message":"Invalid Account ID"}` | route matched, controller validated and rejected |
| `GET /api/v3/accounts/{acct}/garbage_suffix` | `404 text/html <h1>Not Found</h1>` | no route at all |
| `GET /api/v1/accounts/{acct}/networks/12345/state/arm` (POST-only route) | `404 text/html <h1>Not Found</h1>` | **same HTML 404 as no-route** |
| `POST /api/v1/accounts/{acct}/networks/12345/state/nonsense` | `400 {"message":"Arm or Disarm are only valid states"}` | route matched on POST, validator ran |
| `PUT /api/v3/accounts/{acct}/homescreen` (GET-only) | `404 text/html <h1>Not Found</h1>` | wrong verb → HTML 404 |

**Implication:** the 39-path GET sweep does NOT rule out POST-only rosie
controllers. Some of the 39 paths might be live POST endpoints that 404 on GET
identically to a non-existent route. To actually rule out rosie REST control,
we need a POST sweep with empty `{}` payload — controllers running their
validators on empty input will surface as JSON 4xx (e.g. `{"message":"missing
field 'direction'"}`) rather than HTML 404.

**Status:** GET sweep complete; POST sweep is the next probe.
Log: `logs/rosie_probe-get-20260519-171113.jsonl` (39 entries, all 404 HTML).

## 2026-05-19 — Inherited from blink-mcp

Read through `~/projects/blink-mcp` (the production MCP service for this account).
Two things to inherit and one to correct:

**Auth boundary set:** `~/.blink-mcp/session.json` (chmod 600) is the shared session
file. blink-mcp owns the OAuth+2FA bootstrap (Python + blinkpy); blink-rosie reuses
the token. Refresh logic is a port of `blink-mcp/src/blink/client.ts:155-225`.

**REST header correction:** earlier draft of CLAUDE.md said "User-Agent should mimic
the Blink app to avoid Lab126 detection." That's wrong for REST calls — sending UA or
APP-BUILD headers triggers HTTP 426. Bearer + Content-Type only. The Blink-app UA is
ONLY used on the OAuth refresh endpoint. Fixed in CLAUDE.md `Authentication Notes`.

**Already-ruled-out REST paths.** blink-mcp's 2026-05-19 narrative
(`docs/narrative/2026-05-19-two-camera-tooling.md`) records these as **404**:

| Probe | Result |
|---|---|
| `GET /rosie` | 404 |
| `GET /rosies/{id}` | 404 |
| `GET /accessories/*` (any generic, non-camera-scoped) | 404 |
| Camera config exposes only `rosie.calibrated`, `rosie.calibration_compatible` | no movement controls |

Phase 1 will skip those exact paths and focus on the **camera-scoped** accessory shape
(`/api/v1/accounts/{a}/networks/{n}/cameras|owls/{c}/accessories/rosie/{rosieId}/...`),
which is the Storm-floodlight pattern documented in
`refs/homebridge-blink-original/src/blink-api.js`.

**Live target inventory** (this account, 2026-05-19):

| Field | Value |
|---|---|
| Network | `MyHome` / id `12345` |
| Camera with Rosie | `LivingRoom` / id `1234567` (type `owl`) |
| Rosie accessory id | `54321` |
| Rosie serial | `GPXXXXXXXXXXXXXX` |
| Other camera | `BedRoom` / id `1234568` (no Rosie) |

**Status:** auth + REST foundation building next; Phase 1 probes follow.

---

## Open questions

- What HTTP status does Blink return for non-existent vs unauthorized rosie endpoints? (Probe-and-diff in Phase 1.)
- Are there any rosie-specific fields under `/owls/{owlId}/config` or `/cameras/{camId}/config`?
- Does the `rosie_lv_session` event vary based on which UI buttons were used during the session?
- Does ACCESSORY_MESSAGE (0x15) require a session-establishment handshake before pan/tilt payloads will be accepted?

## Ruled out

(nothing yet)
