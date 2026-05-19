# Decoding the Rosie — From Empty Directory to Known Wire Format in One Evening

Nic had a Blink Mini in the LivingRoom with a motorized pan-tilt mount
attached. The community had been chasing programmatic control of that mount
("rosie", in Blink's internal codename) for years and nobody had cracked it.
Blink has no official SDK. blinkpy has no PTZ surface. Hubitat's driver
explicitly says "Rosie devices have no control." The two best-maintained
homebridge projects log accessory bytes off the wire and discard them. A
single GitHub repo (`jakecrowley/blink-immis-proxy`) had a full Frida + socat
MITM kit but nobody using it had publicly written up what the mount actually
sees on the wire.

On 2026-05-19, between roughly 13:16 and 18:50 local time, blink-rosie went
from an empty `~/projects/blink-rosie` directory containing only an
auto-generated `.remember/` folder to a fully decoded server-push wire
format for the Rosie's position state, the message type that carries
client→server commands, both axes anchored at their mechanical limits, and
twelve git commits of durable evidence. The actual movement command remains
out of reach without a real MITM capture or an iOS binary dump, but the
search space has gone from "anywhere" to "find the cmd_id and payload for
SESSION_COMMAND 0x17."

This is the record of how that decode happened.

## What The Ask Actually Was

The user pasted a full project brief into the `/init` flow: a phased plan
with explicit risk constraints, references to six community repos to clone,
the IMMIS packet-framing spec, and the byte-level layout of the 122-byte
auth header. The work was scoped from the start as a reverse-engineering
investigation, not an integration project. Phase 1 was REST endpoint
discovery — automated, no special hardware. Phase 2 was building our own
IMMIS client and probing the protocol. Phase 3 was the Android Frida MITM
that nobody else had finished writing up.

That brief became `CLAUDE.md` verbatim. The first commit (`62bca04`) was a
bootstrap: the brief, a `.gitignore` excluding the reference repos and the
JSONL logs, six cloned references in `refs/` totaling ~6.6 MB, and an empty
`docs/findings.md` with a date-stamped log structure.

## The Session File As Auth Boundary

The user's existing `~/projects/blink-mcp` service had already solved the
hardest part: the Blink OAuth + 2FA dance. blink-mcp uses a Python bootstrap
(`scripts/auth.py`) that drives `blinkpy.Auth` through the login flow and
writes the resulting tokens to `~/.blink-mcp/session.json` (chmod 600). The
blink-rosie work needed authenticated REST access but had no business
re-implementing OAuth.

The cleanest separation was to treat that session file as the auth
boundary: blink-mcp owns the bootstrap, blink-rosie reads the token. That
became `src/session.py` (load, refresh, atomic write-back) and
`src/api_client.py` (BlinkClient class, single-flight refresh on 401). The
refresh logic mirrors `blink-mcp/src/blink/client.ts:155-225` exactly —
form-encoded POST to `https://api.oauth.blink.com/oauth/token` with
`grant_type=refresh_token`, `client_id=ios`, `scope=client`, the session's
`unique_id` as `hardware_id`, and `User-Agent: Blink/2511191620
CFNetwork/3860.200.71 Darwin/25.1.0`.

A correction landed during this step. The original CLAUDE.md (taken from
the user's brief) said *"User-Agent should mimic the Blink app to avoid
detection by Lab126."* The blink-mcp TypeScript client had a hard-won
comment at `src/blink/client.ts:252-261` saying the opposite: sending
User-Agent or APP-BUILD on REST traffic triggers HTTP 426 ("app update
required"). The Blink-app UA is *only* used for the OAuth refresh endpoint.
That correction went into CLAUDE.md under "REST API headers — minimum that
works" in commit `1a043e6`, along with the smoke test:

```
ok tier=uXXX account=99999 networks=1 cameras=0 owls=2 rosies=1
```

One network (`MyHome`, id `12345`), two Blink Mini ("owl") cameras, and
the one Rosie accessory (`id=54321`, serial `GPXXXXXXXXXXXXXX`, attached to
the LivingRoom owl `1234567`).

## Phase 1: Eliminating REST in 85 Probes

The Phase 1 design was deliberately exhaustive. The blink-mcp narrative at
`docs/narrative/2026-05-19-two-camera-tooling.md` had already documented
that top-level `/rosie`, `/rosies/{id}`, and generic `/accessories/*` paths
returned 404 — but the camera-scoped form
(`/api/v1/accounts/{a}/networks/{n}/cameras/{c}/accessories/{type}/{id}/...`,
the shape that works for Storm floodlights per
`refs/homebridge-blink-original/src/blink-api.js:67-68`) had not been
systematically tested.

`src/rosie_probe.py` generated 39 candidate paths: 16 suffixes
(`/status`, `/move`, `/pan`, `/tilt`, `/ptz`, `/home`, `/default_position`,
`/sweep`, `/calibrate`, etc.) under both `/cameras/{c}/` and `/owls/{c}/`
segments — since the Rosie is on a Mini (owl) but Storm's documented shape
uses `/cameras/`. Three additional account-/network-scoped variants and two
legacy `/network/{n}/...` shapes rounded out the candidate list.

All 39 GETs returned `404 <h1>Not Found</h1>` (HTML, served by `nginx +
Phusion Passenger(R)`). Logged to
`logs/rosie_probe-get-20260519-171113.jsonl`.

This is where the investigation almost stopped prematurely. The clean
zero-hit result *looked* conclusive. But a control probe disambiguated:

| Probe | Result |
|---|---|
| `GET /api/v3/accounts/{wrong}/homescreen` | `400 application/json {"code":1620,"message":"Invalid Account ID"}` |
| `GET /api/v3/accounts/{acct}/nope_zzz` | `404 text/html <h1>Not Found</h1>` |
| `GET /api/v1/accounts/{acct}/networks/12345/state/arm` (POST-only) | `404 text/html <h1>Not Found</h1>` |
| `POST /api/v1/accounts/{acct}/networks/12345/state/nonsense` | `400 application/json {"message":"Arm or Disarm are only valid states"}` |

Two findings here. First: Blink returns the **same generic HTML 404** for
"no route matches" *and* for "right route, wrong verb." Second: when a
controller actually matches and runs its validator, you get a JSON 4xx with
a structured message. Our 39 GETs all landed in the HTML 404 bucket — but
that didn't rule out POST-only routes. A POST-only route would 404 on GET
identically to a non-existent route.

So the same 39 paths got swept again via POST with `{}` body. Logged to
`logs/rosie_probe-post-20260519-171729.jsonl`. Same result: 39/39 HTML
404. Then seven more variants — `/owls/{c}/rosie/{id}/...` shapes treating
rosie as a direct sub-resource of the owl, plus alternate API versions
(`/api/v2`, `/api/v4`). Also all HTML 404.

A final liveview-response inspection: `POST
/api/v2/accounts/{a}/networks/12345/owls/1234567/liveview` with
`{"intent":"liveview"}` returned a healthy 200 with the standard fields
(`command_id`, `duration`, `polling_interval`, `is_mclv`, the immis:// URL),
**zero rosie-specific fields**. The mobile app must gate its pan/tilt UI on
the homescreen's `accessories.rosie[].calibrated` flag — not on anything
the liveview endpoint returns.

Commit `38cd3ec` closed Phase 1: ~85 distinct path/method probes, no
controllers found, REST conclusively ruled out for rosie movement. Bonus
intel surfaced in the same commit:

- `POST /network/{n}/command/{id}/done` is now deprecated:
  `{"message":"Endpoint no longer supported.","code":900}`. Liveview
  commands auto-fail server-side if no IMMIS client connects
  (`status_code: 523, status_msg: "Live view failed"`).
- The captured immis:// URL parsed cleanly into the fields the auth header
  expects: connection ID `BCFVdaJ5W9MB4On_` (16 chars), device serial
  `GNTXXXXXXXXXXXXX` (16 chars), client_id `1234567` (the owl ID, fits in
  uint32).

## Phase 2.1: The IMMIS Client

`src/immis_client.py` is an async TLS client that connects to a live IMMIS
server, sends the 122-byte auth header, runs the standard heartbeat cadence
(LATENCY_STATS every 1s, KEEPALIVE every 10s), and logs every non-VIDEO
frame with full hex dumps. The reference port was
`refs/blinkpy/blinkpy/livestream.py` (cleanest Python implementation) with
cross-checks against
`refs/homebridge-blink-new/src/blink-api/immis-proxy.ts` (most complete
message-type enum). One deliberate divergence from blinkpy: use
`StreamReader.readexactly(N)` for frame reassembly rather than
`StreamReader.read(N)` — blinkpy's version warns and breaks on partial
reads, which kills the loop. `readexactly` handles partial-frame
reassembly natively.

Before any live test, the 122-byte auth header was validated byte by byte
against CLAUDE.md's spec:

```
[0:4]   magic         = 00000028   ✓
[4:8]   serial_len    = 00000010   ✓
[8:24]  serial bytes  = GNTXXXXXXXXXXXXX   ✓
[24:28] client_id BE  = 1234567   ✓
[28:30] static        = 0108   ✓
[30:34] token_len     = 00000040   ✓
[34:98] token (all 0) ✓
[98:102] conn_id_len  = 00000010   ✓
[102:118] conn_id     = BCFVdaJ5W9MB4On_   ✓
[118:122] trailer     = 00000001   ✓
```

122 bytes, every offset matching. Time to go live.

## Phase 2.2: The First Connection And What Came Back

Session 1 ran for 30 seconds against owl 1234567. The summary:

```
elapsed: 30.08s
video packets: 4331 (5,166,240 bytes)
non-video packets: 10
by type:
  0x00 VIDEO              4331
  0x06 UNKNOWN_0x06       1
  0x0a KEEPALIVE          3
  0x0c UNKNOWN_0x0c       1
  0x13 UNKNOWN_0x13       1
  0x15 ACCESSORY_MESSAGE  2
  0x18 SESSION_MESSAGE    2
```

Five things in that table were not in any public reference. Three new
message types — `0x06`, `0x0c`, `0x13` — that sealad886's TS enum,
blinkpy, and CLAUDE.md had all missed. KEEPALIVE arriving from the server
(community references describe it as client-only). And the
ACCESSORY_MESSAGE the entire community had been hunting, arriving twice in
the setup burst on a connection where nobody had touched the mount.

The timeline reconstructed from the JSONL log made the structure of the
setup burst clear:

```
t=0.079s → 122-byte auth header
t=0.538s ← 0x06 len=0           (auth ACK, ~0.5s after we sent)
t=0.674s ← KEEPALIVE seq=1      (server echoes our seq=1 keepalive)
t=1.405s ← SESSION_MESSAGE seq=1 len=0
t=1.407s ← SESSION_MESSAGE seq=4 len=0
t=1.437s ← 0x0c seq=0xA0000001 len=0
t=1.440s ← 0x13 len=26          (00000000000000000000 1388 03e8 03e8 0064 00000000…)
t=1.518s ← ACCESSORY_MESSAGE seq=4 len=4   payload=06ae77f1
t=1.527s ← ACCESSORY_MESSAGE seq=2 len=7   payload=006a5e425ab400
t=1.578s ← first VIDEO frame (MPEG-TS, 0x47 sync)
t=10.086s → KEEPALIVE seq=2
t=10.120s ← KEEPALIVE seq=2     (server echoes, 34ms later)
```

Two more findings emerged from that timeline. The server echoes our
KEEPALIVE sequence numbers back at us within 30-50ms — it's a ping/pong RTT
mechanism, not fire-and-forget. And the sequence numbers across different
message types overlap (SESSION_MESSAGE seqs 1 and 4 coexisted with
ACCESSORY_MESSAGE seqs 2 and 4 in the same session): **each message type
maintains its own independent sequence space**.

The 0x13 payload had structure. Numeric fields: 0x1388 = 5000, 0x03e8 = 1000
(twice), 0x0064 = 100. Almost certainly a session-config block with timing
constants — 5000ms session timeout, 1000ms intervals, 100ms something. The
same payload arrived byte-identical in every subsequent session, regardless
of camera state. Marked as `SESSION_CONFIG (provisional)` in CLAUDE.md.

After t≈1.6s, no further ACCESSORY_MESSAGE traffic for the remaining 28.5
seconds. Just video and the keepalive ping-pong. Conclusion: **the
ACCESSORY_MESSAGE packets are part of the session-startup state snapshot,
not idle telemetry.** The server pushes them once at session start and then
only on state changes.

## The Decode

Session 2 ran 5 minutes later against the same Rosie at the same physical
position. The diff was the entire point.

| Packet | Session 1 | Session 2 | Stable? |
|---|---|---|---|
| 0x15 seq=4 len=4 | `06ae77f1` | `06ae77f1` | ✅ identical |
| 0x15 seq=2 len=7 | `006a5e42 5ab400` | `012d63a7 5ab400` | ⚠ prefix changed, trailer stable |
| 0x13 len=26 | identical | identical | ✅ |
| 0x0c seq | 0xA0000001 | 0xA0000001 | ✅ |

The 4-byte payload `06ae77f1` was identical across both sessions and across
all 11 subsequent ones. Hypothesis: per-rosie identity hash. Byte 0 `0x06`
could literally be an accessory-class code (rosie = 6); `ae77f1` is a
per-device constant — probably a hash of the serial or a calibration
parameter.

The 7-byte payload had a stable 3-byte tail and a variable 4-byte prefix.
That's the structure that mattered.

User then panned the Rosie fully to the left via the Blink app, closed the
app, and we ran session 3 immediately. Then session 4 with tilt added on
top. Three diffs in:

| Session | Camera state | Pan byte (4) | Tilt byte (5) |
|---|---|---|---|
| 1 | initial position | `0x5a` | `0xb4` |
| 2 | same (5 min later) | `0x5a` | `0xb4` |
| 3 | panned **full LEFT** | **`0xae`** | `0xb4` |
| 4 | + tilted **UP** | `0xae` | **`0xf1`** |

**Byte 4 changed only when pan changed. Byte 5 changed only when tilt
changed.** The wire format was readable.

Commit `91f30b7` recorded the format hypothesis:

```
[0]    state-version counter (initially looked monotonic)
[1-3]  state-change hash or timestamp
[4]    PAN position byte   — 0x5a at rest, 0xae at full-left
[5]    TILT position byte  — 0xb4 at rest, 0xf1 at full-up
[6]    0x00 trailer
```

The user flagged something important after that commit: "are you
documenting this as we go so nothing is lost during compact or anything,
this is important details." The findings were already in git, but the
question was a useful forcing function — every subsequent finding got
committed within minutes of being observed.

## The "Default View" Correction

Session 5 used the Blink app's "Default View" button to restore a
known-reference position. Reading: `01 087a66 3e b4 00`. Byte 4 came back
to `0x3e` (62), not the `0x5a` (90) we'd seen in sessions 1-2. That seemed
to mean sessions 1-2 weren't actually at any kind of home — just at the
last position the camera happened to be in.

The user then corrected an interpretive mistake that had already landed in
`docs/findings.md` calling that `0x3e b4` reading the "factory home." From
the user: *"important caveat, that's not 'factory home'...that's the
'Default View' that i set in the app."*

So `0x3e b4` was a user-configured preset, not a canonical reference. The
correction landed as its own commit (`5794f65`) — the framing matters
because future readers (Broadside, or a future Claude session reading the
docs cold) would otherwise build wrong models off the wrong baseline. The
findings.md update added the caveat verbatim and reframed the pan-range
constraint as "the +112-unit delta between user-default-view and
app-full-left tells us byte 4 moves leftward when the mount pans left, but
neither endpoint is anchored to a known mechanical limit."

That was the discipline that kept the rest of the decode honest.

## The Wilderness — Sessions 6 Through 9

User panned the Rosie all the way right next. Then four sessions in a row
all failed identically. Each produced exactly the same trace:

```
TLS connect ✓
auth header sent ✓
0x06 auth ACK received ✓
keepalive ping/pong ✓
[no setup burst, no SESSION_MESSAGE, no 0x13, no ACCESSORY_MESSAGE, no VIDEO]
session_end at the duration timeout
```

A diagnostic `/liveview` + immediate command-status check showed Blink
itself thought everything was fine. `status_code: 908, state_condition:
"running", first_joiner: true`. The new pair of fields `player_transaction`
(16 chars: `"VA56vSy5wKydCZSH"`) and `liveview_token` (22-char base64url:
`"9MM46_g-e425BksrD-rg6g"`) — neither of which our auth header populated —
made for a plausible suspect. Our 64-byte token slot was all nulls; maybe
Blink's server-side validation had tightened and now required the
`player_transaction` value packed into that field.

The `--token-source` option went into `immis_client.py` to test that
hypothesis. Session 10 ran with `--token-source player_transaction`. And
then the surprise: the `/liveview` response that turn happened to omit
`player_transaction` entirely. We ended up sending the same all-null token
we'd been sending all along — and the session worked fully.

So the token-slot theory was wrong, or at least wasn't the active blocker.
What had actually happened: between sessions 5 and 6, the user had
power-cycled the LivingRoom camera (the "I had to unplug it" disclosure
came later). Sessions 6-9 hit a freshly-booted camera that hadn't fully
finished its post-reboot handshake with Blink's relay infra. The
homescreen and `/owls/{c}/config` both reported `status: online,
rosie.connected: true, rosie.calibrated: true` — the control plane recovers
faster than the streaming plane.

The `--token-source` option stayed in the code for future experiments. The
real lesson for future sessions, recorded in `docs/findings.md`:
post-reboot, the IMMIS streaming subsystem can lag the REST control plane
by several minutes. Don't trust `status: online` as readiness; just retry.

## The Pan Anchor And The Reboot

Session 10's payload: `01 b15f21 06 b4 00`. Byte 4 (PAN) = `0x06`. Anchors
the low end of the pan range. Combined with prior sessions:

```
full RIGHT ← 0x06 (6) ── 0x3e (62) ── 0x5a (90) ── 0xae (174) → full LEFT
                       Default View   earlier      app full-left
```

Range of ~168 byte values for the documented 350° pan range ≈ 2.08° per
byte. Convention: unsigned, increasing value = leftward. Commit `864a272`.

Then the LivingRoom camera went unresponsive in the user's iPhone Blink
app. Blink's homescreen still reported it healthy. The user power-cycled
the camera a second time, then tilted the mount fully down via the app.
Session 11 captured first try (the post-reboot delay was much shorter the
second time, presumably because the rosie pairing was already cached on
the camera side):

```
00 7992d1 5a 77 00
```

Byte 5 (TILT) = `0x77` (119). Combined with session 4's `0xf1` (241) and
the rest readings at `0xb4` (180):

```
DOWN  ← 0x77 (119) ─── 0xb4 (180) ─── 0xf1 (241) → UP
        delta -61      "rest"          delta +61
```

The deltas were symmetric. 0xb4 was the mechanical center. The tilt range
of 122 byte values for the documented 125° tilt range = **1.025°/byte**.
Essentially 1°/byte. Tilt has noticeably higher byte-resolution than pan.

Byte 4 came back as `0x5a` (90) in session 11 — the same value we'd seen
in sessions 1-2 ("the position the camera happened to be in when we first
connected"). The user then provided the closing observation: *"it did seem
to reset to a middle spot when it power cycled."* That visual confirmation
turned the coincidence into a fact:

| Axis | Center | Min byte | Max byte | Range | °/byte |
|---|---|---|---|---|---|
| Pan  | `0x5a` (90)  | `0x06` (6)   | `0xae` (174) | 168 | **2.08°/byte** |
| Tilt | `0xb4` (180) | `0x77` (119) | `0xf1` (241) | 122 | **1.025°/byte** |

Both axes symmetric around their mechanical centers, both convention-
matching (increasing byte = leftward pan or upward tilt), both
byte-to-degree maps closing cleanly against the documented mechanical
ranges. Commit `b4e170d` recorded Phase 2.2 complete. The Rosie position
state wire format was fully decoded.

## Phase 2.3: Finding The Command Channel

Building the send experiment was the next ~30 minutes. `immis_client.py`
got a `send` subcommand: open a session, wait for the first VIDEO frame
(setup burst is over by then), then transmit one configured packet
(arbitrary msgtype + hex payload), then hold the connection for N more
seconds to observe any reactions.

The probe table:

| Probe | TX msgtype | TX payload | Server reaction | Camera moved? |
|---|---|---|---|---|
| A | `0x14` INLINE_COMMAND | (empty) | none | no |
| B | `0x14` INLINE_COMMAND | `00000000 70 77 00` (7-byte target, pan→0x70) | none | no |
| C | `0x14` INLINE_COMMAND | `01 5a b4` (cmd-id-prefix style) | none | no |
| D | `0x17` SESSION_COMMAND | `05 5a b4` (cmd_id=5, pan, tilt) | **empty 0x18 @ t+37ms** | no |
| E | `0x15` ACCESSORY_MESSAGE | `00000000 70 b4 00` (7-byte echo) | none | no |
| F | `0x17` SESSION_COMMAND | `ff` (1-byte bogus cmd_id) | **empty 0x18 @ t+~30ms** | no |

Two findings made Phase 2.3 conclusive in one direction and inconclusive
in the other.

**`0x17` SESSION_COMMAND is the right channel for client→server commands.**
That's the only message type that produced any server reaction at all. The
37ms response latency is network RTT — the server is reading and
processing our 0x17 packets in real time.

**The empty 0x18 ACK is universal.** Sending `cmd_id=0xff` (clearly bogus)
produced the same empty ACK as `cmd_id=0x05`. The server ACKs every 0x17
it receives at the protocol layer, then silently discards unrecognized
cmd_ids and malformed payloads. **The ACK content can't be used as a
success signal.** Only physical movement or a follow-up ACCESSORY_MESSAGE
position-update would tell us a command was understood.

Without that success signal, brute-forcing the (cmd_id × payload-shape)
space gets impractical fast. Just the obvious cmd_id range (0x00 through
0x1f) × three payload shapes = 96 probes, each requiring 15+ seconds and
eyes-on-mount.

Two other things to record from the probe table. `0x14` INLINE_COMMAND in
the client→server direction is **dead silent**, despite the Blink app's
own `IMMI_DATA_FLAG_INLINE_LV_CMD` counter being marked *sent* in
community refs. Either the type was renamed or there's a gate the app sets
that we're missing. `0x15` ACCESSORY_MESSAGE in the client→server direction
is also silently ignored, despite some refs marking the type bidirectional.

Commit `71a785d` closed Phase 2.3 with the probe table and the pivot
decision.

## What Got Built And What Got Decoded

Six git commits trace the work after the bootstrap, in order:

| Commit | What it locked in |
|---|---|
| `1a043e6` | Session reader, REST client, CLAUDE.md auth-header correction |
| `38cd3ec` | Phase 1 — ~85 REST probes, all 404 HTML |
| `91f30b7` | Phase 2.2 — three new IMMIS msgtypes (0x06, 0x0c, 0x13), bidirectional KEEPALIVE, per-type seq spaces, wire format hypothesis (pan=byte 4, tilt=byte 5) |
| `5794f65` | Default View correction (user-set, not factory home) |
| `864a272` | Pan anchored at both limits (`0x06` right, `0xae` left, ~2.08°/byte) |
| `b4e170d` | Phase 2.2 COMPLETE — both axes symmetric around mechanical centers, `0x5a 0xb4` is the post-boot home position, ~1.025°/byte tilt resolution |
| `71a785d` | Phase 2.3 — `0x17` SESSION_COMMAND is the command channel; cmd_id/payload format unknown |

The `src/` tree at end of session:

```
src/
├── __init__.py
├── session.py          # ~/.blink-mcp/session.json reader + OAuth refresh
├── api_client.py       # BlinkClient — REST with token refresh, CLI: ping, rosies
├── rosie_probe.py      # Phase 1 — REST endpoint sweep with JSONL output
└── immis_client.py     # Phase 2 — async IMMIS observer + send experiment
```

Total non-vendored code: just under 800 lines. The reference repos in
`refs/` (gitignored) were essential reading but contributed no copied code.

Twelve liveview sessions ran during the evening (1-5 in the first arc, 6-10
through the camera-reboot wilderness, 11 for tilt-down confirmation, 12+
for the Phase 2.3 send probes). Combined ~6-8 minutes of live IMMIS
connection time. No rate limiting observed; no 429s; no account
suspension. The post-reboot 3-4-session dead window is the only failure
mode worth flagging for future work.

## What's Still Out Of Reach

The mount remains unmoveable from a script today. The wire format we
*read* from the server is well understood; the wire format we *send* to
move the mount is not. Three things are unknown:

1. The valid Rosie command IDs. Audio commands 3 (StartAudio) and 4
   (StopAudio) are known from community refs. The accessory-control
   cmd_ids are some other set of numbers — could start anywhere.
2. The expected payload shape for a movement command. `cmd_id + pan_byte +
   tilt_byte`? `cmd_id + accessory_id_uint32 + position_struct`? Without a
   real capture, the search space is wide.
3. Whether there are auth/permission fields beyond the 122-byte header
   that gate command execution. The empty 0x18 universal ACK is consistent
   with either "we acknowledge but don't process unrecognized" or "we
   acknowledge but you lack permission to send commands." Indistinguishable
   from outside.

The practical next step is reading those values out of the iOS Blink app
binary — Option 3 from the closing recap. `WalnutPlayer` is the framework
inside the iOS app that handles IMMIS stream decoding (per
`refs/blink-immis-proxy/README.md`). A class-dump or Hopper/Ghidra
analysis should surface the cmd_id constants without needing to run a live
MITM. That's the next session's work.

The Android Frida MITM path (Option 2) stays in the toolkit. If the iOS
binary analysis hits a wall — for example, if the cmd_ids are in obfuscated
or jitted code — the MITM in `refs/blink-immis-proxy/` becomes the
fallback. Either path yields the same ground truth: a real pan/tilt command
captured off the wire.

## What Future Readers Need

CLAUDE.md is the canonical record of the protocol surface (`# Known
Message Types`, the 122-byte auth header layout, the live-derived
ACCESSORY_MESSAGE wire format with full byte tables for pan and tilt
encoding). `docs/findings.md` is the session-by-session running log with
raw payloads, diff tables, and the verb-discriminator diagnostic that kept
Phase 1 honest.

JSONL logs are gitignored (they contain account IDs, IP addresses, and
serials) but live locally for verification:

```
logs/rosie_probe-get-20260519-171113.jsonl   (39 GET probes)
logs/rosie_probe-post-20260519-171729.jsonl  (39 POST probes)
logs/immis_observe-1234567-20260519-*.jsonl  (5 successful observe sessions)
logs/immis_send-1234567-20260519-*.jsonl     (6 send-experiment sessions)
```

The two payloads worth remembering by heart:

```
0x15 ACCESSORY_MESSAGE seq=4 len=4    06ae77f1        (per-rosie identity, stable)
0x15 ACCESSORY_MESSAGE seq=2 len=7    XX HH HH HH PP TT 00    (position snapshot)
                                                       ^^ pan, ^^ tilt
```

At home position, that's `XX HHHHHH 5a b4 00`. At full-left only,
`XX HHHHHH ae b4 00`. At full-up only, `XX HHHHHH 5a f1 00`. At full-right,
`XX HHHHHH 06 b4 00`. At full-down, `XX HHHHHH 5a 77 00`.

See `CHANGES.md` Phase 2 for the chronological diff summary.
