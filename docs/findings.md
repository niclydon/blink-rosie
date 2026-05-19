# Findings — Blink Rosie Pan/Tilt Reverse Engineering

Running log of what we discover, what we ruled out, and what we still need to test.
Newest at the top. Cite source files / packet captures where applicable.

---

## 2026-05-19 — Project bootstrap

- Scaffolded blink-rosie project on Furnace.
- CLAUDE.md captures full prior-art summary, IMMIS packet format, and phased plan.
- blink-mcp confirmed available on the network for authenticated REST access.
- Reference repos cloned into `refs/` (not vendored — see `.gitignore`).

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
