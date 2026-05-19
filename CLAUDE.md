# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Blink Rosie Pan/Tilt Reverse Engineering Project

## Objective

Programmatically control the Blink "Rosie" pan/tilt accessory mount attached to a Blink Mini (Gen 1) camera. Nobody in the community has achieved this yet. The pan/tilt commands are believed to be sent in-band through Blink's proprietary IMMIS streaming protocol, not through REST API calls. Our approach is to exhaust API-level discovery first, then move to protocol-level interception if needed.

## Background and Prior Art

### What is Rosie?

The Blink Pan-Tilt Mount (internal codename "rosie") is a motorized base that attaches to the Blink Mini Gen 1 camera. It provides 350 degrees horizontal rotation and 125 degrees vertical tilt, controlled exclusively through the Blink Home Monitor app during live view sessions. There is no official API, no Alexa voice control for movement, and no documented way to control it programmatically.

### What the Community Has Figured Out So Far

The Rosie accessory is visible in the Blink REST API via the homescreen endpoint. It shows up as an accessory with type `rosie` in the response:

```
GET /api/v3/accounts/{AccountID}/homescreen
```

Response excerpt:
```json
{
  "accessories": {
    "rosie": [
      {
        "id": 1881,
        "serial": "G7...GH",
        "type": "rosie",
        "connected": true,
        "calibrated": true,
        "target": "owl",
        "target_id": 377378,
        "created_at": "2023-06-20T04:38:48+00:00",
        "revision": "01"
      }
    ]
  }
}
```

Key fields: `id` is the rosie accessory ID. `target` is `owl` (the Blink Mini camera type). `target_id` is the camera ID. `connected` and `calibrated` report device status.

A researcher captured all HTTP traffic during live view with pan/tilt actions and found **no separate REST API calls** for movement commands. The only REST call mentioning rosie was a telemetry event:

```
POST /api/v1/accounts/{AccountID}/events/app
```

```json
{
  "events": [
    {
      "timestamp": "2023-06-23T21:14:05+0000",
      "event": "rosie_lv_session",
      "data": [
        { "name": "target_id", "value": "377590" },
        { "name": "status", "value": "online" },
        { "name": "360_button", "value": "false" },
        { "name": "d_pad_controls", "value": "true" },
        { "name": "set_home_button", "value": "false" },
        { "name": "target", "value": "owl" },
        { "name": "go_home_button", "value": "false" }
      ]
    }
  ]
}
```

This is telemetry (reporting which UI buttons were used), NOT a control mechanism.

### The IMMIS Protocol

When a live view is started, the Blink API returns a command response with a server URL in the format:

```
immis://{IpAddress}:{Port}/{ConnectionID}__IMDS_{DeviceSerial}?client_id={ClientID}
```

IMMIS is a Blink-proprietary protocol that wraps MPEG-TS video data in custom packets over TLS. The community has reverse-engineered the protocol framing:

#### IMMIS Packet Format

Every IMMIS packet has a **9-byte header**:

| Offset | Size | Field | Endian |
|--------|------|-------|--------|
| 0 | 1 byte | Message Type | -- |
| 1 | 4 bytes | Sequence Number | Big-endian |
| 5 | 4 bytes | Payload Length | Big-endian |

Followed by `payload_length` bytes of payload data.

#### Known Message Types

| Name | Hex | Direction | Purpose |
|------|-----|-----------|---------|
| VIDEO | 0x00 | server -> client | MPEG-TS video data (payload starts with 0x47 sync byte) |
| KEEPALIVE | 0x0A | client -> server | Keep-alive ping, sent every 10 seconds, no payload |
| LATENCY_STATS | 0x12 | client -> server | 24-byte stats payload, sent every 1 second |
| INLINE_COMMAND | 0x14 | bidirectional | "Device control" - purpose not fully explored |
| **ACCESSORY_MESSAGE** | **0x15** | **bidirectional** | **Pan/tilt commands almost certainly use this type** |
| SESSION_COMMAND | 0x17 | client -> server | Start/Stop audio (command IDs: 3=StartAudio, 4=StopAudio) |
| SESSION_MESSAGE | 0x18 | bidirectional | ACKs, control-plane updates, audio uplink frames |

The `ACCESSORY_MESSAGE (0x15)` type is the primary target. Post-live-view logs from the Blink app contain counters confirming accessory messages are exchanged during pan/tilt sessions:
- `IMMI_DATA_FLAG_ACCESSORY_MSG` (received counter)
- `IMMI_DATA_FLAG_INLINE_LV_CMD` (sent counter)

#### IMMIS Authentication Header (122 bytes)

The TLS connection is authenticated with a fixed-format 122-byte header:

| Offset | Size | Content |
|--------|------|---------|
| 0 | 4 bytes | Magic number: `0x00000028` |
| 4 | 4 bytes | Serial field length: `0x00000010` (16) |
| 8 | 16 bytes | Camera serial string (null-padded) |
| 24 | 4 bytes | Client ID (big-endian uint32, from URL query param) |
| 28 | 1 byte | Static: `0x01` |
| 29 | 1 byte | Static: `0x08` |
| 30 | 4 bytes | Token field length: `0x00000040` (64) |
| 34 | 64 bytes | Auth token (all null bytes in current implementations) |
| 98 | 4 bytes | Connection ID field length: `0x00000010` (16) |
| 102 | 16 bytes | Connection ID string (from URL path, before `__`) |
| 118 | 4 bytes | Trailer: `0x00000001` |

#### Keep-Alive Packet (latency stats, sent every 1 second)

```
0x12 0x00 0x00 0x03 0xe8 0x00 0x00 0x00 0x18  # 9-byte header (type=0x12, seq=1000, len=24)
0x00 0x00 0x00 0x00  # audioAverageLatencyInMS
0x00 0x00 0x00 0x00  # audioMaxLatencyInMS
0x00 0x00            # audioFramesPresented
0x00 0x00            # audioFramesDropped
0x00 0x00 0x00 0x00  # videoAverageLatencyInMS
0x00 0x00 0x00 0x00  # videoMaxLatencyInMS
0x00 0x00            # videoFramesPresented
0x00 0x00            # videoFramesDropped
```

#### Keep-Alive Ping (sent every 10 seconds)

```
0x0A {4-byte sequence BE} 0x00 0x00 0x00 0x00  # type=0x0A, no payload
```

### Known REST API Endpoints for Accessories

From the codebase analysis, these accessor endpoints exist:

```
POST /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{cameraId}/accessories/{accessoryType}/{accessoryId}/delete/
POST /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{cameraId}/accessories/{accessoryType}/{accessoryId}/lights/{lightControl}
```

The `lights/{lightControl}` endpoint is for Storm (floodlight) accessories. **Nobody has systematically tested what other endpoints exist under the `/accessories/rosie/{rosieId}/` path.**

### Known Blink API Base URLs and Patterns

- Auth: `https://api.oauth.blink.com/oauth/token`
- API base: `https://rest-{region}.immedia-semi.com` (e.g., `rest-u011.immedia-semi.com`)
- Homescreen: `GET /api/v3/accounts/{accountId}/homescreen`
- Liveview (owl/mini): `POST /api/v2/accounts/{accountId}/networks/{networkId}/owls/{owlId}/liveview`
- Liveview (camera): `POST /api/v5/accounts/{accountId}/networks/{networkId}/cameras/{cameraId}/liveview`
- Command status: `GET /network/{networkId}/command/{commandId}`
- Command done: `POST /network/{networkId}/command/{commandId}/done`

Liveview request body: `{"intent": "liveview"}`

### Existing Integrations and Their Rosie Support

- **blinkpy** (Python): No rosie/pan-tilt support. Has working IMMIS livestream proxy.
- **Home Assistant Blink integration**: No pan/tilt. Uses blinkpy under the hood.
- **Hubitat BlinkAPI.groovy driver**: Explicitly states "Rosie devices have no control."
- **homebridge-blink-for-home** (archived April 2025): No rosie support. Had partial IMMIS decode.
- **homebridge-blink-cameras-new-api** (sealad886, active April 2026): Has working IMMIS proxy with full message type enum. Logs ACCESSORY_MESSAGE payloads but discards them. Two-way audio still in progress.
- **blink-liveview-middleware** (Go): Has TODO for "PTZ commands". No rosie support.

## Reference Repositories

Clone these into a `refs/` directory for local reference:

```bash
mkdir -p refs
git clone --depth 1 https://github.com/sealad886/homebridge-blink-cameras-new-api.git refs/homebridge-blink-new
git clone --depth 1 https://github.com/colinbendell/homebridge-blink-for-home.git refs/homebridge-blink-original
git clone --depth 1 https://github.com/MattTW/BlinkMonitorProtocol.git refs/blink-protocol-docs
git clone --depth 1 https://github.com/fronzbot/blinkpy.git refs/blinkpy
git clone --depth 1 https://github.com/jakecrowley/blink-immis-proxy.git refs/blink-immis-proxy
git clone --depth 1 https://github.com/amattu2/blink-liveview-middleware.git refs/blink-liveview-middleware
```

### Key Files to Study

| File | What It Contains |
|------|-----------------|
| `refs/homebridge-blink-new/src/blink-api/immis-proxy.ts` | **Most complete IMMIS implementation.** Full message type enum, auth header construction, packet parsing, session command sending, audio uplink scaffolding. Lines 60-75 define all message types. Lines 467-518 build the 122-byte auth header. Lines 520-571 parse incoming packets by type. Lines 652-672 show how to construct and send arbitrary commands. |
| `refs/blinkpy/blinkpy/livestream.py` | Clean Python IMMIS implementation. Auth header construction (lines 39-100), packet receive loop with message type dispatch (lines 178-248), keep-alive/latency-stats sending (lines 251-302). |
| `refs/blink-liveview-middleware/common/tcp.go` | Go implementation. Auth frame construction in `util.go` `GetTCPAuthFrames()`. Has explicit `TODO: Support command I/O (e.g. PTZ commands)` at line 42. |
| `refs/blink-liveview-middleware/common/api.go` | Blink REST API patterns: login, homescreen, liveview, command polling. |
| `refs/blink-immis-proxy/proxy.py` | **Complete MITM setup** using mitmproxy + socat for intercepting IMMIS traffic. |
| `refs/blink-immis-proxy/inject-tls-verify-hook.py` | **Frida script** to bypass TLS cert pinning in Blink's `libwalnut.so` native library (hooks `mbedtls_x509_crt_verify_with_profile`). |
| `refs/homebridge-blink-original/src/blink-api.js` | Documents accessory REST API endpoints (lines 67-68). |

## Environment

- This project runs on Furnace (AMD Strix Halo, primary compute node)
- blink-mcp is already running and connected, providing authenticated access to the Blink API
- Python 3, Node.js, and Go are available
- The owner has Blink Mini cameras with Rosie pan/tilt mounts connected and operational

## Phased Approach

### Phase 1: REST API Discovery (Automated, No Special Hardware)

Before we touch the IMMIS protocol, exhaustively probe the Blink REST API for any undiscovered rosie control endpoints. This is cheap, fast, and requires no special setup.

#### 1.1: Enumerate Rosie Device Info

Pull the homescreen data and extract all rosie accessory details:
- Rosie ID, serial, target camera ID, firmware revision, calibration state
- Full homescreen JSON dump for reference

#### 1.2: Probe Accessory REST Endpoints

We know the pattern `/api/v1/accounts/{acctId}/networks/{netId}/cameras/{camId}/accessories/{type}/{id}/...` exists. Systematically try:

```
# Known endpoint patterns from Storm (floodlight) accessories
GET  /accessories/rosie/{rosieId}
GET  /accessories/rosie/{rosieId}/status
POST /accessories/rosie/{rosieId}/calibrate
POST /accessories/rosie/{rosieId}/command
POST /accessories/rosie/{rosieId}/move
POST /accessories/rosie/{rosieId}/position
POST /accessories/rosie/{rosieId}/ptz
POST /accessories/rosie/{rosieId}/home
POST /accessories/rosie/{rosieId}/default_position
POST /accessories/rosie/{rosieId}/pan
POST /accessories/rosie/{rosieId}/tilt
POST /accessories/rosie/{rosieId}/sweep

# Try with owl (mini) path pattern too
GET  /owls/{owlId}/accessories/rosie/{rosieId}
POST /owls/{owlId}/accessories/rosie/{rosieId}/command
POST /owls/{owlId}/accessories/rosie/{rosieId}/move
```

Try various HTTP methods (GET, POST, PUT, PATCH) and record all responses, including 404s (which confirm the path prefix is valid) vs 403s (which might indicate an endpoint exists but needs different auth) vs other status codes.

Also try POST bodies like:
```json
{"direction": "left", "degrees": 10}
{"pan": 180, "tilt": 90}
{"command": "move", "pan": 180, "tilt": 90}
{"command": "home"}
{"command": "sweep"}
```

#### 1.3: Capture the rosie_lv_session Event

Start a liveview session via the API and capture the full `rosie_lv_session` telemetry event to see if there are any additional fields or patterns we can learn from.

#### 1.4: Check Firmware/Config Endpoints

```
GET /api/v1/accounts/{acctId}/networks/{netId}/cameras/{camId}/config
GET /api/v1/accounts/{acctId}/networks/{netId}/owls/{owlId}/config
```

Look for any rosie-specific configuration, firmware update URLs, or feature flags that might hint at control mechanisms.

### Phase 2: IMMIS Protocol Exploration (Automated, No Special Hardware)

If Phase 1 comes up empty, we move to the IMMIS protocol. We can do significant work here without MITM hardware by building our own IMMIS client.

#### 2.1: Build an IMMIS Client

Using the reference implementations (blinkpy's `livestream.py` is cleanest), build a Python client that:
1. Authenticates with the Blink API
2. Starts a liveview session
3. Connects to the IMMIS server via TLS
4. Sends the 122-byte auth header
5. Receives and categorizes all incoming packets by message type
6. Logs full hex dumps of any INLINE_COMMAND (0x14) and ACCESSORY_MESSAGE (0x15) packets
7. Maintains the connection with keep-alive and latency stats

#### 2.2: Observe Baseline Traffic

Connect to a camera with a Rosie attached and log all non-video message types during an idle live view (no movement). This establishes what "normal" looks like.

#### 2.3: Try Sending ACCESSORY_MESSAGE Packets

Using the `sendSessionCommand` pattern from sealad886's code as a template, try sending ACCESSORY_MESSAGE (0x15) packets with various payloads:

```python
# Hypothesis: simple direction + magnitude format
# Try single-byte direction commands
for cmd_byte in range(256):
    send_accessory_message(bytes([cmd_byte]))

# Try 2-byte direction + speed/distance
for direction in [0x01, 0x02, 0x03, 0x04]:  # left/right/up/down
    for amount in [1, 5, 10, 45, 90]:
        send_accessory_message(bytes([direction]) + amount.to_bytes(2, 'big'))
```

Watch the camera physically for any movement after each send. Even if we guess wrong on the format, any movement at all confirms the mechanism.

#### 2.4: Try Sending INLINE_COMMAND Packets

Same approach with INLINE_COMMAND (0x14). The original researcher noted `IMMI_DATA_FLAG_INLINE_LV_CMD` in the sent counters, so this type may also carry movement commands.

### Phase 3: Traffic Interception (Requires Additional Setup)

If Phases 1-2 don't produce results, we need to see what the actual Blink app sends.

#### 3.1: Android MITM with Frida

The `blink-immis-proxy` repo provides a complete setup:
1. Rooted Android device (or Bliss OS in QEMU/KVM)
2. Frida server running on the device
3. `inject-tls-verify-hook.py` to bypass libwalnut TLS cert pinning
4. `proxy.py` (mitmproxy addon) to redirect IMMIS URLs through local socat relay
5. Wireshark on loopback to capture decrypted traffic

From there: issue pan/tilt commands in the Blink app and capture the raw IMMIS packets. Diff idle-session captures vs movement-session captures to isolate the 0x14/0x15 payloads.

#### 3.2: iOS App Binary Analysis

Someone previously found "WalnutPlayer" in the Blink iOS app binary, which handles IMMIS stream decoding. A class-dump or Hopper/Ghidra analysis of the WalnutPlayer framework could reveal the serialization format for accessory commands without needing to run a MITM.

## Project Structure

```
blink-rosie/
  CLAUDE.md           # This file (project instructions)
  refs/               # Cloned reference repos (git clone commands above)
  src/
    api_client.py     # Blink REST API client (auth, homescreen, liveview)
    immis_client.py   # IMMIS protocol client (connect, auth, send/receive)
    rosie_probe.py    # Phase 1: REST endpoint discovery
    rosie_immis.py    # Phase 2: IMMIS protocol exploration
  logs/               # Captured API responses and packet dumps
  docs/
    findings.md       # Running log of what we discover
```

## Authentication Notes

The Blink API uses OAuth 2.0 with 2FA. The blink-mcp server already handles authentication. For standalone scripts, use blinkpy's auth flow or extract credentials from the existing blink-mcp session.

Required headers for REST API calls:
```
Authorization: Bearer {access_token}
Content-Type: application/json; charset=UTF-8
locale: en_US
```

The User-Agent should mimic the Blink app to avoid detection by Lab126 (Amazon's hardware division that develops Blink).

## Success Criteria

1. **Minimum**: Identify the exact mechanism (REST endpoint or IMMIS message type/format) used for pan/tilt control
2. **Target**: Send programmatic pan/tilt commands from a script (any direction, any amount)
3. **Stretch**: Build a reusable Python library/CLI tool for rosie control with commands like `move_left(degrees)`, `move_right(degrees)`, `tilt_up(degrees)`, `tilt_down(degrees)`, `go_home()`, `sweep_360()`

## Key Constraints

- Do NOT drain the camera battery or hammer the API with excessive requests. Use reasonable rate limiting.
- The Blink API is known to rate-limit and occasionally ban clients. Use appropriate User-Agent strings and back off on 429 responses.
- IMMIS connections use `rejectUnauthorized: false` / `verify_mode = ssl.CERT_NONE` because Blink uses non-standard TLS certificates.
- The Rosie is Mini Gen 1 only (not compatible with Mini 2).
