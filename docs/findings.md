# Findings — Blink Rosie Pan/Tilt Reverse Engineering

Running log of what we discover, what we ruled out, and what we still need to test.
Newest at the top. Cite source files / packet captures where applicable.

---

## 2026-05-19 — Project bootstrap

- Scaffolded blink-rosie project on Furnace.
- CLAUDE.md captures full prior-art summary, IMMIS packet format, and phased plan.
- blink-mcp confirmed available on the network for authenticated REST access.
- Reference repos cloned into `refs/` (not vendored — see `.gitignore`).

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
