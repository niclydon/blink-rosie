# Findings — Blink Rosie Pan/Tilt Reverse Engineering

Running log of what we discover, what we ruled out, and what we still need to test.
Newest at the top. Cite source files / packet captures where applicable.

---

## 2026-05-19 — Project bootstrap

- Scaffolded blink-rosie project on Furnace.
- CLAUDE.md captures full prior-art summary, IMMIS packet format, and phased plan.
- blink-mcp confirmed available on the network for authenticated REST access.
- Reference repos cloned into `refs/` (not vendored — see `.gitignore`).

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
