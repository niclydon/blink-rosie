# Findings — Blink Rosie Pan/Tilt Reverse Engineering

Running log of what we discover, what we ruled out, and what we still need to test.
Newest at the top. Cite source files / packet captures where applicable.

---

## 2026-05-19 — Project bootstrap

- Scaffolded blink-rosie project on Furnace.
- CLAUDE.md captures full prior-art summary, IMMIS packet format, and phased plan.
- blink-mcp confirmed available on the network for authenticated REST access.
- Reference repos cloned into `refs/` (not vendored — see `.gitignore`).
- **Status:** ready to start Phase 1 (REST endpoint discovery).

---

## Open questions

- What HTTP status does Blink return for non-existent vs unauthorized rosie endpoints? (Probe-and-diff in Phase 1.)
- Are there any rosie-specific fields under `/owls/{owlId}/config` or `/cameras/{camId}/config`?
- Does the `rosie_lv_session` event vary based on which UI buttons were used during the session?
- Does ACCESSORY_MESSAGE (0x15) require a session-establishment handshake before pan/tilt payloads will be accepted?

## Ruled out

(nothing yet)
