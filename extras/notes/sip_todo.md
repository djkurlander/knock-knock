# SIP experiment & TODO backlog

Parking lot for SIP / B2BUA experiment ideas and deferred work, so they aren't lost.
Promote an item to its own `sip-<topic>.md` note (or implement it) when picked up;
strike it through / remove when done.

---

## Deferred: in-dialog responsiveness probe (mid-call re-INVITE / session refresh)

**Status:** Deferred 2026-06-20 (design agreed; not needed yet)

**Goal.** Distinguish a *sophisticated long-hold monetizer* (a real UA that handles the
dialog and could survive an enforcing route) from a *crude fire-and-forget dialer* (only
holds on permissive routes). Concretely: mid-call, poke the bot with an in-dialog request
and see whether it answers.

**Why two channels exist for "committed to the hold."** To keep a call alive against a
real carrier, a bot must cope with two *independent* teardown mechanisms:
1. **RTP-inactivity teardown** (unsignaled, unilateral) → defended by **keepalive RTP**:
   the bot proactively sends the occasional packet. Observable passively (stray RTP) or by
   enforcing an inactivity timeout and watching who defends.
2. **Session timers** (RFC 4028, negotiated) → defended by **responding to / originating
   a session refresh** (re-INVITE / UPDATE). A bot can offload *originating* the refresh to
   the far side, but on an enforcing route it must at least **respond** to the PBX's refresh
   or the call is torn down.

**Why deferred.** The keepalive-RTP channel (#1) already yields the "committed long-term"
signal we mainly care about — an occasional RTP packet shows commitment. The re-INVITE probe
(#2) is a *different channel* (signaling vs media) and confirms the bot is a real
dialog-handling UA, but for the "is it committed" question it's largely **duplicative**.
Revisit when we specifically want to separate "defends via media keepalive" from "handles
in-dialog signaling," or to grade UA sophistication / FAS-resistance.

**Preferred design (agreed): drive it from Asterisk, relay it in the B2BUA.**
Not a hand-rolled B2BUA-originated re-INVITE (too much transaction state / retransmit / CSeq
FSM in our Python). Instead:
- **Asterisk owns the state machine.** Enable native `res_pjsip` session timers on the
  honeypot endpoint (`timers`, `timers_sess_expires`, `timers_min_se`, Asterisk as
  refresher). Asterisk drives periodic re-INVITE/UPDATE with correct timing, retransmits
  (Timer A/B), CSeq, dialog state — battle-tested, and **more realistic / least
  fingerprintable** than a synthetic one-shot (no randomization hacks needed).
- **B2BUA does a thin relay.** Forward the in-dialog re-INVITE/UPDATE from the Asterisk leg
  to the bot, relay the bot's response back to Asterisk, relay Asterisk's ACK to the bot —
  reusing the existing per-leg dialog mapping. No timers/retries in the B2BUA. Hooks:
  `_handle_pbx_request` (Asterisk→bot direction) and `forward_in_dialog` (bot→Asterisk).
- **Observable signal:** the bot's response to the refresh — `200` (real UA, handles the
  dialog → sophisticated) / `4xx` e.g. `481` (real stack, discarded dialog state) / no
  answer (fire-and-forget). Trace it for the `b2bua_trace.py` classifier.

**Coupling caveat (ship together).** Asterisk session timers + the B2BUA relay are a
package: enable Asterisk timers *without* the relay and Asterisk's unanswered refresh tears
down the very holds we want to watch. (Confirm session timers are currently OFF on the
endpoint — they should be, since holds reach the 1200s cap fine today.)

**Architecture note.** The B2BUA is two independent back-to-back dialogs (`bot↔B2BUA`,
`B2BUA↔Asterisk`); a re-INVITE on one leg never confuses the other as long as we don't
cross-relay incorrectly. Asterisk can't reach the bot directly, so the B2BUA is
unavoidably in the path — the design just keeps its role to mechanical relay.

---

## Other deferred items (this session)

- **INVITE retransmission (B2BUA→Asterisk, Timer A/B).** Makes a dropped INVITE on the
  remote-Asterisk UDP leg recoverable instead of a lost call. Deferred after the 06-20
  burst — revisit if the intake-rate overload recurs. (Reap + per-IP cap shipped as the
  mitigation; see `sip_daily_observations.md` 2026-06-20.)
- **Per-IP INVITE *rate* limit.** The current `PBX_MAX_BRIDGES_PER_IP` is a *concurrency*
  cap (resource bound), not a rate limit — it doesn't fully bound the INVITE *arrival rate*
  that drove the no-response drops. A token-bucket per IP would. Deferred ("fix if it
  becomes a problem").
- **`b2bua_trace.py`: third `sent` state `stray`.** `sent=engaged` uses a 400-byte
  threshold, so bots that sent 1–399 B of RTP (a few stray/keepalive packets) read as
  `silent`. A `silent`/`stray`/`engaged` split would directly answer "which bots sent *any*
  RTP" (17 such bridges currently hidden, incl. the FR pump + embassy). Reconcile with the
  `media-sent` column (which uses `>0`).
- **Capture session-timer headers per INVITE** (`Supported`, `Session-Expires`, `Min-SE`,
  `refresher`). Read-only; not stored today. Tells us whether the holders even negotiate
  session timers and who they expect to refresh (i.e. whether their silence is correct UA
  behavior or a tell). Prerequisite for "grade UA sophistication" above.
- **Trace blind spot:** an in-dialog re-INVITE *from the attacker* is answered but not
  traced (`sip_b2bua.py:903`). 1-line `trace()` to remove the blind spot.
- **Media-inactivity "challenge mode."** Enforce an RTP-inactivity teardown (drop a held
  call after N s of no inbound RTP) to test which bots defend with keepalive RTP vs just
  redial — the media-channel counterpart to the re-INVITE probe.
- **Analyzer/skill stage lists:** add the new `pbx_no_response` and `rejected` (per_ip_cap)
  stages to `b2bua_trace.py` / the `sip-daily-review` skill stage docs.
